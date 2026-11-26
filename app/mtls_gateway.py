"""Paari mTLS ingress enforcement and Agent Card certificate registry.

TLS is terminated at a trusted ingress proxy. The proxy MUST overwrite the
X-Paari-Mtls-* headers and the application MUST be network-restricted so only
that proxy can reach it. This module independently binds the verified client
certificate fingerprint to an active Agent Card and active parent authority.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import crypto_utils, models, security as platform_security
from app.mtls_binding import (build_agent_card_binding_payload,
                              certificate_validity_utc as _utc_validity)
from app.audit import record_audit
from app.database import SessionLocal, get_db

router = APIRouter(prefix="/control/v1", tags=["zero-trust-agent-ingress"])
logger = logging.getLogger("paari.gateway")
PAYMENT_INGRESS_PATHS = {"/v1/payments/intent", "/payments/intent"}


def mtls_is_required() -> bool:
    env = os.environ.get("PAARI_ENV", "sandbox").strip().lower()
    return (os.environ.get("PAARI_REQUIRE_MTLS_INGRESS") == "1"
            or os.environ.get("PAARI_LIVE") == "1" or env in {"prod", "prod-live"})


def _proxy_network_is_narrow(network: ipaddress._BaseNetwork) -> bool:
    # Do not accept universal or broad private-network trust entries. The local
    # Compose profile uses one fixed /32 gateway address; production should use
    # explicit proxy addresses or a tightly controlled subnet.
    minimum_prefix = 24 if network.version == 4 else 64
    return network.prefixlen >= minimum_prefix


def _trusted_proxy_networks():
    raw = os.environ.get("PAARI_MTLS_TRUSTED_PROXY_CIDRS", "")
    networks = []
    try:
        for item in raw.split(","):
            item = item.strip()
            if item:
                network = ipaddress.ip_network(item, strict=False)
                if not _proxy_network_is_narrow(network):
                    return []
                networks.append(network)
    except ValueError:
        # Invalid proxy configuration must fail closed, never turn a request
        # into a 500 or accidentally trust a partially parsed allowlist.
        return []
    return networks


def trusted_proxy_cidrs_valid() -> bool:
    raw = os.environ.get("PAARI_MTLS_TRUSTED_PROXY_CIDRS", "").strip()
    if not raw:
        return False
    try:
        parsed = [ipaddress.ip_network(item.strip(), strict=False)
                  for item in raw.split(",") if item.strip()]
        return bool(parsed) and all(_proxy_network_is_narrow(item) for item in parsed)
    except ValueError:
        return False


def mtls_ca_certificate_valid() -> bool:
    ca_path = os.environ.get("PAARI_MTLS_CA_CERT", "").strip()
    if not ca_path or not Path(ca_path).is_file():
        return False
    try:
        ca = x509.load_pem_x509_certificate(Path(ca_path).read_bytes())
        constraints = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = ca.extensions.get_extension_for_class(x509.KeyUsage).value
        not_before, not_after = _utc_validity(ca)
        now = datetime.now(timezone.utc)
        if not constraints.ca or constraints.path_length not in (None, 0):
            return False
        if not usage.key_cert_sign or ca.subject != ca.issuer or not not_before <= now < not_after:
            return False
        _verify_signed_by(ca, ca)
        return True
    except Exception:
        return False


def _proxy_is_trusted(client_host: str | None) -> bool:
    if not client_host:
        return False
    try:
        ip = ipaddress.ip_address(client_host)
    except ValueError:
        return False
    return any(ip in network for network in _trusted_proxy_networks())


def _normalize_fingerprint(value: str | None) -> str:
    raw = (value or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", raw):
        return raw
    if re.fullmatch(r"(?:[0-9a-f]{2}:){31}[0-9a-f]{2}", raw):
        return raw.replace(":", "")
    return ""


def _append_gateway_audit(*, reason_code: str, fingerprint: str, path: str,
                          method: str, agent_id: str | None = None,
                          org_id: str = "gateway") -> None:
    """Record blocked ingress separately from payment-intent history."""
    db = SessionLocal()
    try:
        record_audit(
            db,
            transaction_id=f"gateway-{uuid.uuid4().hex}",
            agent_id=agent_id or "unregistered",
            parent_id=None,
            kind="gateway_ingress_denied",
            org_id=org_id,
            detail={
                "reason_code": reason_code,
                "certificate_fingerprint_sha256": fingerprint or None,
                "path": path,
                "method": method,
                "payment_intent_created": False,
                "authorization_issued": False,
            },
        )
        db.commit()
    except Exception:
        db.rollback()
        # Deny remains fail-closed even if the audit store is unavailable, but
        # never silently conceal loss of the security event.
        logger.exception("Failed to persist blocked mTLS ingress audit event reason=%s path=%s", reason_code, path)
    finally:
        db.close()


def _agent_card_key_fingerprint(agent: models.Agent, *, old: bool = False) -> str:
    public_pem = agent.old_public_key_pem if old else agent.public_key_pem
    algorithm_name = (agent.old_public_key_algorithm if old else agent.public_key_algorithm) or "ed25519"
    if not public_pem:
        return ""
    algorithm = crypto_utils.Algorithm(algorithm_name)
    return crypto_utils.public_key_fingerprint(public_pem, algorithm)


def resolve_certificate_binding(fingerprint: str, db: Session) -> tuple[bool, str, str | None, str]:
    """Resolve the certificate -> Agent Card -> parent binding on every protected request."""
    row = db.query(models.AgentClientCertificate).filter_by(fingerprint_sha256=fingerprint).first()
    if row is None:
        return False, "AGENT_CERTIFICATE_UNKNOWN", None, "gateway"
    if row.status != "ACTIVE" or row.revoked_at is not None:
        return False, "AGENT_CERTIFICATE_REVOKED", row.agent_id, row.org_id
    now = datetime.now(timezone.utc)
    if row.not_before > now or row.not_after <= now:
        return False, "AGENT_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID", row.agent_id, row.org_id
    agent = db.query(models.Agent).filter_by(agent_id=row.agent_id, org_id=row.org_id).first()
    if agent is None:
        return False, "AGENT_NOT_REGISTERED", row.agent_id, row.org_id
    if row.subject_cn != agent.agent_id:
        return False, "AGENT_CERTIFICATE_CARD_SUBJECT_MISMATCH", row.agent_id, row.org_id
    if agent.status != models.AgentStatus.ACTIVE:
        return False, "AGENT_NOT_ACTIVE", row.agent_id, row.org_id
    if agent.valid_until is not None and agent.valid_until <= now:
        return False, "AGENT_REGISTRATION_EXPIRED", row.agent_id, row.org_id

    # The certificate is pinned to the precise Agent Card signing-key version
    # that proved possession at registration. Rotation invalidates the transport
    # binding immediately, except while the recorded old-key grace period is live.
    if not row.agent_card_key_fingerprint:
        return False, "AGENT_CARD_KEY_BINDING_MISSING_REENROLL_REQUIRED", row.agent_id, row.org_id
    try:
        current_key_fp = _agent_card_key_fingerprint(agent)
        if current_key_fp != row.agent_card_key_fingerprint:
            old_key_fp = _agent_card_key_fingerprint(agent, old=True)
            grace_open = agent.key_sunset_at is not None and agent.key_sunset_at > now
            if not (grace_open and old_key_fp == row.agent_card_key_fingerprint):
                return False, "AGENT_CARD_KEY_ROTATED_CERT_REBIND_REQUIRED", row.agent_id, row.org_id
    except Exception:
        return False, "AGENT_CARD_KEY_BINDING_INVALID", row.agent_id, row.org_id

    parent = db.query(models.ParentAuthority).filter_by(id=agent.parent_pk, org_id=row.org_id).first()
    if parent is None or parent.status != models.ParentStatus.ACTIVE:
        return False, "PARENT_AUTHORITY_INACTIVE", row.agent_id, row.org_id
    return True, "MTLS_AGENT_CARD_BOUND", row.agent_id, row.org_id


class GatewayMTLSMiddleware:
    """Enforce proxy-verified mTLS on payment-intent ingress when configured."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not mtls_is_required():
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        method = scope.get("method", "GET").upper()
        if path not in PAYMENT_INGRESS_PATHS or method != "POST":
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
        client_host = (scope.get("client") or (None, None))[0]
        # Nginx's built-in $ssl_client_fingerprint is SHA-1 on common builds.
        # Forward the escaped PEM and calculate SHA-256 here so the value always
        # matches the certificate registry's SHA-256 fingerprint contract.
        fingerprint = ""
        cert_header = headers.get("x-paari-mtls-certificate", "")
        if cert_header:
            try:
                proxy_cert = x509.load_pem_x509_certificate(unquote(cert_header).encode("utf-8"))
                fingerprint = proxy_cert.fingerprint(hashes.SHA256()).hex()
            except Exception:
                fingerprint = ""
        else:
            # SHA-256 fingerprint header is retained for trusted non-Nginx
            # ingress adapters. The adapter must explicitly document this contract.
            fingerprint = _normalize_fingerprint(headers.get("x-paari-mtls-fingerprint"))
        verified = headers.get("x-paari-mtls-verify", "").upper() == "SUCCESS"
        reason = None
        agent_id = None
        org_id = "gateway"

        if not _proxy_is_trusted(client_host):
            reason = "MTLS_UNTRUSTED_PROXY"
        elif not verified or len(fingerprint) != 64:
            reason = "MTLS_CLIENT_CERTIFICATE_INVALID"
        else:
            db = SessionLocal()
            try:
                allowed, reason, agent_id, org_id = resolve_certificate_binding(fingerprint, db)
            finally:
                db.close()
            if allowed:
                await self.app(scope, receive, send)
                return

        _append_gateway_audit(reason_code=reason or "MTLS_CLIENT_CERTIFICATE_INVALID",
                              fingerprint=fingerprint, path=path, method=method,
                              agent_id=agent_id, org_id=org_id)
        body = json.dumps({"detail": "Agent ingress authentication failed",
                           "reason_code": "AGENT_INGRESS_REJECTED",
                           "payment_intent_created": False}).encode("utf-8")
        await send({"type": "http.response.start", "status": 403,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode("ascii")),
                                (b"cache-control", b"no-store")]})
        await send({"type": "http.response.body", "body": body})


class CertificateRegistration(BaseModel):
    certificate_pem: str = Field(min_length=100, max_length=20000)
    agent_card_signature_b64: str = Field(min_length=40, max_length=20000)


class CertificateRevocation(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


def _load_certificate(certificate_pem: str) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
    except Exception as exc:
        raise HTTPException(422, "Client certificate PEM is invalid") from exc


def _utc_validity(cert: x509.Certificate) -> tuple[datetime, datetime]:
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    return not_before, not_after


def _verify_signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    digest = cert.signature_hash_algorithm
    if digest is not None and digest.name.lower() in {"md5", "sha1"}:
        raise ValueError("MD5/SHA-1 certificate signatures are not accepted")
    key = issuer.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        parameters = getattr(cert, "signature_algorithm_parameters", None) or padding.PKCS1v15()
        key.verify(cert.signature, cert.tbs_certificate_bytes, parameters, cert.signature_hash_algorithm)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        parameters = getattr(cert, "signature_algorithm_parameters", None) or ec.ECDSA(cert.signature_hash_algorithm)
        key.verify(cert.signature, cert.tbs_certificate_bytes, parameters)
    elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key.verify(cert.signature, cert.tbs_certificate_bytes)
    else:
        raise ValueError("unsupported certificate issuer public-key type")


def _verify_issued_by_configured_ca(cert: x509.Certificate) -> x509.Certificate:
    ca_path = os.environ.get("PAARI_MTLS_CA_CERT", "").strip()
    if not ca_path or not Path(ca_path).is_file():
        raise HTTPException(503, "PAARI_MTLS_CA_CERT must point to the configured trusted CA certificate")
    try:
        ca = x509.load_pem_x509_certificate(Path(ca_path).read_bytes())
        now = datetime.now(timezone.utc)
        ca_before, ca_after = _utc_validity(ca)
        constraints = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = ca.extensions.get_extension_for_class(x509.KeyUsage).value
        if not constraints.ca or constraints.path_length not in (None, 0):
            raise ValueError("configured certificate is not an allowed issuing CA")
        if not usage.key_cert_sign:
            raise ValueError("configured CA does not permit certificate signing")
        if ca.subject != ca.issuer or not ca_before <= now < ca_after:
            raise ValueError("configured CA must be currently valid and self-issued")
        _verify_signed_by(ca, ca)
        if cert.issuer != ca.subject:
            raise ValueError("client certificate issuer mismatch")
        _verify_signed_by(cert, ca)
        return ca
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(422, "Client certificate is not validly signed by Paari's configured ingress CA/profile") from exc


def _certificate_identity(cert: x509.Certificate, expected_agent_id: str) -> tuple[str, datetime, datetime]:
    now = datetime.now(timezone.utc)
    not_before, not_after = _utc_validity(cert)
    if not_before > now or not_after <= now:
        raise HTTPException(422, "Client certificate is expired or not yet valid")

    # Exact subject profile: one CN and no additional identity attributes.
    cn_items = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(cert.subject) != 1 or len(cn_items) != 1 or cn_items[0].value != expected_agent_id:
        raise HTTPException(422, "Client certificate subject must contain only the exact Agent Card common name")

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        uri_names = san.get_values_for_type(x509.UniformResourceIdentifier)
        expected_uri = f"urn:paari:agent:{expected_agent_id}"
        # Require exactly one SAN entry; additional DNS/IP/email/URI SANs are rejected.
        if len(san) != 1 or uri_names != [expected_uri]:
            raise ValueError("SAN must contain exactly the expected Agent Card URI")
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if list(eku) != [ExtendedKeyUsageOID.CLIENT_AUTH]:
            raise ValueError("EKU must contain only clientAuth")
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if constraints.ca:
            raise ValueError("client certificate must not be a CA")
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not usage.digital_signature:
            raise ValueError("client certificate must permit digital signatures")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(422, "Client certificate must satisfy the strict Agent Card SAN, clientAuth, BasicConstraints and KeyUsage profile") from exc

    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < 2048:
            raise HTTPException(422, "RSA client certificate keys must be at least 2048 bits")
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.key_size < 256:
            raise HTTPException(422, "EC client certificate keys must be at least 256 bits")
    elif not isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        raise HTTPException(422, "Unsupported client certificate public-key type")

    return cert.fingerprint(hashes.SHA256()).hex(), not_before, not_after


@router.post("/agents/{agent_id}/mtls-certificates", status_code=201)
def register_agent_certificate(
    agent_id: str,
    req: CertificateRegistration,
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    agent = db.query(models.Agent).filter_by(agent_id=agent_id).first()
    if agent is None:
        raise HTTPException(404, "Registered Agent Card not found")
    platform_security.require_admin_org(x_admin_api_key, agent.org_id)
    if agent.status != models.AgentStatus.ACTIVE:
        raise HTTPException(409, "Only an active Agent Card can receive an mTLS certificate binding")
    parent = db.query(models.ParentAuthority).filter_by(id=agent.parent_pk, org_id=agent.org_id).first()
    if parent is None or parent.status != models.ParentStatus.ACTIVE:
        raise HTTPException(409, "An active parent authority is required for mTLS certificate registration")
    cert = _load_certificate(req.certificate_pem)
    _verify_issued_by_configured_ca(cert)
    fingerprint, not_before, not_after = _certificate_identity(cert, agent_id)
    try:
        binding_payload = build_agent_card_binding_payload(
            agent.agent_id, agent.org_id, cert, agent.public_key_pem, agent.public_key_algorithm or "ed25519")
        binding_message = crypto_utils.canonical_json(binding_payload)
        proof_valid = crypto_utils.verify_signature(
            agent.public_key_pem, binding_message, req.agent_card_signature_b64,
            algorithm=crypto_utils.Algorithm(agent.public_key_algorithm or "ed25519"))
    except Exception as exc:
        raise HTTPException(422, "Agent Card signing key could not verify the certificate binding proof") from exc
    if not proof_valid:
        raise HTTPException(403, "Agent Card proof-of-possession is invalid for this certificate and organization")
    agent_card_key_fingerprint = binding_payload["agent_card_key_fingerprint"]
    existing = db.query(models.AgentClientCertificate).filter_by(fingerprint_sha256=fingerprint).first()
    if existing:
        raise HTTPException(409, "Certificate fingerprint is already registered")
    row = models.AgentClientCertificate(
        agent_id=agent.agent_id, org_id=agent.org_id, fingerprint_sha256=fingerprint,
        agent_card_key_fingerprint=agent_card_key_fingerprint,
        subject_cn=agent_id, not_before=not_before, not_after=not_after, status="ACTIVE",
    )
    db.add(row)
    record_audit(db, transaction_id=f"mtls-register-{fingerprint[:24]}",
                 agent_id=agent.agent_id, parent_id=agent.parent.parent_id if agent.parent else None,
                 org_id=agent.org_id, kind="mtls_certificate_registered",
                 detail={"certificate_id": row.certificate_id, "fingerprint_sha256": fingerprint,
                         "subject_cn": agent_id, "not_before": not_before.isoformat(),
                         "not_after": not_after.isoformat(), "agent_card_bound": True,
                         "agent_card_key_fingerprint": agent_card_key_fingerprint,
                         "agent_card_proof_verified": True,
                         "agent_card_proof_sha256": hashlib.sha256(req.agent_card_signature_b64.encode("ascii")).hexdigest()})
    db.commit()
    return {"certificate_id": row.certificate_id, "agent_id": agent_id,
            "fingerprint_sha256": fingerprint, "status": row.status,
            "not_after": not_after.isoformat(), "agent_card_bound": True,
            "agent_card_key_fingerprint": agent_card_key_fingerprint,
            "agent_card_proof_verified": True}


@router.get("/agents/{agent_id}/mtls-certificates")
def list_agent_certificates(
    agent_id: str,
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    agent = db.query(models.Agent).filter_by(agent_id=agent_id).first()
    if agent is None:
        raise HTTPException(404, "Registered Agent Card not found")
    platform_security.require_admin_org(x_admin_api_key, agent.org_id)
    rows = db.query(models.AgentClientCertificate).filter_by(agent_id=agent_id, org_id=agent.org_id).order_by(models.AgentClientCertificate.issued_at.desc()).all()
    return {"items": [{"certificate_id": r.certificate_id, "fingerprint_sha256": r.fingerprint_sha256,
                       "status": r.status, "agent_card_key_fingerprint": r.agent_card_key_fingerprint,
                       "not_before": r.not_before.isoformat(),
                       "not_after": r.not_after.isoformat(), "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
                       "revocation_reason": r.revocation_reason} for r in rows]}


@router.post("/agents/{agent_id}/mtls-certificates/{fingerprint}/revoke")
def revoke_agent_certificate(
    agent_id: str,
    fingerprint: str,
    req: CertificateRevocation,
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    agent = db.query(models.Agent).filter_by(agent_id=agent_id).first()
    if agent is None:
        raise HTTPException(404, "Registered Agent Card not found")
    platform_security.require_admin_org(x_admin_api_key, agent.org_id)
    normalized = _normalize_fingerprint(fingerprint)
    row = db.query(models.AgentClientCertificate).filter_by(
        agent_id=agent_id, org_id=agent.org_id, fingerprint_sha256=normalized).first()
    if row is None:
        raise HTTPException(404, "Certificate binding not found")
    if row.status == "REVOKED":
        return {"agent_id": agent_id, "fingerprint_sha256": normalized, "status": "REVOKED", "idempotent": True}
    row.status = "REVOKED"
    row.revoked_at = datetime.now(timezone.utc)
    row.revocation_reason = req.reason
    record_audit(db, transaction_id=f"mtls-revoke-{normalized[:24]}",
                 agent_id=agent.agent_id, parent_id=agent.parent.parent_id if agent.parent else None,
                 org_id=agent.org_id, kind="mtls_certificate_revoked",
                 detail={"certificate_id": row.certificate_id, "fingerprint_sha256": normalized,
                         "reason_code": "AGENT_CERTIFICATE_REVOKED", "reason": req.reason})
    db.commit()
    return {"agent_id": agent_id, "fingerprint_sha256": normalized, "status": row.status,
            "revoked_at": row.revoked_at.isoformat(), "idempotent": False}
