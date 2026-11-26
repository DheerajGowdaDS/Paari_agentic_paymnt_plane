"""Signed, least-privilege Agent Card export and portability verification.

Portability exports identity metadata and the original parent-signed delegation.
They do NOT transfer tenant grants, user mandates, resource access, credentials,
provider tokens, authorizations, private keys or spending permission to a new tenant.
A receiving control plane must trust the Paari issuer key out of band, validate
both signatures, re-verify status and issue fresh destination-side consent/grants.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from typing import Any, Mapping

from app import crypto_utils, security

PACKAGE_TYPE = "paari.agent-portability-package"
PACKAGE_VERSION = "1.0"


class PortabilityValidationError(ValueError):
    pass


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def delegation_payload_from_record(record: Any, parent_id: str) -> dict[str, Any]:
    """Reconstruct exactly the integer timestamp fields originally signed by the parent."""
    return {
        "delegation_id": record.delegation_id,
        "parent_id": parent_id,
        "agent_public_key_fingerprint": record.agent_public_key_fingerprint,
        "granted_capabilities": list(record.granted_capabilities or []),
        "payment_limit_minor_units": int(record.payment_limit_minor_units),
        "currency": record.currency,
        "issued_at": int(record.issued_at.timestamp()),
        "expires_at": int(record.expires_at.timestamp()),
    }


def build_agent_portability_package(*, agent: Any, parent: Any, delegation_record: Any,
                                    agent_card: dict[str, Any]) -> dict[str, Any]:
    """Create a Paari-signed portability artifact without transferring authority."""
    if not delegation_record.delegation_signature_b64:
        raise PortabilityValidationError(
            "original parent delegation signature is not available; reissue/re-register a signed delegation before export"
        )
    signer = security.signing_backend_status()
    issuer_public_key = security.paari_public_key_pem()
    delegation = delegation_payload_from_record(delegation_record, parent.parent_id)
    if not crypto_utils.verify_signature(parent.public_key_pem, crypto_utils.canonical_json(delegation),
                                         delegation_record.delegation_signature_b64, algorithm=getattr(parent, "public_key_algorithm", "ed25519")):
        raise PortabilityValidationError("stored parent delegation no longer verifies; refusing export")
    fingerprint = crypto_utils.public_key_fingerprint(agent.public_key_pem)
    if not hmac.compare_digest(fingerprint.lower(), delegation["agent_public_key_fingerprint"].lower()):
        raise PortabilityValidationError("stored agent key no longer matches parent delegation; refusing export")

    package_body = {
        "package_type": PACKAGE_TYPE,
        "package_version": PACKAGE_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "issuer": {
            "issuer_id": "paari",
            "key_id": signer["key_id"],
            "algorithm": "Ed25519",
            "public_key_pem": issuer_public_key,
            "public_key_fingerprint": crypto_utils.public_key_fingerprint(issuer_public_key),
        },
        "source_organization": {"org_id": agent.org_id},
        "agent_card": dict(agent_card),
        "parent_identity": {
            "parent_id": parent.parent_id,
            "parent_type": parent.parent_type,
            "status_at_export": parent.status.value if hasattr(parent.status, "value") else str(parent.status),
            "trust_tier_at_export": parent.trust_tier,
            "verified_at": _iso(parent.verified_at),
            "verification_evidence_included": False,
        },
        "parent_public_key_pem": parent.public_key_pem,
        "delegation": {
            "claims": delegation,
            "signature_b64": delegation_record.delegation_signature_b64,
            "signature_algorithm": "Ed25519",
        },
        "agent_key_binding": {
            "public_key_pem": agent.public_key_pem,
            "fingerprint_algorithm": "sha256-pem-bytes",
            "fingerprint": fingerprint,
        },
        "portability_policy": {
            "identity_metadata_portable": True,
            "parent_delegation_artifact_portable": True,
            "authority_transferred": False,
            "destination_reverification_required": True,
            "destination_consent_and_grants_required": True,
            "never_exported": [
                "private_keys", "session_tokens", "credential_jwts", "user_mandates",
                "resource_access_grants", "provider_credentials", "provider_tokens",
                "bounded_authorizations", "tenant_private_data",
            ],
        },
    }
    signature = security.sign_agent_card(package_body)
    return {**package_body, "package_signature_b64": signature}


def validate_agent_portability_package(package: Mapping[str, Any], *,
                                        trusted_issuer_keys: Mapping[str, str]) -> dict[str, Any]:
    """Verify portability signatures against externally trusted Paari issuer key(s).

    Never trust the public key embedded in the package by itself. `trusted_issuer_keys`
    must be populated from a separate trust channel / pinned configuration.
    """
    if not isinstance(package, Mapping) or package.get("package_type") != PACKAGE_TYPE:
        raise PortabilityValidationError("unsupported portability package type")
    if package.get("package_version") != PACKAGE_VERSION:
        raise PortabilityValidationError("unsupported portability package version")
    issuer = package.get("issuer")
    if not isinstance(issuer, Mapping):
        raise PortabilityValidationError("issuer metadata missing")
    key_id = issuer.get("key_id")
    trusted_public_key = trusted_issuer_keys.get(str(key_id)) if key_id else None
    if not trusted_public_key:
        raise PortabilityValidationError("issuer key ID is not in the out-of-band trust store")
    if issuer.get("issuer_id") != "paari" or issuer.get("algorithm") != "Ed25519":
        raise PortabilityValidationError("unexpected issuer or signature algorithm")
    if not hmac.compare_digest(
        crypto_utils.public_key_fingerprint(trusted_public_key).lower(),
        str(issuer.get("public_key_fingerprint", "")).lower(),
    ):
        raise PortabilityValidationError("package issuer fingerprint does not match trust anchor")
    if not hmac.compare_digest(
        crypto_utils.public_key_fingerprint(trusted_public_key).lower(),
        crypto_utils.public_key_fingerprint(str(issuer.get("public_key_pem", ""))).lower(),
    ):
        raise PortabilityValidationError("embedded issuer key does not match trust anchor")

    body = dict(package)
    package_signature = body.pop("package_signature_b64", None)
    if not isinstance(package_signature, str) or not crypto_utils.verify_signature(
        trusted_public_key, crypto_utils.canonical_json(body), package_signature
    ):
        raise PortabilityValidationError("Paari portability package signature verification failed")

    card = package.get("agent_card")
    parent_identity = package.get("parent_identity")
    delegation_node = package.get("delegation")
    binding = package.get("agent_key_binding")
    if not all(isinstance(v, Mapping) for v in (card, parent_identity, delegation_node, binding)):
        raise PortabilityValidationError("portability package is missing required identity/delegation sections")

    # Verify the separately signed Agent Card.
    card_fields = dict(card)
    card_signature = card_fields.pop("card_signature_b64", None)
    card_public_key = card_fields.pop("paari_public_key_pem", None)
    if not card_signature or not isinstance(card_public_key, str):
        raise PortabilityValidationError("signed Agent Card is incomplete")
    if not hmac.compare_digest(crypto_utils.public_key_fingerprint(card_public_key),
                               crypto_utils.public_key_fingerprint(trusted_public_key)):
        raise PortabilityValidationError("Agent Card issuer key differs from trusted Paari issuer key")
    if not crypto_utils.verify_signature(trusted_public_key, crypto_utils.canonical_json(card_fields), card_signature):
        raise PortabilityValidationError("Agent Card signature verification failed")

    claims = delegation_node.get("claims")
    delegation_signature = delegation_node.get("signature_b64")
    parent_key = package.get("parent_public_key_pem")
    if not isinstance(claims, Mapping) or not isinstance(parent_key, str) or not isinstance(delegation_signature, str):
        raise PortabilityValidationError("parent-signed delegation artifact is incomplete")
    if not crypto_utils.verify_signature(parent_key, crypto_utils.canonical_json(dict(claims)), delegation_signature):
        raise PortabilityValidationError("parent delegation signature verification failed")
    public_key = binding.get("public_key_pem")
    expected_fingerprint = crypto_utils.public_key_fingerprint(str(public_key or ""))
    if not hmac.compare_digest(expected_fingerprint.lower(), str(binding.get("fingerprint", "")).lower()):
        raise PortabilityValidationError("agent public-key fingerprint mismatch")
    if not hmac.compare_digest(expected_fingerprint.lower(), str(claims.get("agent_public_key_fingerprint", "")).lower()):
        raise PortabilityValidationError("parent delegation is not bound to exported agent public key")
    if not hmac.compare_digest(
        crypto_utils.public_key_fingerprint(str(card.get("public_key_reference", ""))).lower(),
        expected_fingerprint.lower(),
    ):
        raise PortabilityValidationError("Agent Card public key does not match portable agent key")
    if card.get("parent_id") != parent_identity.get("parent_id") or claims.get("parent_id") != parent_identity.get("parent_id"):
        raise PortabilityValidationError("parent identity mismatch across package sections")
    return {
        "valid": True,
        "package_type": PACKAGE_TYPE,
        "package_version": PACKAGE_VERSION,
        "agent_id": card.get("agent_id"),
        "parent_id": parent_identity.get("parent_id"),
        "agent_status_at_export": card.get("identity_status", card.get("status")),
        "signatures_verified": ["paari_package", "paari_agent_card", "parent_delegation"],
        "authority_transferred": False,
        "destination_reverification_required": True,
    }
