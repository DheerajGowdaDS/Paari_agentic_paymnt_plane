"""Paari signing, credentials, sender-constrained sessions and admin auth."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Header, HTTPException
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from app import crypto_utils
from app.signing_backends import (
    LocalPemSigningBackend, SigningBackendError, encode_ed25519_jwt, load_signing_backend,
)

_KEY_PATH = os.environ.get("PAARI_SIGNING_KEY_PATH", "paari_signing_key.pem")
CREDENTIAL_TTL = timedelta(days=90)
SESSION_TOKEN_TTL = timedelta(minutes=15)
CHALLENGE_NONCE_TTL = timedelta(minutes=2)
BOUNDED_AUTHORIZATION_TTL = timedelta(minutes=2)
MFA_CHALLENGE_TTL = timedelta(minutes=5)
REQUEST_PROOF_TTL = timedelta(seconds=90)
CLOCK_SKEW_LEEWAY_SECONDS = 60
ISSUER = "paari"
AUDIENCE = "paari-payment"


def _production_signing_posture() -> bool:
    env = os.environ.get("PAARI_ENV", "sandbox").strip().lower()
    return os.environ.get("PAARI_LIVE") == "1" or env in {"prod", "prod-live"}


def _load_or_create_signing_key() -> Ed25519PrivateKey:
    """Load the provisioned Ed25519 key, auto-generating only in sandbox/test.

    Production must not silently mint a new key on process start: doing so
    rotates the signing identity and invalidates previously issued credentials.
    A production deployment must provision the same durable key before boot.
    """
    production = _production_signing_posture()
    configured_path = os.environ.get("PAARI_SIGNING_KEY_PATH", "").strip()
    if production and not configured_path:
        raise RuntimeError("Production requires PAARI_SIGNING_KEY_PATH to reference a pre-provisioned Ed25519 private key")

    if os.path.isfile(_KEY_PATH):
        if production and os.name != "nt":
            mode = os.stat(_KEY_PATH).st_mode & 0o777
            if mode & 0o077:
                raise RuntimeError(
                    "Production signing-key file permissions are too broad; restrict the key file to owner-only access (0600/0400)"
                )
        with open(_KEY_PATH, "rb") as f:
            loaded = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise RuntimeError("Paari signing key must be an Ed25519 private key")
        return loaded

    if production:
        raise RuntimeError(
            "Production refuses to auto-generate a signing key; provision the durable Ed25519 key before starting Paari"
        )

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    parent = os.path.dirname(os.path.abspath(_KEY_PATH))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(_KEY_PATH, "wb") as f:
        f.write(pem)
    try:
        os.chmod(_KEY_PATH, 0o600)
    except OSError:
        pass
    return key


# All Paari-issued JWTs and agent-card signatures go through this interface.
# The sandbox defaults to local PEM; production operators must configure a real
# managed adapter and will still be blocked until trusted KYC/KYB is integrated.
_signing_backend = load_signing_backend(_load_or_create_signing_key)
_signing_key = getattr(_signing_backend, "private_key", None)  # dev/test compatibility only
_private_pem = getattr(_signing_backend, "private_pem", None)  # never populated by managed adapters
_public_pem = _signing_backend.public_key_pem_for(_signing_backend.key_id)


def signing_backend_status() -> dict:
    """Return non-secret signer status for startup/readiness checks."""
    try:
        healthy = bool(_signing_backend.healthcheck())
    except Exception:
        healthy = False
    return {
        "backend": "managed" if _signing_backend.managed else "local_pem",
        "key_id": str(_signing_backend.key_id),
        "managed": bool(_signing_backend.managed),
        "healthy": healthy,
    }


def paari_public_key_pem() -> str:
    return _signing_backend.public_key_pem_for(_signing_backend.key_id)


# Map the PQC algorithm strings carried by `crypto_utils.Algorithm` to the
# JWS/JWT `alg` identifiers registered in the IETF JOSE PQC registries. Ed25519
# keeps the legacy "EdDSA" identifier so pre-existing tokens verify unchanged.
_JWS_ALG_TO_ALGORITHM = {
    "ML-DSA-65": crypto_utils.Algorithm.ML_DSA_65,
    "SLH-DSA-SHA2-128S": crypto_utils.Algorithm.SLH_DSA_128S,
}


def _jws_alg(backend) -> str:
    algorithm = str(getattr(backend, "algorithm", "ed25519") or "ed25519")
    if algorithm == "ml-dsa-65":
        return "ML-DSA-65"
    if algorithm == "slh-dsa-sha2-128s":
        return "SLH-DSA-SHA2-128S"
    return "EdDSA"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def encode_jwt(payload: dict, backend) -> str:
    """Encode a compact JWS/JWT using the algorithm of the given backend.

    Ed25519 backends emit an "EdDSA" header and 64-byte signatures; PQC
    backends emit the matching PQC alg identifier and their (larger) signature
    bytes. The signing input is exactly `header_b64url.payload_b64url`, which is
    what the backend signs, so Ed25519 output is byte-identical to the legacy
    `encode_ed25519_jwt` for the same payload/keys.
    """
    header = {"alg": _jws_alg(backend), "kid": str(backend.key_id), "typ": "JWT"}
    header_part = _b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    payload_part = _b64url(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    signature = backend.sign(signing_input)
    if not isinstance(signature, bytes) or not signature:
        raise SigningBackendError("signing backend returned an empty signature")
    return f"{header_part}.{payload_part}.{_b64url(signature)}"


def _verify_pqc_signature(token: str, public_key_material: str, algorithm) -> None:
    header_part, payload_part, sig_part = token.split(".")
    signature_b64 = base64.b64encode(
        base64.urlsafe_b64decode(sig_part + "=" * (-len(sig_part) % 4))
    ).decode("ascii")
    if not crypto_utils.verify_signature(
        public_key_material, f"{header_part}.{payload_part}", signature_b64, algorithm=algorithm
    ):
        raise jwt.InvalidTokenError("post-quantum signature verification failed")


def decode_jwt(token: str, backend, *, typ: str | None = None,
               require: list[str] | None = None,
               issuer: str | None = None, audience: str | None = None) -> dict:
    """Decode and verify a Paari JWS/JWT, dispatching on the header `alg`.

    "EdDSA" tokens go through PyJWT (legacy path, unchanged). PQC tokens are
    verified by re-signing the JWS signing input and comparing with
    `crypto_utils.verify_signature` for the algorithm named in the header.
    """
    header = jwt.get_unverified_header(token)
    alg = header.get("alg")
    kid = header.get("kid") or getattr(backend, "key_id", None)
    try:
        public_material = backend.public_key_pem_for(kid)
    except SigningBackendError as exc:
        raise jwt.InvalidTokenError("token signing key is unknown or unavailable") from exc
    if alg == "EdDSA":
        claims = jwt.decode(
            token, public_material, algorithms=["EdDSA"],
            issuer=issuer, audience=audience,
            leeway=CLOCK_SKEW_LEEWAY_SECONDS,
            options={"verify_aud": audience is not None,
                     "require": list(require or []),
                     "verify_exp": True})
    else:
        algorithm = _JWS_ALG_TO_ALGORITHM.get(alg)
        if algorithm is None:
            raise jwt.InvalidTokenError(f"unsupported token algorithm: {alg!r}")
        _verify_pqc_signature(token, public_material, algorithm)
        claims = json.loads(base64.urlsafe_b64decode(
            token.split(".")[1] + "=" * (-len(token.split(".")[1]) % 4)))
        now = int(datetime.now(timezone.utc).timestamp())
        if "exp" in claims and claims["exp"] < now - CLOCK_SKEW_LEEWAY_SECONDS:
            raise jwt.InvalidTokenError("post-quantum token expired")
        if issuer is not None and claims.get("iss") != issuer:
            raise jwt.InvalidTokenError("post-quantum token issuer mismatch")
        if audience is not None and claims.get("aud") != audience:
            raise jwt.InvalidTokenError("post-quantum token audience mismatch")
        if require:
            for claim in require:
                if claim not in claims:
                    raise jwt.InvalidTokenError(f"post-quantum token missing claim {claim!r}")
    if typ and claims.get("typ") != typ:
        raise jwt.InvalidTokenError("wrong token type")
    return claims


def _verification_key_for_token(token: str) -> str:
    try:
        header = jwt.get_unverified_header(token)
        key_id = header.get("kid")
        if not isinstance(key_id, str) or not key_id:
            raise jwt.InvalidTokenError("token has no key id")
        return _signing_backend.public_key_pem_for(key_id)
    except jwt.InvalidTokenError:
        raise
    except Exception as exc:
        raise jwt.InvalidTokenError("token signing key is unknown or unavailable") from exc


def issue_credential_jwt(agent_id: str, capabilities: list[str], payment_limit: int, currency: str, *, protocol_version: str = "1.0") -> tuple[str, str, datetime]:
    credential_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = now + CREDENTIAL_TTL
    payload = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": agent_id, "jti": credential_id,
        "iat": int(now.timestamp()), "exp": int(expires_at.timestamp()),
        "typ": "paari_credential", "protocol_version": protocol_version,
        "capabilities": list(capabilities), "payment_limit_minor_units": int(payment_limit), "currency": currency,
    }
    token = encode_jwt(payload, _signing_backend)
    return token, credential_id, expires_at


def decode_credential_jwt(token: str) -> dict:
    return decode_jwt(token, _signing_backend, typ="paari_credential",
                      require=["iss", "aud", "sub", "jti", "iat", "exp"],
                      issuer=ISSUER, audience=AUDIENCE)


def issue_session_token(agent_id: str, credential_id: str, capabilities: list[str], payment_limit: int,
                        *, key_fingerprint: str = "", protocol_version: str = "1.0") -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires_at = now + SESSION_TOKEN_TTL
    payload = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": agent_id, "jti": str(uuid.uuid4()),
        "credential_id": credential_id, "iat": int(now.timestamp()), "exp": int(expires_at.timestamp()),
        "typ": "paari_session", "protocol_version": protocol_version,
        "capabilities": list(capabilities), "payment_limit_minor_units": int(payment_limit),
        "cnf": {"jkt": key_fingerprint} if key_fingerprint else {},
    }
    token = encode_jwt(payload, _signing_backend)
    return token, expires_at


def decode_session_token(token: str) -> dict:
    return decode_jwt(token, _signing_backend, typ="paari_session",
                      require=["iss", "aud", "sub", "jti", "iat", "exp"],
                      issuer=ISSUER, audience=AUDIENCE)


def issue_bounded_authorization_jwt(authorization_id: str, agent_id: str, intent_id: str,
                                    transaction_id: str, merchant: str, amount_minor_units: int,
                                    currency: str, mandate_id: str | None = None) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires_at = now + BOUNDED_AUTHORIZATION_TTL
    payload = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": agent_id, "jti": authorization_id,
        "iat": int(now.timestamp()), "exp": int(expires_at.timestamp()),
        "typ": "paari_bounded_authorization", "intent_id": intent_id,
        "transaction_id": transaction_id, "merchant": merchant,
        "amount_minor_units": int(amount_minor_units), "currency": currency, "max_usage": 1,
        "mandate_id": mandate_id,
    }
    token = encode_jwt(payload, _signing_backend)
    return token, expires_at


def decode_bounded_authorization_jwt(token: str) -> dict:
    return decode_jwt(token, _signing_backend, typ="paari_bounded_authorization",
                      require=["iss", "aud", "sub", "jti", "iat", "exp"],
                      issuer=ISSUER, audience=AUDIENCE)


def sign_agent_card(card_fields: dict) -> str:
    return base64.b64encode(_signing_backend.sign(crypto_utils.canonical_json(card_fields).encode())).decode("ascii")


def verify_agent_card(card_fields: dict, signature_b64: str, algorithm: str | None = None) -> bool:
    """Verify a Paari-signed agent card. `algorithm` defaults to the active
    signing backend's algorithm, so Ed25519 cards verify under ed25519 and
    ML-DSA cards verify under ml-dsa-65 without callers passing it explicitly."""
    algo = algorithm or getattr(_signing_backend, "algorithm", "ed25519")
    return crypto_utils.verify_signature(
        paari_public_key_pem(), crypto_utils.canonical_json(card_fields),
        signature_b64, algorithm=algo)


def request_proof_payload(*, method: str, path: str, access_token: str, agent_id: str,
                          jti: str, issued_at: int) -> dict:
    token_hash = hashlib.sha256(access_token.encode("utf-8")).digest()
    ath = base64.urlsafe_b64encode(token_hash).rstrip(b"=").decode("ascii")
    return {"typ": "paari-proof", "alg": "EdDSA", "sub": agent_id, "htm": method.upper(),
            "htu": path, "iat": int(issued_at), "jti": jti, "ath": ath}


def encode_request_proof(private_key_pem: str, *, method: str, path: str, access_token: str,
                         agent_id: str, jti: str, issued_at: int | None = None) -> str:
    issued = int(datetime.now(timezone.utc).timestamp()) if issued_at is None else int(issued_at)
    payload = request_proof_payload(method=method, path=path, access_token=access_token,
                                    agent_id=agent_id, jti=jti, issued_at=issued)
    return jwt.encode(payload, private_key_pem, algorithm="EdDSA", headers={"typ": "paari-proof+jwt", "kid": "agent"})


def verify_request_proof(proof_jwt: str, access_token: str, *, agent_id: str, public_key_pem: str,
                         method: str, path: str, db=None, org_id: str | None = None) -> dict:
    """Verify a DPoP-inspired Paari proof and burn its jti in the DB when
    a RequestProof model/session is supplied. Proofs are sender-constrained
    to the session token and exact HTTP method/path."""
    header = jwt.get_unverified_header(proof_jwt)
    alg = header.get("alg")
    if alg not in {"EdDSA", "ML-DSA-65", "SLH-DSA-SHA2-128S"}:
        raise jwt.InvalidTokenError("unsupported proof algorithm")
    if alg == "EdDSA":
        claims = jwt.decode(proof_jwt, public_key_pem, algorithms=["EdDSA"], options={"verify_aud": False})
    else:
        # PQC path: verify manually using crypto_utils (PyJWT has no PQC algs).
        _algo = _JWS_ALG_TO_ALGORITHM.get(alg)
        if _algo is None:
            raise jwt.InvalidTokenError(f"unsupported proof algorithm: {alg!r}")
        header_part, payload_part, sig_part = proof_jwt.split(".")
        sig_std_b64 = base64.b64encode(
            base64.urlsafe_b64decode(sig_part + "=" * (-len(sig_part) % 4))
        ).decode("ascii")
        if not crypto_utils.verify_signature(
            public_key_pem, f"{header_part}.{payload_part}", sig_std_b64, algorithm=_algo
        ):
            raise jwt.InvalidTokenError("post-quantum proof signature verification failed")
        claims = json.loads(base64.urlsafe_b64decode(
            payload_part + "=" * (-len(payload_part) % 4)))
    if claims.get("typ") != "paari-proof" or claims.get("sub") != agent_id:
        raise jwt.InvalidTokenError("invalid proof identity/type")
    now = int(datetime.now(timezone.utc).timestamp())
    iat = int(claims.get("iat", 0))
    if abs(now - iat) > int(REQUEST_PROOF_TTL.total_seconds()) + CLOCK_SKEW_LEEWAY_SECONDS:
        raise jwt.InvalidTokenError("proof too old or too far in the future")
    if claims.get("htm") != method.upper() or claims.get("htu") != path:
        raise jwt.InvalidTokenError("proof is not bound to this request")
    expected_ath = base64.urlsafe_b64encode(hashlib.sha256(access_token.encode("utf-8")).digest()).rstrip(b"=").decode("ascii")
    if not secrets.compare_digest(str(claims.get("ath", "")), expected_ath):
        raise jwt.InvalidTokenError("proof is not bound to this session token")
    jti = claims.get("jti")
    if not jti:
        raise jwt.InvalidTokenError("proof missing jti")
    if db is not None:
        from app import models
        existing = db.query(models.RequestProof).filter_by(jti=jti).first()
        if existing is not None:
            raise jwt.InvalidTokenError("request proof replayed")
        db.add(models.RequestProof(jti=jti, agent_id=agent_id, org_id=org_id or "default",
                                   issued_at=datetime.fromtimestamp(iat, tz=timezone.utc),
                                   expires_at=datetime.fromtimestamp(iat, tz=timezone.utc) + REQUEST_PROOF_TTL))
        db.flush()
    return claims


_ADMIN_API_KEY = os.environ.get("PAARI_ADMIN_API_KEY")
if not _ADMIN_API_KEY:
    _ADMIN_API_KEY = secrets.token_urlsafe(32)
    print("PAARI_ADMIN_API_KEY not set; using an ephemeral development key for this process.")


def is_admin_key(candidate: str) -> bool:
    return bool(candidate) and secrets.compare_digest(candidate, _ADMIN_API_KEY)


def require_admin(x_admin_api_key: str = Header(default="")) -> None:
    if not is_admin_key(x_admin_api_key):
        raise HTTPException(status_code=401, detail="Missing or invalid admin credentials")


def require_admin_org(x_admin_api_key: str, target_org: str | None) -> None:
    if not is_admin_key(x_admin_api_key):
        raise HTTPException(status_code=401, detail="Missing or invalid admin credentials")
    bound_org = os.environ.get("PAARI_ADMIN_ORG", "")
    if bound_org and bound_org != (target_org or ""):
        raise HTTPException(status_code=403, detail="Admin key is not authorized for this organization")
