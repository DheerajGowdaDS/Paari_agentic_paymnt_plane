"""Cryptographic primitives for an external Paari v1 agent.

This package intentionally has no dependency on the Paari server's ``app``
modules. An independent agent can use it as the protocol reference client.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROTOCOL = "paari"
VERSION = "1.0"


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _oqs_signer(algorithm: str):
    """Return an `oqs.Signature` instance, or None if unavailable."""
    import oqs
    mechanism_names = {
        "ml-dsa-65": "ML-DSA-65",
        "slh-dsa-sha2-128s": "SLH_DSA_PURE_SHAKE_128S",
    }
    name = mechanism_names.get(algorithm, algorithm)
    try:
        return oqs.Signature(name)
    except Exception:
        return None


def generate_keypair(algorithm: str = "ed25519") -> tuple[str, str]:
    """Generate a key pair.

    Ed25519 (default): returns PEM strings.
    PQC algorithms: returns (base64 raw secret, base64 raw public) — no
    standard PQC PEM format exists yet.
    """
    if algorithm == "ed25519":
        key = Ed25519PrivateKey.generate()
        private_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        public_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return private_pem, public_pem
    else:
        signer = _oqs_signer(algorithm)
        if signer is None:
            raise RuntimeError(
                f"PQC algorithm {algorithm!r} is not available in the installed "
                "liboqs build. Install or upgrade liboqs-python.")
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
        return base64.b64encode(secret_key).decode(), base64.b64encode(public_key).decode()


def fingerprint(public_key_pem: str, algorithm: str = "ed25519") -> str:
    digest = hashlib.sha256(public_key_pem.encode("utf-8")).hexdigest()
    if algorithm == "ed25519":
        return digest
    return f"{algorithm}:{digest}"


_OQS_MECHANISM_NAMES = {
    "ml-dsa-65": "ML-DSA-65",
    "slh-dsa-sha2-128s": "SLH_DSA_PURE_SHAKE_128S",
}


def _oqs_mechanism(algorithm: str) -> str:
    return _OQS_MECHANISM_NAMES.get(algorithm, algorithm)


def sign_text(private_key_pem: str, text: str, algorithm: str = "ed25519") -> str:
    if algorithm == "ed25519":
        key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        return base64.b64encode(key.sign(text.encode("utf-8"))).decode("ascii")
    import oqs
    if _oqs_signer(algorithm) is None:
        raise RuntimeError(
            f"PQC algorithm {algorithm!r} is not available in the installed "
            "liboqs build.")
    secret_key = base64.b64decode(private_key_pem)
    sig_obj = oqs.Signature(_oqs_mechanism(algorithm), secret_key)
    return base64.b64encode(sig_obj.sign(text.encode("utf-8"))).decode("ascii")


def verify_signature(public_key: str, text: str, signature_b64: str,
                     algorithm: str = "ed25519") -> bool:
    """Verify a signature. Ed25519: PEM key. PQC: base64 raw public key."""
    if algorithm == "ed25519":
        key = serialization.load_pem_public_key(public_key.encode())
        try:
            key.verify(base64.b64decode(signature_b64), text.encode("utf-8"))
            return True
        except Exception:
            return False
    else:
        import oqs
        try:
            pub = base64.b64decode(public_key)
            sig = base64.b64decode(signature_b64)
            signer = oqs.Signature(_oqs_mechanism(algorithm))
            return bool(signer.verify(text.encode("utf-8"), sig, pub))
        except Exception:
            return False


def sign_delegation(private_key_pem: str, delegation: dict[str, Any],
                    algorithm: str = "ed25519") -> str:
    return sign_text(private_key_pem, canonical_json(delegation), algorithm=algorithm)


def build_envelope(private_key_pem: str, *, sender: str, payload: dict[str, Any],
                   message_type: str, ttl_seconds: int = 120,
                   receiver: str = "paari", algorithm: str = "ed25519") -> dict[str, Any]:
    now = int(time.time())
    if ttl_seconds <= 0 or ttl_seconds > 300:
        raise ValueError("ttl_seconds must be between 1 and 300")
    envelope = {
        "protocol": PROTOCOL,
        "version": VERSION,
        "type": message_type,
        "message_id": str(uuid.uuid4()),
        "sender": sender,
        "receiver": receiver,
        "issued_at": now,
        "expires_at": now + ttl_seconds,
        "payload": payload,
    }
    if algorithm != "ed25519":
        envelope["signature_algorithm"] = algorithm
    envelope["signature"] = sign_text(private_key_pem, canonical_json(envelope),
                                      algorithm=algorithm)
    return envelope


def build_request_proof(private_key_pem: str, *, agent_id: str, access_token: str,
                        method: str, path: str, jti: str | None = None,
                        issued_at: int | None = None, algorithm: str = "ed25519") -> str:
    """Build a JWS proof. Ed25519 uses PyJWT; PQC uses manual JWS construction."""
    issued = int(time.time()) if issued_at is None else int(issued_at)
    ath = base64.urlsafe_b64encode(hashlib.sha256(access_token.encode()).digest()).rstrip(b"=").decode()
    claims = {
        "typ": "paari-proof",
        "sub": agent_id,
        "htm": method.upper(),
        "htu": path,
        "iat": issued,
        "jti": jti or str(uuid.uuid4()),
        "ath": ath,
    }
    if algorithm == "ed25519":
        key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        header = {"alg": "EdDSA", "typ": "paari-proof+jwt", "kid": "agent"}
        return jwt.encode(claims, key, algorithm="EdDSA", headers=header)
    else:
        # Manual PQC JWS
        header = {"alg": "ML-DSA-65" if algorithm == "ml-dsa-65" else "SLH-DSA-SHA2-128S",
                  "typ": "paari-proof+jwt", "kid": "agent"}
        h64 = base64.urlsafe_b64encode(
            json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        p64 = base64.urlsafe_b64encode(
            json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        sig_input = f"{h64}.{p64}".encode("ascii")
        import oqs
        sig = oqs.Signature(_oqs_mechanism(algorithm), base64.b64decode(private_key_pem)).sign(sig_input)
        s64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return f"{h64}.{p64}.{s64}"


def verify_paari_card(card: dict[str, Any]) -> bool:
    """Verify a Paari-signed Agent Card using the key embedded in the card.

    Checks both Ed25519 (PEM) and PQC (base64 raw) key formats based on the
    card's `paari_key_algorithm` field (default ed25519)."""
    signature = card.get("card_signature_b64", "")
    paari_public = card.get("paari_public_key_pem", "")
    algorithm = card.get("paari_key_algorithm", "ed25519")
    if not signature or not paari_public:
        return False
    signed_fields = {k: v for k, v in card.items()
                     if k not in {"card_signature_b64", "paari_public_key_pem", "paari_key_algorithm"}}
    try:
        return verify_signature(paari_public, canonical_json(signed_fields),
                                signature, algorithm=algorithm)
    except Exception:
        return False
