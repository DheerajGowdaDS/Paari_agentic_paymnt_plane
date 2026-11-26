"""Phase 4: algorithm-aware JWS/JWT encoding and decoding.

Verifies:
- encode_jwt with an ML-DSA backend sets the header alg to "ML-DSA-65".
- decode_jwt accepts PQC-signed tokens and Ed25519 (EdDSA) tokens.
- verify_request_proof no longer rejects non-EdDSA algs.
- The legacy Ed25519 path is unchanged.
"""
from __future__ import annotations

import base64
import json
import pytest

# liboqs-python is an optional dependency. Skip this module cleanly when its
# native provider is not installed instead of failing test collection.
pytest.importorskip("oqs", reason="liboqs-python is required for PQC backend tests")

from app.crypto_utils import Algorithm, generate_keypair
from app.pqc_signing_backends import MlDsaSigningBackend, SlhDsaSigningBackend
from app.signing_backends import (
    LocalPemSigningBackend,
    SigningBackendError,
    encode_ed25519_jwt,
)
from app import security


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_local_backend():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return LocalPemSigningBackend(Ed25519PrivateKey.generate())


def _make_ml_dsa_backend():
    priv, pub = generate_keypair(Algorithm.ML_DSA_65)
    return MlDsaSigningBackend(secret_key_b64=priv, public_key_b64=pub)


# ─────────────────────────────────────────────────────────────────────────────
#  encode_jwt  (new — algorithm-aware)
# ─────────────────────────────────────────────────────────────────────────────

class TestEncodeJwt:
    def test_ed25519_backend_produces_eddsa_header(self):
        backend = _make_local_backend()
        token = security.encode_jwt({"sub": "agent-1"}, backend)
        h64 = token.split(".")[0]
        header = json.loads(base64.urlsafe_b64decode(h64 + "=" * (-len(h64) % 4)))
        assert header["alg"] == "EdDSA"
        assert header["kid"] == backend.key_id

    def test_ml_dsa_backend_produces_ml_dsa_65_header(self):
        backend = _make_ml_dsa_backend()
        token = security.encode_jwt({"sub": "agent-1"}, backend)
        h64 = token.split(".")[0]
        header = json.loads(base64.urlsafe_b64decode(h64 + "=" * (-len(h64) % 4)))
        assert header["alg"] == "ML-DSA-65"

    def test_encoded_token_has_three_segments(self):
        backend = _make_ml_dsa_backend()
        token = security.encode_jwt({"sub": "agent-1"}, backend)
        assert token.count(".") == 2


# ─────────────────────────────────────────────────────────────────────────────
#  decode_jwt  (new — algorithm-aware verification)
# ─────────────────────────────────────────────────────────────────────────────

class TestDecodeJwt:
    def test_ed25519_roundtrip_unchanged(self):
        backend = _make_local_backend()
        token = security.encode_jwt({"sub": "agent-1", "typ": "paari_credential",
                                     "iss": "paari", "aud": "paari-payment",
                                     "jti": "abc", "iat": 0, "exp": 9999999999,
                                     "capabilities": [], "payment_limit_minor_units": 0,
                                     "currency": "INR"},
                                    backend)
        claims = security.decode_jwt(token, backend)
        assert claims["sub"] == "agent-1"

    def test_ml_dsa_roundtrip(self):
        backend = _make_ml_dsa_backend()
        token = security.encode_jwt({"sub": "agent-1", "typ": "paari_credential",
                                     "iss": "paari", "aud": "paari-payment",
                                     "jti": "abc", "iat": 0, "exp": 9999999999,
                                     "capabilities": [], "payment_limit_minor_units": 0,
                                     "currency": "INR"},
                                    backend)
        claims = security.decode_jwt(token, backend)
        assert claims["sub"] == "agent-1"
        assert claims["jti"] == "abc"

    def test_tampered_payload_rejected(self):
        backend = _make_ml_dsa_backend()
        token = security.encode_jwt({"sub": "agent-1", "typ": "paari_credential",
                                     "iss": "paari", "aud": "paari-payment",
                                     "jti": "abc", "iat": 0, "exp": 9999999999,
                                     "capabilities": [], "payment_limit_minor_units": 0,
                                     "currency": "INR"},
                                    backend)
        h, p, s = token.split(".")
        payload = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        payload["sub"] = "agent-evil"
        tampered_payload = _b64url(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        tampered = f"{h}.{tampered_payload}.{s}"
        with pytest.raises(Exception):
            security.decode_jwt(tampered, backend)

    def test_wrong_backend_rejects(self):
        backend_a = _make_ml_dsa_backend()
        backend_b = _make_ml_dsa_backend()
        token = security.encode_jwt({"sub": "x", "typ": "paari_credential", "iss": "paari",
                                     "aud": "paari-payment", "jti": "j", "iat": 0,
                                     "exp": 9999999999, "capabilities": [],
                                     "payment_limit_minor_units": 0, "currency": "INR"},
                                    backend_a)
        with pytest.raises(Exception):
            security.decode_jwt(token, backend_b)


# ─────────────────────────────────────────────────────────────────────────────
#  verify_request_proof  (PQC alg acceptance)
# ─────────────────────────────────────────────────────────────────────────────

class TestVerifyRequestProof:
    def test_ed25519_proof_still_accepted(self):
        from app.crypto_utils import sign_with_private_key
        priv, pub = generate_keypair(Algorithm.ED25519)
        token_hash = base64.urlsafe_b64encode(
            __import__("hashlib").sha256(b"session-token-abc").digest()
        ).rstrip(b"=").decode()
        import jwt as pyjwt
        import time
        claims = {"typ": "paari-proof", "alg": "EdDSA", "sub": "agent-1",
                  "htm": "POST", "htu": "/v1/payments", "iat": int(time.time()),
                  "jti": "proof-1", "ath": token_hash}
        proof = pyjwt.encode(claims, priv, algorithm="EdDSA",
                             headers={"typ": "paari-proof+jwt", "kid": "agent"})
        result = security.verify_request_proof(
            proof, "session-token-abc", agent_id="agent-1",
            public_key_pem=pub, method="POST", path="/v1/payments", db=None)
        assert result["sub"] == "agent-1"

    def test_ml_dsa_proof_accepted(self):
        import time
        priv, pub = generate_keypair(Algorithm.ML_DSA_65)
        iat = int(time.time())
        token_hash = base64.urlsafe_b64encode(
            __import__("hashlib").sha256(b"session-token-abc").digest()
        ).rstrip(b"=").decode()
        claims = {"typ": "paari-proof", "alg": "ML-DSA-65", "sub": "agent-1",
                  "htm": "POST", "htu": "/v1/payments", "iat": iat,
                  "jti": "proof-pqc-1", "ath": token_hash}
        header_b64 = _b64url(json.dumps({"alg": "ML-DSA-65", "typ": "paari-proof+jwt", "kid": "agent"},
                                         sort_keys=True, separators=(",", ":")).encode())
        payload_b64 = _b64url(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
        sig_input = f"{header_b64}.{payload_b64}".encode("ascii")
        from app.crypto_utils import sign_with_private_key
        sig_b64 = sign_with_private_key(priv, sig_input.decode(), algorithm=Algorithm.ML_DSA_65)
        proof = f"{header_b64}.{payload_b64}.{_b64url(base64.b64decode(sig_b64))}"

        result = security.verify_request_proof(
            proof, "session-token-abc", agent_id="agent-1",
            public_key_pem=pub, method="POST", path="/v1/payments", db=None)
        assert result["sub"] == "agent-1"
