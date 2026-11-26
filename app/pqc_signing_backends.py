"""Post-quantum signing backends (Phase 3).

MlDsaSigningBackend / SlhDsaSigningBackend implement the SigningBackend
protocol over liboqs-python. They are instantiated from raw (base64) keys
produced by crypto_utils.generate_keypair(Algorithm.ML_DSA_65/SLH_DSA_128S).
"""
from __future__ import annotations

import base64
from typing import Protocol, runtime_checkable

import oqs

from app.crypto_utils import Algorithm, _OQS_MECHANISM_NAMES, PQCBackendUnavailable
from app.signing_backends import SigningBackend, SigningBackendError


class PqcSigningBackend:
    """Shared implementation for ML-DSA / SLH-DSA signing backends."""

    managed = False

    def __init__(self, *, algorithm: Algorithm, secret_key_b64: str, public_key_b64: str, key_id: str = "paari-pq-1") -> None:
        self.algorithm = algorithm.value
        self.key_id = key_id
        self._secret_key = base64.b64decode(secret_key_b64)
        self._public_key = base64.b64decode(public_key_b64)
        self._mechanism = _OQS_MECHANISM_NAMES[algorithm]
        # Validate the mechanism is available up front.
        try:
            oqs.Signature(self._mechanism)
        except Exception as exc:
            raise SigningBackendError(f"PQC mechanism {self._mechanism} unavailable: {exc}") from exc

    def sign(self, message: bytes) -> bytes:
        bound = oqs.Signature(self._mechanism, self._secret_key)
        return bound.sign(message)

    def public_key_pem_for(self, key_id: str) -> str:
        # PQC keys have no standard PEM format yet; return the base64 raw
        # public key so crypto_utils.verify_signature can decode it.
        return base64.b64encode(self._public_key).decode("ascii")

    def healthcheck(self) -> bool:
        try:
            oqs.Signature(self._mechanism)
            return True
        except Exception:
            return False


class MlDsaSigningBackend(PqcSigningBackend):
    def __init__(self, *, secret_key_b64: str, public_key_b64: str, key_id: str = "paari-ml-dsa-65-1") -> None:
        super().__init__(algorithm=Algorithm.ML_DSA_65, secret_key_b64=secret_key_b64, public_key_b64=public_key_b64, key_id=key_id)


class SlhDsaSigningBackend(PqcSigningBackend):
    def __init__(self, *, secret_key_b64: str, public_key_b64: str, key_id: str = "paari-slh-dsa-128s-1") -> None:
        super().__init__(algorithm=Algorithm.SLH_DSA_128S, secret_key_b64=secret_key_b64, public_key_b64=public_key_b64, key_id=key_id)
