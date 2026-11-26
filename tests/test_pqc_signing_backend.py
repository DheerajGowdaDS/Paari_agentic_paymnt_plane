"""Tests for post-quantum signing backends (Phase 3)."""
from __future__ import annotations

import base64

import pytest

# liboqs-python is an optional dependency. Skip this module cleanly when its
# native provider is not installed instead of failing test collection.
pytest.importorskip("oqs", reason="liboqs-python is required for PQC backend tests")

from app.crypto_utils import Algorithm, generate_keypair, sign_with_private_key, verify_signature
from app.pqc_signing_backends import MlDsaSigningBackend, SlhDsaSigningBackend
from app.signing_backends import SigningBackend


class TestMlDsaSigningBackend:
    def test_implements_signing_backend_protocol(self):
        private, public = generate_keypair(Algorithm.ML_DSA_65)
        backend = MlDsaSigningBackend(secret_key_b64=private, public_key_b64=public)
        assert isinstance(backend, SigningBackend)
        assert backend.algorithm == "ml-dsa-65"
        assert backend.managed is False

    def test_sign_and_verify_via_crypto_utils(self):
        private, public = generate_keypair(Algorithm.ML_DSA_65)
        backend = MlDsaSigningBackend(secret_key_b64=private, public_key_b64=public)
        message = b"paari agent card payload"
        signature = backend.sign(message)
        assert isinstance(signature, bytes) and len(signature) > 0
        # crypto_utils expects base64 strings.
        sig_b64 = base64.b64encode(signature).decode()
        pub = backend.public_key_pem_for(backend.key_id)
        assert verify_signature(pub, message.decode(), sig_b64, algorithm=Algorithm.ML_DSA_65) is True

    def test_healthcheck(self):
        private, public = generate_keypair(Algorithm.ML_DSA_65)
        backend = MlDsaSigningBackend(secret_key_b64=private, public_key_b64=public)
        assert backend.healthcheck() is True


class TestSlhDsaSigningBackend:
    def test_implements_signing_backend_protocol(self):
        private, public = generate_keypair(Algorithm.SLH_DSA_128S)
        backend = SlhDsaSigningBackend(secret_key_b64=private, public_key_b64=public)
        assert isinstance(backend, SigningBackend)
        assert backend.algorithm == "slh-dsa-sha2-128s"

    def test_sign_and_verify_via_crypto_utils(self):
        private, public = generate_keypair(Algorithm.SLH_DSA_128S)
        backend = SlhDsaSigningBackend(secret_key_b64=private, public_key_b64=public)
        message = b"audit anchor"
        signature = backend.sign(message)
        sig_b64 = base64.b64encode(signature).decode()
        pub = backend.public_key_pem_for(backend.key_id)
        assert verify_signature(pub, message.decode(), sig_b64, algorithm=Algorithm.SLH_DSA_128S) is True

    def test_healthcheck(self):
        private, public = generate_keypair(Algorithm.SLH_DSA_128S)
        backend = SlhDsaSigningBackend(secret_key_b64=private, public_key_b64=public)
        assert backend.healthcheck() is True
