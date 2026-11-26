"""Post-quantum signature abstraction layer (Phase 1).

Tests for `app.crypto_utils` algorithm dispatch:
- ED25519 remains the working default (regression).
- ML-DSA-65 / SLH-DSA-128S sign and verify via the installed PQC backend
  (liboqs-python). Keys are raw bytes base64-encoded (no standard PQC PEM
  format exists yet); Ed25519 keys remain PEM.
- `public_key_fingerprint` is algorithm-prefixed.
"""
from __future__ import annotations

import pytest

from app.crypto_utils import (
    Algorithm,
    PQCBackendUnavailable,
    _OQS_MECHANISM_NAMES,
    generate_keypair,
    public_key_fingerprint,
    sign_with_private_key,
    verify_signature,
)

# liboqs-python is optional. The Ed25519 regression tests below must keep
# running everywhere; only the PQC-specific tests require the `oqs` package.
# (Sibling PQC modules use a module-level importorskip because they are
# PQC-only; this file mixes classical and PQC coverage, so the guard is
# per-test instead of per-module.)
try:
    import oqs  # noqa: F401
    _OQS_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    _OQS_AVAILABLE = False

_OQS_SKIP = pytest.mark.skipif(not _OQS_AVAILABLE, reason="liboqs-python not installed")


class TestAlgorithmEnum:
    def test_values(self):
        assert Algorithm.ED25519 == "ed25519"
        assert Algorithm.ML_DSA_65 == "ml-dsa-65"
        assert Algorithm.SLH_DSA_128S == "slh-dsa-sha2-128s"


class TestEd25519Regression:
    def test_sign_verify_round_trip(self):
        private_pem, public_pem = generate_keypair(Algorithm.ED25519)
        message = "agent delegation payload"
        signature = sign_with_private_key(private_pem, message, algorithm=Algorithm.ED25519)
        assert isinstance(signature, str) and signature
        assert verify_signature(public_pem, message, signature, algorithm=Algorithm.ED25519) is True

    def test_wrong_message_fails(self):
        private_pem, public_pem = generate_keypair(Algorithm.ED25519)
        signature = sign_with_private_key(private_pem, "original", algorithm=Algorithm.ED25519)
        assert verify_signature(public_pem, "tampered", signature, algorithm=Algorithm.ED25519) is False


class TestPQCRoundTrip:
    @_OQS_SKIP
    def test_ml_dsa_65_sign_verify_round_trip(self):
        private, public = generate_keypair(Algorithm.ML_DSA_65)
        assert isinstance(private, str) and isinstance(public, str) and private and public
        signature = sign_with_private_key(private, "delegation payload", algorithm=Algorithm.ML_DSA_65)
        assert isinstance(signature, str) and signature
        assert verify_signature(public, "delegation payload", signature, algorithm=Algorithm.ML_DSA_65) is True
        assert verify_signature(public, "tampered", signature, algorithm=Algorithm.ML_DSA_65) is False

    @_OQS_SKIP
    def test_slh_dsa_128s(self):
        """SLH-DSA round-trips when the mechanism is enabled in liboqs; otherwise
        requesting it raises PQCBackendUnavailable (this build omits SLH-DSA)."""
        import oqs

        mechanism = _OQS_MECHANISM_NAMES[Algorithm.SLH_DSA_128S]
        available = mechanism in oqs.get_enabled_sig_mechanisms()
        if available:
            private, public = generate_keypair(Algorithm.SLH_DSA_128S)
            signature = sign_with_private_key(private, "audit anchor", algorithm=Algorithm.SLH_DSA_128S)
            assert verify_signature(public, "audit anchor", signature, algorithm=Algorithm.SLH_DSA_128S) is True
            assert verify_signature(public, "tampered", signature, algorithm=Algorithm.SLH_DSA_128S) is False
        else:
            with pytest.raises(PQCBackendUnavailable):
                generate_keypair(Algorithm.SLH_DSA_128S)


class TestPublicKeyFingerprint:
    def test_ed25519_fingerprint_is_plain_hex_backward_compatible(self):
        _, public_pem = generate_keypair(Algorithm.ED25519)
        fp = public_key_fingerprint(public_pem)
        assert len(fp) == 64
        assert fp == public_key_fingerprint(public_pem, algorithm=Algorithm.ED25519)
        assert not fp.startswith("ed25519:")

    @_OQS_SKIP
    def test_pqc_fingerprint_is_algorithm_prefixed(self):
        _, public = generate_keypair(Algorithm.ML_DSA_65)
        fp = public_key_fingerprint(public, algorithm=Algorithm.ML_DSA_65)
        assert fp.startswith("ml-dsa-65:")
        assert fp != public_key_fingerprint(public)  # default is ed25519 plain hash of base64 key
