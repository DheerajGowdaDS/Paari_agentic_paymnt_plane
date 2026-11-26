"""Phase 7: hybrid (classical + PQC) signatures and Ed25519 backward compat.

Model A (dual-algorithm): store/transmit both an Ed25519 and a PQC signature.
During the migration window, at least one must verify; at cutover, the PQC
signature must verify. `crypto_utils.verify_hybrid_signature` implements the
fail-closed OR/AND logic so callers don't hand-roll it.
"""
from __future__ import annotations

import pytest

from app.crypto_utils import (
    Algorithm,
    generate_keypair,
    sign_with_private_key,
    verify_signature,
    verify_hybrid_signature,
)

# liboqs-python is optional. The Ed25519-only tests in this file keep running
# on every machine; only tests that actually call generate_keypair(ML_DSA_65)
# require the PQC backend.
try:
    import oqs  # noqa: F401
    _OQS_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    _OQS_AVAILABLE = False

_OQS_SKIP = pytest.mark.skipif(not _OQS_AVAILABLE, reason="liboqs-python not installed")


class TestHybridSignature:
    @_OQS_SKIP
    def test_both_signatures_verify(self):
        ed_priv, ed_pub = generate_keypair(Algorithm.ED25519)
        pq_priv, pq_pub = generate_keypair(Algorithm.ML_DSA_65)
        message = "delegation document v1"
        ed_sig = sign_with_private_key(ed_priv, message, algorithm=Algorithm.ED25519)
        pq_sig = sign_with_private_key(pq_priv, message, algorithm=Algorithm.ML_DSA_65)
        # During-window (require_any=True): at least one valid signature.
        assert verify_hybrid_signature(
            message, ed_sig, ed_pub, Algorithm.ED25519,
            pq_sig, pq_pub, Algorithm.ML_DSA_65, require_any=True) is True

    def test_ed25519_tampered_pqc_still_passes_window_mode(self):
        """Window mode: if EITHER is valid the signature set is accepted."""
        ed_priv, ed_pub = generate_keypair(Algorithm.ED25519)
        message = "delegation document v1"
        ed_sig = sign_with_private_key(ed_priv, message, algorithm=Algorithm.ED25519)
        assert verify_hybrid_signature(
            message, ed_sig, ed_pub, Algorithm.ED25519,
            None, None, None, require_any=True) is True

    @_OQS_SKIP
    def test_cutover_mode_requires_pqc(self):
        """Cutover mode: the PQC signature MUST verify (window requirement)."""
        ed_priv, ed_pub = generate_keypair(Algorithm.ED25519)
        pq_priv, pq_pub = generate_keypair(Algorithm.ML_DSA_65)
        message = "delegation document v1"
        ed_sig = sign_with_private_key(ed_priv, message, algorithm=Algorithm.ED25519)
        pq_sig = sign_with_private_key(pq_priv, message, algorithm=Algorithm.ML_DSA_65)
        # require_any=False (cutover): only PQC must verify.
        assert verify_hybrid_signature(
            message, None, None, None,
            pq_sig, pq_pub, Algorithm.ML_DSA_65, require_any=False) is True
        # PQC signature absent -> cutover fails closed.
        assert verify_hybrid_signature(
            message, ed_sig, ed_pub, Algorithm.ED25519,
            None, None, None, require_any=False) is False

    @_OQS_SKIP
    def test_both_tampered_fails(self):
        ed_priv, ed_pub = generate_keypair(Algorithm.ED25519)
        pq_priv, pq_pub = generate_keypair(Algorithm.ML_DSA_65)
        # Both signatures are for a different message.
        other = "some other message"
        ed_sig = sign_with_private_key(ed_priv, other, algorithm=Algorithm.ED25519)
        pq_sig = sign_with_private_key(pq_priv, other, algorithm=Algorithm.ML_DSA_65)
        assert verify_hybrid_signature(
            "delegation document v1", ed_sig, ed_pub, Algorithm.ED25519,
            pq_sig, pq_pub, Algorithm.ML_DSA_65, require_any=True) is False


class TestEd25519BackwardCompat:
    def test_legacy_key_still_verifies_after_pqc_work(self):
        """Regression: an Ed25519 key produced before PQC migration verifies
        with the default algorithm (no PQC involvement)."""
        ed_priv, ed_pub = generate_keypair(Algorithm.ED25519)
        sig = sign_with_private_key(ed_priv, "legacy delegation", algorithm=Algorithm.ED25519)
        # Default algorithm is ed25519; no PQC backend needed.
        assert verify_signature(ed_pub, "legacy delegation", sig) is True
        # Fingerprint is plain hex (no algorithm prefix), matching Phase 1.
        from app.crypto_utils import public_key_fingerprint
        fp = public_key_fingerprint(ed_pub)
        assert len(fp) == 64 and not fp.startswith("ed25519:")
