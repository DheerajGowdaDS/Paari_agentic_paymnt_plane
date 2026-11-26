"""Phase 6: SDK PQC keygen/sign and the v3.5 agreement signing script.

The agent SDK (sdk/paari_agent) must be able to generate and sign with
ML-DSA-65 keys so external agents can adopt PQC without touching the server.
Ed25519 behaviour is unchanged (regression).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

from sdk.paari_agent import crypto as sdk_crypto


def _ml_dsa_available():
    try:
        import oqs
        return "ML-DSA-65" in oqs.get_enabled_sig_mechanisms()
    except Exception:
        return False


class TestSdkGenerateKeypair:
    def test_ed25519_default_unchanged(self):
        priv, pub = sdk_crypto.generate_keypair()
        assert "PRIVATE KEY" in priv
        assert sdk_crypto.fingerprint(pub) == sdk_crypto.fingerprint(pub, algorithm="ed25519")

    @pytest.mark.skipif(not _ml_dsa_available(), reason="ML-DSA not enabled in liboqs")
    def test_ml_dsa_keypair_returns_raw_b64(self):
        priv, pub = sdk_crypto.generate_keypair("ml-dsa-65")
        import base64
        # PQC keys are raw bytes base64 (no standard PQC PEM yet).
        assert isinstance(priv, str) and isinstance(pub, str) and priv and pub
        assert "PRIVATE KEY" not in priv  # not PEM
        base64.b64decode(priv, validate=True)
        base64.b64decode(pub, validate=True)


class TestSdkSign:
    def test_ed25519_sign_verify(self):
        priv, pub = sdk_crypto.generate_keypair()
        sig = sdk_crypto.sign_text(priv, "hello")
        # verify via the SDK's canonical path (Ed25519)
        import base64
        from cryptography.hazmat.primitives import serialization
        key = serialization.load_pem_public_key(pub.encode())
        key.verify(base64.b64decode(sig), b"hello")

    @pytest.mark.skipif(not _ml_dsa_available(), reason="ML-DSA not enabled in liboqs")
    def test_ml_dsa_sign_verify(self):
        priv, pub = sdk_crypto.generate_keypair("ml-dsa-65")
        sig = sdk_crypto.sign_text(priv, "agent delegation", algorithm="ml-dsa-65")
        ok = sdk_crypto.verify_signature(pub, "agent delegation", sig, algorithm="ml-dsa-65")
        assert ok is True
        assert sdk_crypto.verify_signature(pub, "tampered", sig, algorithm="ml-dsa-65") is False


class TestSdkEnvelope:
    @pytest.mark.skipif(not _ml_dsa_available(), reason="ML-DSA not enabled in liboqs")
    def test_ml_dsa_envelope_carries_algorithm(self):
        priv, pub = sdk_crypto.generate_keypair("ml-dsa-65")
        env = sdk_crypto.build_envelope(priv, sender="agent-1", payload={"a": 1},
                                        message_type="payment.intent", algorithm="ml-dsa-65")
        assert env["signature_algorithm"] == "ml-dsa-65"
        # Envelope signature must verify under the PQC algorithm.
        import app.protocol.envelope as penv
        assert penv.verify_envelope(pub, env, algorithm="ml-dsa-65") is True


class TestV35SignAgreementScript:
    @pytest.mark.skipif(not _ml_dsa_available(), reason="ML-DSA not enabled in liboqs")
    def test_script_signs_with_algorithm_flag(self, tmp_path):
        # Generate an ML-DSA keypair and write a minimal valid claims file.
        import hashlib
        from datetime import datetime, timedelta, timezone
        from app.federation.contracts import AgreementClaims
        from app import crypto_utils

        priv, _pub = crypto_utils.generate_keypair(crypto_utils.Algorithm.ML_DSA_65)
        key_file = tmp_path / "user.key"
        key_file.write_text(priv, encoding="utf-8")

        now = datetime.now(timezone.utc)
        claims = AgreementClaims(
            agreement_id="a" * 12, org_id="default", agent_id="agent-1",
            beneficiary_id="ben-1", subject_type="SENDER_ORG", subject_id="default",
            purpose="approved vendor purchase", max_amount_minor_units=10000,
            currency="INR", policy_digest="b" * 64, document_digest="c" * 64,
            issued_at=now, expires_at=now + timedelta(days=1))
        claims_file = tmp_path / "claims.json"
        claims_file.write_text(json.dumps(claims.model_dump(mode="json")), encoding="utf-8")

        out = tmp_path / "signed.json"
        import os
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "v35_sign_agreement.py"),
             "--claims", str(claims_file), "--private-key", str(key_file),
             "--out", str(out), "--algorithm", "ml-dsa-65"],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT)})
        assert result.returncode == 0, result.stderr
        signed = json.loads(out.read_text())
        assert signed["signature_algorithm"] == "ml-dsa-65"
        assert signed["signature_b64"]  # non-empty PQC signature
