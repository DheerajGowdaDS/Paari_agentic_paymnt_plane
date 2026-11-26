"""Phase 2b + 5: PQC-sized federation schema and algorithm-aware verification.

Covers:
- SignedAgreement contract accepts PQC-sized signatures.
- policy.verify_agreement verifies Ed25519 (regression) AND ML-DSA-65
  signatures when the federation signer row carries a PQC algorithm.
- Cross-algorithm rejection (PQC signature against an Ed25519-tagged signer).
- security.sign_agent_card / verify_agent_card round-trip under an ML-DSA
  signing backend, and policy.seal_context / verify_context with that backend.
- Router-level PQC signer enrollment.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest

# liboqs-python is an optional dependency. Skip this module cleanly when its
# native provider is not installed instead of failing test collection.
pytest.importorskip("oqs", reason="liboqs-python is required for PQC backend tests")
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from app import crypto_utils, models, security
from app.crypto_utils import Algorithm, generate_keypair
from app.federation import policy
from app.federation.contracts import AgreementClaims, SignedAgreement
from app.pqc_signing_backends import MlDsaSigningBackend


@pytest.fixture()
def db():
    engine = sa.create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()
    engine.dispose()


def _claims_dict(db, *, subject_type="SENDER_ORG", subject_id="default", org="default") -> dict:
    now = datetime.now(timezone.utc)
    return {
        "agreement_id": uuid.uuid4().hex, "org_id": org, "agent_id": "agent-1",
        "beneficiary_id": "ben-1", "subject_type": subject_type, "subject_id": subject_id,
        "purpose": "approved vendor purchase", "max_amount_minor_units": 10000,
        "currency": "INR", "policy_digest": policy.policy_digest(db, org),
        "document_digest": hashlib.sha256(b"document").hexdigest(),
        "issued_at": now, "expires_at": now + timedelta(days=2),
    }


def _seed(db, *, signer_public: str = None, algorithm: str = "ed25519") -> None:
    # ParentAuthority (id=1) satisfies the Agent.parent_pk FK.
    db.add(models.ParentAuthority(
        id=1, parent_id="parent-1", org_id="default", name="Parent",
        parent_type="developer", contact="test@example.com",
        public_key_pem="x" * 120, status="ACTIVE"))
    db.add(models.Agent(
        agent_id="agent-1", org_id="default", name="Agent One", agent_type="payment",
        purpose="test", parent_pk=1, delegation_id="del-1",
        public_key_pem=signer_public or "x" * 120, status="ACTIVE", currency="INR",
        payment_limit_minor_units=999999))
    db.add(models.ReceiverInstitution(
        receiver_id="recv-1", org_id="default", external_id="ext-1",
        name="Test Receiver", rail="bank", public_key_pem="x" * 120,
        status="ACTIVE", identity_assurance="ADMIN_APPROVED"))
    db.add(models.ReceiverBeneficiary(
        beneficiary_id="ben-1", org_id="default", receiver_id="recv-1",
        alias="test", account_fingerprint="a" * 64,
        currency="INR", max_payment_minor_units=999999, status="ACTIVE"))
    db.add(models.FederationSigner(
        org_id="default", subject_type="SENDER_ORG", subject_id="default",
        public_key_pem=signer_public or "x" * 120,
        public_key_algorithm=algorithm, status="ACTIVE"))
    db.flush()


def _sign_agreement(claims_dict: dict, private, algorithm=Algorithm.ED25519) -> tuple[dict, str]:
    claims = AgreementClaims.model_validate(claims_dict)
    payload = claims.model_dump(mode="json")
    sig = crypto_utils.sign_with_private_key(private, crypto_utils.canonical_json(payload),
                                             algorithm=algorithm)
    return payload, sig


class TestSignedAgreementContract:
    def test_accepts_pqc_sized_signature(self):
        payload = {
            "agreement_id": "a" * 12, "org_id": "default", "agent_id": "agent-1",
            "beneficiary_id": "ben-1", "subject_type": "SENDER_ORG", "subject_id": "default",
            "purpose": "p", "max_amount_minor_units": 100, "currency": "INR",
            "policy_digest": "b" * 64, "document_digest": "c" * 64,
            "issued_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(days=1),
        }
        pq_sig = "x" * 4412  # ML-DSA-65 base64 length
        SignedAgreement(claims=AgreementClaims.model_validate(payload), signature_b64=pq_sig)

    def test_rejects_oversized_signature(self):
        payload = {
            "agreement_id": "a" * 12, "org_id": "default", "agent_id": "agent-1",
            "beneficiary_id": "ben-1", "subject_type": "SENDER_ORG", "subject_id": "default",
            "purpose": "p", "max_amount_minor_units": 100, "currency": "INR",
            "policy_digest": "b" * 64, "document_digest": "c" * 64,
            "issued_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(days=1),
        }
        with pytest.raises(ValueError):
            SignedAgreement(claims=AgreementClaims.model_validate(payload), signature_b64="x" * 9000)


class TestVerifyAgreement:
    def test_ed25519_regression(self, db):
        priv, pub = generate_keypair(Algorithm.ED25519)
        _seed(db, signer_public=pub, algorithm="ed25519")
        payload, sig = _sign_agreement(_claims_dict(db), priv)
        ok, reason, fingerprint, algorithm = policy.verify_agreement(
            db, AgreementClaims.model_validate(payload), sig)
        assert ok is True, reason
        assert algorithm == "ed25519"
        assert len(fingerprint) == 64

    def test_ml_dsa_65_signature_verifies(self, db):
        priv, pub = generate_keypair(Algorithm.ML_DSA_65)
        _seed(db, signer_public=pub, algorithm="ml-dsa-65")
        payload, sig = _sign_agreement(_claims_dict(db), priv, algorithm=Algorithm.ML_DSA_65)
        ok, reason, fingerprint, algorithm = policy.verify_agreement(
            db, AgreementClaims.model_validate(payload), sig)
        assert ok is True, reason
        assert algorithm == "ml-dsa-65"
        assert fingerprint.startswith("ml-dsa-65:")

    def test_pqc_signature_rejected_against_ed25519_signer(self, db):
        """An ML-DSA signature must NOT verify when the signer row is tagged ed25519."""
        ed_priv, ed_pub = generate_keypair(Algorithm.ED25519)
        _seed(db, signer_public=ed_pub, algorithm="ed25519")
        pq_priv, _ = generate_keypair(Algorithm.ML_DSA_65)
        payload, sig = _sign_agreement(_claims_dict(db), pq_priv, algorithm=Algorithm.ML_DSA_65)
        ok, reason, _, _ = policy.verify_agreement(
            db, AgreementClaims.model_validate(payload), sig)
        assert ok is False
        assert "signature" in reason.lower()


class TestAgentCardAndContextWithPqcBackend:
    def test_agent_card_round_trip_under_ml_dsa_backend(self, monkeypatch):
        priv, pub = generate_keypair(Algorithm.ML_DSA_65)
        monkeypatch.setattr(security, "_signing_backend",
                            MlDsaSigningBackend(secret_key_b64=priv, public_key_b64=pub))
        fields = {"intent_id": "i-1", "action": "make_payment", "amount_minor_units": 500}
        sig = security.sign_agent_card(fields)
        assert security.verify_agent_card(fields, sig) is True
        # Tamper with the fields → verify fails
        assert security.verify_agent_card({"intent_id": "i-1", "action": "tampered"}, sig) is False

    def test_seal_and_verify_context_under_ml_dsa_backend(self, monkeypatch, db):
        priv, pub = generate_keypair(Algorithm.ML_DSA_65)
        monkeypatch.setattr(security, "_signing_backend",
                            MlDsaSigningBackend(secret_key_b64=priv, public_key_b64=pub))
        agent_pub = generate_keypair(Algorithm.ED25519)[1]

        # Build a minimal intent + agent in memory (no DB write needed for seal_context)
        intent = models.PaymentIntent()
        intent.intent_id = "i-pqc-1"
        intent.transaction_id = "t-pqc-1"
        intent.org_id = "default"
        intent.agent_id = "agent-pqc"
        intent.mandate_id = "m-1"
        intent.beneficiary_id = "ben-pqc"
        intent.merchant = "M"
        intent.amount_minor_units = 500
        intent.currency = "INR"
        intent.action = "make_payment"
        intent.purpose = "p"
        intent.decision = "allow"

        agent = models.Agent()
        agent.agent_id = "agent-pqc"
        agent.public_key_pem = agent_pub

        row = policy.seal_context(db, intent, agent)
        assert policy.verify_context(row, intent) is True

        # Tampered payload → verify fails
        tampered = dict(row.payload, amount_minor_units=1)
        bad_row = models.PaymentContextEnvelope(
            org_id=row.org_id, intent_id=row.intent_id,
            payload=tampered, payload_digest=row.payload_digest,
            signature_b64=row.signature_b64, issuer_key_id=row.issuer_key_id,
        )
        assert policy.verify_context(bad_row, intent) is False


class TestRouterPqcSignerEnrollment:
    """The /control/v1/federation/signers endpoint must accept PQC public keys."""

    def test_enrolls_ml_dsa_signer(self, paari_client, monkeypatch):
        from tests.test_v34_receivers import _create, _approve, _beneficiary
        ctx = paari_client
        headers, recv, _recv_priv = _create(ctx, monkeypatch)
        _approve(ctx, recv)
        _beneficiary(ctx, monkeypatch, headers, recv)
        _, pub = generate_keypair(Algorithm.ML_DSA_65)
        r = ctx.client.post("/control/v1/federation/signers", headers=headers, json={
            "subject_type": "USER", "subject_id": "user-pqc",
            "public_key_pem": pub, "public_key_algorithm": "ml-dsa-65"})
        assert r.status_code == 201, r.text
        assert r.json()["key_fingerprint"].startswith("ml-dsa-65:")
        db = ctx.Session()
        try:
            row = db.query(models.FederationSigner).filter_by(subject_id="user-pqc",
                                                              org_id="default").one()
            assert row.public_key_algorithm == "ml-dsa-65"
        finally:
            db.close()

    def test_rejects_unknown_algorithm(self, paari_client, monkeypatch):
        from tests.test_v34_receivers import _create, _approve, _beneficiary
        ctx = paari_client
        headers, recv, _recv_priv = _create(ctx, monkeypatch)
        _approve(ctx, recv)
        _beneficiary(ctx, monkeypatch, headers, recv)
        _, pub = generate_keypair(Algorithm.ED25519)
        r = ctx.client.post("/control/v1/federation/signers", headers=headers, json={
            "subject_type": "USER", "subject_id": "user-x",
            "public_key_pem": pub, "public_key_algorithm": "unknown-alg"})
        assert r.status_code == 422
