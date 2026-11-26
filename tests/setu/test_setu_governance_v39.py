import hashlib
from datetime import datetime, timedelta, timezone

from app import crypto_utils, models
from app.mandate_signing import sign_mandate

AUTH_URL = "https://uat.setu.co/api/v2/auth/token"
AA_URL = "https://fiu-sandbox.setu.co/v2"
ORG_ID = "default"
CONTROL_SECRET = "setu-v39-control-secret"


def _headers():
    return {"X-Paari-Control-Key": CONTROL_SECRET, "X-Paari-Org": ORG_ID}


def _setup(paari_client, monkeypatch):
    monkeypatch.setenv("SETU_AA_ENABLED", "true")
    monkeypatch.setenv("SETU_AA_CLIENT_ID", "setu-client-id")
    monkeypatch.setenv("SETU_AA_CLIENT_SECRET", "setu-client-secret")
    monkeypatch.setenv("SETU_AA_PRODUCT_INSTANCE_ID", "setu-product-instance")
    monkeypatch.setenv("SETU_AA_REQUIRE_SIGNED_MANDATE", "1")
    monkeypatch.setenv("PAARI_FINANCIAL_CONTEXT_ENCRYPTION_SECRET", "v39-test-context-encryption-secret-0123456789")
    db = paari_client.Session()
    try:
        if not db.query(models.Organization).filter_by(org_id=ORG_ID).first():
            db.add(models.Organization(org_id=ORG_ID, name="Default organization"))
        db.add(models.OrganizationAdminKey(
            org_id=ORG_ID,
            key_hash=hashlib.sha256(CONTROL_SECRET.encode()).hexdigest(),
            key_prefix=CONTROL_SECRET[:12], scopes=["control:write", "control:read"],
            status="ACTIVE", expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            created_by="v3.9 test",
        ))
        private, _ = crypto_utils.generate_agent_keypair()
        mandate = models.UserPaymentMandate(
            mandate_id="mandate-setu-v39-1", org_id=ORG_ID, user_id="user-setu-v39",
            agent_id=paari_client.agent_id, max_per_transaction=100_000,
            max_daily_amount=500_000, currency="INR",
            valid_from=datetime.now(timezone.utc) - timedelta(minutes=1),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            status=models.MandateStatus.ACTIVE,
        )
        db.add(mandate)
        db.flush()
        sign_mandate(mandate, private, signing_key_id="setu-v39-user-key")
        consent = models.SetuConsent(
            org_id=ORG_ID, subject_user_id=mandate.user_id,
            provider_consent_id="provider-consent-v39-1", status="ACTIVE",
            purpose_digest="a" * 64,
        )
        db.add(consent)
        db.commit()
        return mandate.mandate_id, consent.setu_consent_id, consent.provider_consent_id
    finally:
        db.close()


def test_v39_binding_completed_session_encrypted_snapshot_and_context_policy(paari_client, monkeypatch):
    mandate_id, consent_id, provider_consent_id = _setup(paari_client, monkeypatch)

    binding = paari_client.client.post(
        f"/integrations/setu-aa/v1/consents/{consent_id}/mandate-binding",
        headers=_headers(), json={"mandate_id": mandate_id},
    )
    assert binding.status_code == 201, binding.text
    binding_payload = binding.json()
    assert binding_payload["status"] == "ACTIVE"
    assert binding_payload["mandate_id"] == mandate_id

    # Keep the synthetic balance observation fresh relative to the runtime
    # policy clock; fixed historical fixtures become stale as the calendar moves.
    observed_at = datetime.now(timezone.utc) - timedelta(hours=1)
    range_from = (datetime.now(timezone.utc) - timedelta(days=21)).date().isoformat()
    range_to = (datetime.now(timezone.utc) - timedelta(days=1)).date().isoformat()
    data_response = {
        "id": "provider-session-v39-1",
        "consentId": provider_consent_id,
        "status": "COMPLETED",
        "data": {"FinancialInformation": [{
            "fipId": "FIP-DEMO",
            "data": [{
                "maskedAccNumber": "XXXXXX1234",
                "type": "SAVINGS",
                "Summary": {"currency": "INR", "currentBalance": "45000.00",
                            "balanceDateTime": observed_at.isoformat()},
                "Transactions": {"startDate": range_from, "endDate": range_to,
                                 "Transaction": [{"txnId": "private-txn-1"}]},
            }],
        }]},
    }
    class FakeSetuClient:
        def create_data_session(self, consent_id, data_range, data_format):
            assert consent_id == provider_consent_id
            assert data_range["from"] == range_from
            assert data_format == "json"
            return {"id": "provider-session-v39-1", "status": "PENDING"}

        def get_data_session(self, session_id):
            assert session_id == "provider-session-v39-1"
            return data_response

    from app.integrations.setu import router as setu_router
    monkeypatch.setattr(setu_router, "_client", lambda: FakeSetuClient())

    created = paari_client.client.post("/integrations/setu-aa/v1/sessions", headers=_headers(), json={
        "setu_consent_id": consent_id,
        "data_range": {"from": range_from, "to": range_to},
        "data_format": "json",
    })
    assert created.status_code == 201, created.text
    session_id = created.json()["data_session_id"]

    refreshed = paari_client.client.get(
        f"/integrations/setu-aa/v1/sessions/{session_id}", headers=_headers()
    )
    assert refreshed.status_code == 200, refreshed.text
    result = refreshed.json()
    assert result["status"] == "COMPLETED"
    snapshot_view = result["financial_context"]
    assert snapshot_view["status"] == "AVAILABLE"
    assert snapshot_view["account_count"] == 1
    assert snapshot_view["normalized_context"]["accounts"][0]["currency"] == "INR"
    assert snapshot_view["raw_payload_encrypted"] is True

    context_response = paari_client.client.get(
        f"/integrations/setu-aa/v1/mandates/{mandate_id}/financial-context", headers=_headers()
    )
    assert context_response.status_code == 200, context_response.text
    assert context_response.json()["snapshot_id"] == snapshot_view["snapshot_id"]

    db = paari_client.Session()
    try:
        stored = db.query(models.FinancialContextSnapshot).filter_by(
            snapshot_id=snapshot_view["snapshot_id"]
        ).one()
        assert stored.raw_payload_ciphertext.startswith("aesgcm:v1:")
        assert "private-txn-1" not in stored.raw_payload_ciphertext
        mandate = db.query(models.UserPaymentMandate).filter_by(mandate_id=mandate_id).one()
        from app.financial_context.policy import evaluate_financial_context
        decision = evaluate_financial_context(db, org_id=ORG_ID, mandate=mandate)
        assert decision.status == "FRESH"
        assert decision.fresh is True
    finally:
        db.close()

    revoked = paari_client.client.post(
        f"/integrations/setu-aa/v1/bindings/{binding_payload['binding_id']}/revoke",
        headers=_headers(),
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "REVOKED"
    unavailable = paari_client.client.get(
        f"/integrations/setu-aa/v1/mandates/{mandate_id}/financial-context", headers=_headers()
    )
    assert unavailable.status_code == 404


def test_v39_binding_rejects_unsigned_mandate(paari_client, monkeypatch):
    monkeypatch.setenv("SETU_AA_REQUIRE_SIGNED_MANDATE", "1")
    db = paari_client.Session()
    try:
        if not db.query(models.Organization).filter_by(org_id=ORG_ID).first():
            db.add(models.Organization(org_id=ORG_ID, name="Default organization"))
        db.add(models.OrganizationAdminKey(
            org_id=ORG_ID, key_hash=hashlib.sha256(CONTROL_SECRET.encode()).hexdigest(),
            key_prefix=CONTROL_SECRET[:12], scopes=["control:write"], status="ACTIVE",
            expires_at=datetime.now(timezone.utc) + timedelta(days=1), created_by="test",
        ))
        mandate = models.UserPaymentMandate(
            mandate_id="mandate-setu-unsigned", org_id=ORG_ID, user_id="unsigned-user",
            agent_id=paari_client.agent_id, max_per_transaction=1000, max_daily_amount=10000,
            currency="INR", valid_from=datetime.now(timezone.utc) - timedelta(minutes=1),
            expires_at=datetime.now(timezone.utc) + timedelta(days=1), status=models.MandateStatus.ACTIVE,
        )
        consent = models.SetuConsent(
            org_id=ORG_ID, subject_user_id="unsigned-user", provider_consent_id="provider-unsigned",
            status="ACTIVE", purpose_digest="b" * 64,
        )
        db.add_all([mandate, consent])
        db.commit()
        consent_id = consent.setu_consent_id
    finally:
        db.close()
    response = paari_client.client.post(
        f"/integrations/setu-aa/v1/consents/{consent_id}/mandate-binding",
        headers=_headers(), json={"mandate_id": "mandate-setu-unsigned"},
    )
    assert response.status_code == 403
    assert "cryptographically signed" in response.json()["detail"]


def test_v39_fresh_context_gate_is_explicit_and_fails_closed_when_required(paari_client, monkeypatch):
    from app.financial_context.policy import evaluate_financial_context
    from fastapi import HTTPException
    from app.financial_context.policy import require_execution_financial_context
    from app import models

    monkeypatch.setenv("PAARI_REQUIRE_FRESH_FINANCIAL_CONTEXT", "1")
    db = paari_client.Session()
    try:
        missing = evaluate_financial_context(db, org_id=ORG_ID, mandate=None)
        assert missing.required is True
        assert missing.fresh is False
        assert missing.policy_result.passed is False
        intent = models.PaymentIntent(
            org_id=ORG_ID, agent_id=paari_client.agent_id, transaction_id="txn-context-required",
            idempotency_key="idem-context-required", merchant="Example Supplier",
            amount_minor_units=5000, currency="INR", action="payment.create", purpose="supplier invoice",
            decision=models.GovernanceDecision.ALLOW, reasons=[], reason_codes=[], reason_evidence={},
            mandate_id=None,
        )
        db.add(intent)
        db.commit()
        try:
            require_execution_financial_context(db, intent=intent)
            assert False, "execution must fail closed when fresh context is required"
        except HTTPException as exc:
            assert exc.status_code == 403
    finally:
        db.close()


def test_v39_local_revocation_blocks_context_when_setu_provider_is_unavailable(paari_client, monkeypatch):
    mandate_id, consent_id, _ = _setup(paari_client, monkeypatch)
    binding = paari_client.client.post(
        f"/integrations/setu-aa/v1/consents/{consent_id}/mandate-binding",
        headers=_headers(), json={"mandate_id": mandate_id},
    )
    assert binding.status_code == 201, binding.text

    class UnavailableSetuClient:
        def revoke_consent(self, provider_consent_id):
            from app.integrations.setu.client import SetuAAUpstreamError
            raise SetuAAUpstreamError("simulated provider outage")

    from app.integrations.setu import router as setu_router
    monkeypatch.setattr(setu_router, "_client", lambda: UnavailableSetuClient())
    revoked = paari_client.client.post(
        f"/integrations/setu-aa/v1/consents/{consent_id}/revoke", headers=_headers()
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "REVOKED"
    assert revoked.json()["provider_revocation_pending"] is True

    db = paari_client.Session()
    try:
        stored = db.query(models.SetuConsentMandateBinding).filter_by(
            binding_id=binding.json()["binding_id"]
        ).one()
        assert stored.status == "REVOKED"
    finally:
        db.close()
