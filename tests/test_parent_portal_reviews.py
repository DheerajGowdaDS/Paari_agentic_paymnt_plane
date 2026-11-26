"""Parent Organization Portal review queue and organization profile regressions."""
from __future__ import annotations

import uuid

from app import models as core
from app.audit import verify_chain
from app.security import encode_request_proof
from app.v36 import models as v36_models
from app.v36 import security as v36_security
from tests.conftest import make_intent

PARENT_PASSWORD = "Demo-Parent-Password-2026!"


def parent_portal_session(ctx, monkeypatch):
    monkeypatch.setenv("PAARI_V36_KEY_ENCRYPTION_SECRET", "portal-review-key-encryption-secret-2026")
    monkeypatch.setenv("PAARI_V36_PII_HMAC_SECRET", "portal-review-pii-hmac-secret-2026")
    monkeypatch.setenv("PAARI_V36_AUTH_SECRET", "portal-review-authentication-secret-2026")
    with ctx.Session() as db:
        parent = db.query(core.ParentAuthority).filter_by(parent_id=ctx.parent_id).one()
        encrypted_private = v36_security.signing_fernet().encrypt(ctx.parent_private.encode()).decode()
        db.add(v36_models.ParentAccount(
            parent_pk=parent.id,
            kind="organization",
            identifier_last4="1Z5X",
            identifier_hmac=uuid.uuid4().hex + uuid.uuid4().hex,
            representative_name="Demo Parent Reviewer",
            representative_email="reviewer@paari-demo.invalid",
            representative_phone="+919800000001",
            address="Demo registered office, Bengaluru",
            password_hash=v36_security.hash_password(PARENT_PASSWORD),
            encrypted_signing_key=encrypted_private,
        ))
        tenant = db.query(core.Organization).filter_by(org_id=parent.org_id).first()
        if not tenant:
            db.add(core.Organization(org_id=parent.org_id, name="Paari Demo Organization", status="ACTIVE"))
        db.commit()
    login = ctx.client.post("/v36/parents/login", json={
        "parent_id": ctx.parent_id,
        "password": PARENT_PASSWORD,
    })
    assert login.status_code == 200, login.text
    return login.json()["access_token"]


def test_parent_overview_returns_masked_paari_organization_profile(paari_client, monkeypatch):
    ctx = paari_client
    token = parent_portal_session(ctx, monkeypatch)
    response = ctx.client.get("/portal/v1/parent/overview", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["parent"]["parent_type"] == "organization"
    assert body["parent"]["account"]["registration_id_type"] == "GSTIN"
    assert body["parent"]["account"]["registration_id_last4"] == "1Z5X"
    assert body["parent"]["tenant"]["tenant_id"] == "default"
    assert body["active_agent_count"] == 1
    assert "encrypted_signing_key" not in str(body)
    assert "password_hash" not in str(body)


def test_safr_escalation_is_visible_in_parent_queue_and_rejection_is_audited(paari_client, monkeypatch):
    ctx = paari_client
    token = parent_portal_session(ctx, monkeypatch)
    intent_body = make_intent(ctx, amount=450000, suffix="parent-safr-review")
    assert intent_body["decision"] == "review"
    with ctx.Session() as db:
        intent = db.query(core.PaymentIntent).filter_by(intent_id=intent_body["intent_id"]).one()
        db.add(core.ControlPlaneDecision(
            intent_id=intent.intent_id,
            org_id=intent.org_id,
            principal_id=None,
            resource_id=None,
            policy_name="payment_execution",
            policy_version="test-v1",
            disposition="ESCALATE",
            reason_codes=["RISK_ESCALATION_THRESHOLD"],
            risk_score_bps=8200,
            evidence_quality_bps=9400,
            transaction_digest="a" * 64,
        ))
        db.commit()

    headers = {"Authorization": f"Bearer {token}"}
    queue = ctx.client.get("/portal/v1/parent/reviews", headers=headers)
    assert queue.status_code == 200, queue.text
    item = next(x for x in queue.json()["items"] if x["intent_id"] == intent_body["intent_id"])
    assert item["review_type"] == "SAFR_ESCALATION"
    assert item["risk_score_bps"] == 8200

    rejected = ctx.client.post(
        f"/portal/v1/parent/reviews/{intent_body['intent_id']}/decision",
        headers=headers,
        json={"approve": False, "reviewer_password": PARENT_PASSWORD,
              "reviewer_note": "Supplier bank details could not be validated."},
    )
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["decision"] == "deny"
    assert rejected.json()["authorization_issued"] is False
    with ctx.Session() as db:
        stored = db.query(core.PaymentIntent).filter_by(intent_id=intent_body["intent_id"]).one()
        assert stored.decision == core.GovernanceDecision.DENY
        assert db.query(core.BoundedAuthorization).filter_by(intent_id=stored.intent_id).count() == 0
        assert db.query(core.AuditEvent).filter_by(
            transaction_id=stored.transaction_id, kind="parent_portal_review_note").count() == 1
        assert verify_chain(db, stored.transaction_id)


def test_parent_approval_mints_bounded_authorization_without_exposing_token_to_parent(paari_client, monkeypatch):
    ctx = paari_client
    token = parent_portal_session(ctx, monkeypatch)
    intent_body = make_intent(ctx, amount=450000, suffix="parent-stepup-approve")
    assert intent_body["decision"] == "review"
    headers = {"Authorization": f"Bearer {token}"}
    response = ctx.client.post(
        f"/portal/v1/parent/reviews/{intent_body['intent_id']}/decision",
        headers=headers,
        json={"approve": True, "reviewer_password": PARENT_PASSWORD,
              "reviewer_note": "Invoice and supplier were verified by treasury."},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "allow"
    assert body["authorization_issued"] is True
    assert body["agent_authorization_endpoint"].endswith(intent_body["intent_id"] + "/authorization")
    assert "authorization" not in body
    assert "token" not in str(body).lower()
    with ctx.Session() as db:
        auth = db.query(core.BoundedAuthorization).filter_by(intent_id=intent_body["intent_id"]).one()
        assert auth.max_usage == 1
        assert auth.usage_count == 0

    proof = encode_request_proof(
        ctx.agent_private,
        method="GET",
        path=f"/payments/intents/{intent_body['intent_id']}/authorization",
        access_token=ctx.session_token,
        agent_id=ctx.agent_id,
        jti=str(uuid.uuid4()),
    )
    agent_response = ctx.client.get(
        f"/payments/intents/{intent_body['intent_id']}/authorization",
        headers={"Authorization": f"Bearer {ctx.session_token}", "X-Paari-Proof": proof},
    )
    assert agent_response.status_code == 200, agent_response.text
    assert agent_response.json()["token"]


def test_parent_review_requires_password_reauthentication(paari_client, monkeypatch):
    ctx = paari_client
    token = parent_portal_session(ctx, monkeypatch)
    intent_body = make_intent(ctx, amount=450000, suffix="parent-review-bad-password")
    response = ctx.client.post(
        f"/portal/v1/parent/reviews/{intent_body['intent_id']}/decision",
        headers={"Authorization": f"Bearer {token}"},
        json={"approve": True, "reviewer_password": "incorrect-parent-password",
              "reviewer_note": "Attempting to approve this transaction."},
    )
    assert response.status_code == 401, response.text
    with ctx.Session() as db:
        intent = db.query(core.PaymentIntent).filter_by(intent_id=intent_body["intent_id"]).one()
        assert intent.decision == core.GovernanceDecision.REVIEW
        assert db.query(core.BoundedAuthorization).filter_by(intent_id=intent.intent_id).count() == 0
