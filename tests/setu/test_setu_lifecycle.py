import hashlib
from datetime import datetime, timedelta, timezone

import respx
from httpx import Response

from app import models


AUTH_URL = "https://uat.setu.co/api/v2/auth/token"
AA_URL = "https://fiu-sandbox.setu.co/v2"
ORG_ID = "default"
CONTROL_SECRET = "setu-lifecycle-control-key"


def _headers() -> dict[str, str]:
    return {"X-Paari-Control-Key": CONTROL_SECRET, "X-Paari-Org": ORG_ID}


def _configure_setu(monkeypatch) -> None:
    monkeypatch.setenv("SETU_AA_ENABLED", "true")
    monkeypatch.setenv("SETU_AA_CLIENT_ID", "setu-client-id")
    monkeypatch.setenv("SETU_AA_CLIENT_SECRET", "setu-client-secret")
    monkeypatch.setenv("SETU_AA_PRODUCT_INSTANCE_ID", "setu-product-instance")
    # Existing lifecycle contract tests create bindings directly to exercise
    # tenant isolation. The new v3.9 API test separately verifies the signed
    # mandate requirement on the supported binding-creation path.
    monkeypatch.setenv("SETU_AA_REQUIRE_SIGNED_MANDATE", "0")


def _control_key(db) -> None:
    if not db.query(models.Organization).filter_by(org_id=ORG_ID).first():
        db.add(models.Organization(org_id=ORG_ID, name="Default organization"))
    db.add(models.OrganizationAdminKey(
        org_id=ORG_ID,
        key_hash=hashlib.sha256(CONTROL_SECRET.encode("utf-8")).hexdigest(),
        key_prefix=CONTROL_SECRET[:12],
        scopes=["control:write"],
        status="ACTIVE",
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        created_by="test",
    ))
    db.commit()


def _active_binding(db, *, consent_id: str, agent_id: str, user_id: str) -> None:
    mandate = models.UserPaymentMandate(
        org_id=ORG_ID,
        user_id=user_id,
        agent_id=agent_id,
        max_per_transaction=1_000,
        max_daily_amount=10_000,
        currency="INR",
        valid_from=datetime.now(timezone.utc) - timedelta(minutes=1),
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        status=models.MandateStatus.ACTIVE,
    )
    db.add(mandate)
    db.flush()
    db.add(models.SetuConsentMandateBinding(
        org_id=ORG_ID,
        setu_consent_id=consent_id,
        mandate_id=mandate.mandate_id,
        subject_user_id=user_id,
        purpose_digest="a" * 64,
        status="ACTIVE",
    ))
    db.commit()


@respx.mock
def test_lifecycle_persists_active_consent_and_bound_session(paari_client, monkeypatch):
    """Fails if the lifecycle trusts provider state without tenant-bound persistence."""
    _configure_setu(monkeypatch)
    db = paari_client.Session()
    try:
        _control_key(db)
    finally:
        db.close()

    respx.post(AUTH_URL).mock(return_value=Response(
        200, json={"success": True, "data": {"token": "setu-token", "expiresIn": 1800}}
    ))
    respx.post(f"{AA_URL}/consents").mock(return_value=Response(200, json={
        "id": "provider-consent-1",
        "status": "PENDING",
        "url": "https://fiu-sandbox.setu.co/consents/webview/provider-consent-1",
    }))
    respx.get(f"{AA_URL}/consents/provider-consent-1").mock(
        return_value=Response(200, json={"id": "provider-consent-1", "status": "ACTIVE"})
    )
    session_route = respx.post(f"{AA_URL}/sessions").mock(
        return_value=Response(200, json={"id": "provider-session-1", "status": "PENDING"})
    )

    create = paari_client.client.post("/integrations/setu-aa/v1/consents", headers=_headers(), json={
        "subject_user_id": "user-1",
        "purpose": "cash-flow context",
        "consent": {"vua": "9999999999@setu", "consentDuration": {"unit": "MONTH", "value": "1"}},
    })

    assert create.status_code == 201, create.text
    consent = create.json()
    assert consent["org_id"] == ORG_ID
    assert consent["subject_user_id"] == "user-1"
    assert consent["provider_consent_id"] == "provider-consent-1"
    assert consent["status"] == "PENDING"
    assert "vua" not in consent

    refreshed = paari_client.client.post(
        f"/integrations/setu-aa/v1/consents/{consent['setu_consent_id']}/refresh", headers=_headers()
    )
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["status"] == "ACTIVE"

    db = paari_client.Session()
    try:
        _active_binding(db, consent_id=consent["setu_consent_id"], agent_id=paari_client.agent_id, user_id="user-1")
    finally:
        db.close()

    session = paari_client.client.post("/integrations/setu-aa/v1/sessions", headers=_headers(), json={
        "setu_consent_id": consent["setu_consent_id"],
        "data_range": {"from": "2026-11-01", "to": "2026-11-21"},
        "data_format": "json",
    })

    assert session.status_code == 201, session.text
    session_payload = session.json()
    assert session_payload["org_id"] == ORG_ID
    assert session_payload["setu_consent_id"] == consent["setu_consent_id"]
    assert session_payload["provider_session_id"] == "provider-session-1"
    assert session_payload["status"] == "PENDING"
    assert session_payload["created_at"]
    assert session_payload["updated_at"]
    assert session_route.called

    db = paari_client.Session()
    try:
        stored_consent = db.query(models.SetuConsent).filter_by(setu_consent_id=consent["setu_consent_id"]).one()
        stored_session = db.query(models.SetuDataSession).filter_by(
            data_session_id=session_payload["data_session_id"]
        ).one()
        assert stored_consent.org_id == ORG_ID
        assert stored_consent.status == "ACTIVE"
        assert stored_session.org_id == ORG_ID
        assert stored_session.setu_consent_id == stored_consent.setu_consent_id
    finally:
        db.close()


def test_session_creation_rejects_binding_for_another_user(paari_client, monkeypatch):
    """Fails if any active binding can authorize a consent owned by another user."""
    _configure_setu(monkeypatch)
    db = paari_client.Session()
    try:
        _control_key(db)
        consent = models.SetuConsent(
            org_id=ORG_ID,
            subject_user_id="user-1",
            provider_consent_id="provider-consent-foreign-binding",
            status="ACTIVE",
            purpose_digest="b" * 64,
        )
        db.add(consent)
        db.flush()
        _active_binding(
            db,
            consent_id=consent.setu_consent_id,
            agent_id=paari_client.agent_id,
            user_id="another-user",
        )
        consent_id = consent.setu_consent_id
    finally:
        db.close()

    response = paari_client.client.post("/integrations/setu-aa/v1/sessions", headers=_headers(), json={
        "setu_consent_id": consent_id,
        "data_range": {"from": "2026-11-01", "to": "2026-11-21"},
        "data_format": "json",
    })

    assert response.status_code == 403
    assert response.json()["detail"] == "An active consent binding for this organization and user is required"
