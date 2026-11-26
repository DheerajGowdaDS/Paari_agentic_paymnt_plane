from datetime import datetime, timedelta, timezone

import pytest

from app import models, security


def _root_header(monkeypatch, key="test-root-control-key"):
    monkeypatch.setattr(security, "_ADMIN_API_KEY", key)
    return {"X-Admin-Api-Key": key}


def _ensure_org(ctx, org_id="default"):
    db = ctx.Session()
    try:
        if not db.query(models.Organization).filter_by(org_id=org_id).first():
            db.add(models.Organization(org_id=org_id, name="Default Test Organization"))
            db.commit()
    finally:
        db.close()


def _issue_org_key(ctx, monkeypatch, org_id="default"):
    _ensure_org(ctx, org_id)
    response = ctx.client.post("/control/v1/admin-keys", headers=_root_header(monkeypatch), json={
        "org_id": org_id,
        "scopes": ["control:read", "control:write"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    })
    assert response.status_code == 201, response.text
    return response.json()["secret"]


def test_org_scoped_control_key_and_principal_lifecycle(paari_client, monkeypatch):
    ctx = paari_client
    key = _issue_org_key(ctx, monkeypatch)
    headers = {"X-Paari-Control-Key": key, "X-Paari-Org": "default"}

    created = ctx.client.post("/control/v1/principals", headers=headers, json={
        "external_subject_id": "customer-42", "identity_provider": "oidc:bank-example",
        "display_name": "Test customer",
    })
    assert created.status_code == 201, created.text
    principal = created.json()
    assert principal["status"] == "PENDING"
    assert principal["assurance_level"] == "low"

    # Assurance is not user input: strict schema rejects a client-asserted high level.
    forged_assurance = ctx.client.post("/control/v1/principals", headers=headers, json={
        "external_subject_id": "customer-forged", "identity_provider": "oidc:bank-example",
        "display_name": "Forged assurance", "assurance_level": "high",
    })
    assert forged_assurance.status_code == 422

    activated = ctx.client.post(f"/control/v1/principals/{principal['principal_id']}/attest",
                                headers=headers, json={"attestation_reference": "kyc-case-123"})
    assert activated.status_code == 200, activated.text
    assert activated.json()["status"] == "ACTIVE"
    assert activated.json()["assurance_level"] == "low"

    # A key bound to tenant A cannot be reused by merely changing the tenant header.
    cross_tenant = ctx.client.get("/control/v1/resources", headers={
        "X-Paari-Control-Key": key, "X-Paari-Org": "other-org"})
    assert cross_tenant.status_code == 401


def test_root_can_suspend_tenant_and_revoke_org_keys(paari_client, monkeypatch):
    ctx = paari_client
    key = _issue_org_key(ctx, monkeypatch)
    headers = {"X-Paari-Control-Key": key, "X-Paari-Org": "default"}
    before = ctx.client.get("/control/v1/resources", headers=headers)
    assert before.status_code == 200, before.text

    suspended = ctx.client.post("/control/v1/organizations/default/status",
        headers=_root_header(monkeypatch), json={"status": "SUSPENDED", "reason": "risk investigation"})
    assert suspended.status_code == 200, suspended.text
    denied = ctx.client.get("/control/v1/resources", headers=headers)
    assert denied.status_code == 401, denied.text

    reactivated = ctx.client.post("/control/v1/organizations/default/status",
        headers=_root_header(monkeypatch), json={"status": "ACTIVE", "reason": "investigation cleared"})
    assert reactivated.status_code == 200, reactivated.text
    # Reactivation does not resurrect previously revoked organization credentials.
    still_denied = ctx.client.get("/control/v1/resources", headers=headers)
    assert still_denied.status_code == 401, still_denied.text


def test_resource_secret_rejection_and_access_grant(paari_client, monkeypatch):
    ctx = paari_client
    key = _issue_org_key(ctx, monkeypatch)
    headers = {"X-Paari-Control-Key": key, "X-Paari-Org": "default"}
    principal = ctx.client.post("/control/v1/principals", headers=headers, json={
        "external_subject_id": "customer-43", "identity_provider": "oidc:bank-example",
        "display_name": "Test customer",
    }).json()
    ctx.client.post(f"/control/v1/principals/{principal['principal_id']}/attest", headers=headers,
                    json={"attestation_reference": "kyc-case-124"})

    bad = ctx.client.post("/control/v1/resources", headers=headers, json={
        "resource_type": "bank_account", "provider_id": "bank-example",
        "external_resource_ref": "customer-secret123", "owner_principal_id": principal["principal_id"],
        "currency": "INR", "classification": "restricted", "metadata": {},
    })
    assert bad.status_code == 422

    good = ctx.client.post("/control/v1/resources", headers=headers, json={
        "resource_type": "bank_account", "provider_id": "bank-example",
        "external_resource_ref": "ob_account_9fe2", "owner_principal_id": principal["principal_id"],
        "currency": "INR", "classification": "restricted", "metadata": {"scheme": "open-banking"},
    })
    assert good.status_code == 201, good.text
    resource = good.json()

    now = datetime.now(timezone.utc)
    grant = ctx.client.post(f"/control/v1/resources/{resource['resource_id']}/grants", headers=headers, json={
        "subject_type": "principal", "subject_id": principal["principal_id"],
        "actions": ["payment:execute", "resource:read"], "consent_reference": "consent-43",
        "valid_from": (now - timedelta(seconds=1)).isoformat(),
        "valid_until": (now + timedelta(days=10)).isoformat(),
    })
    assert grant.status_code == 201, grant.text
    assert "payment:execute" in grant.json()["actions"]

    revoked = ctx.client.post(f"/control/v1/grants/{grant.json()['grant_id']}/revoke", headers=headers)
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "REVOKED"


def test_versioned_policy_activation_is_auditable_and_ordered(paari_client, monkeypatch):
    ctx = paari_client
    key = _issue_org_key(ctx, monkeypatch)
    headers = {"X-Paari-Control-Key": key, "X-Paari-Org": "default"}
    policy1 = ctx.client.post("/control/v1/policies", headers=headers, json={
        "policy_name": "payment_execution", "version": "1.0.0", "activate": True,
        "min_evidence_quality_bps": 8500, "observe_threshold_bps": 2500,
        "escalate_threshold_bps": 6000, "deny_threshold_bps": 9000,
        "require_signed_mandate": True,
    })
    assert policy1.status_code == 201, policy1.text
    assert policy1.json()["status"] == "ACTIVE"

    policy2 = ctx.client.post("/control/v1/policies", headers=headers, json={
        "policy_name": "payment_execution", "version": "1.1.0", "activate": True,
        "min_evidence_quality_bps": 9000, "observe_threshold_bps": 2000,
        "escalate_threshold_bps": 5000, "deny_threshold_bps": 8500,
        "require_signed_mandate": True,
    })
    assert policy2.status_code == 201, policy2.text
    assert policy2.json()["status"] == "ACTIVE"

    active = ctx.client.get("/control/v1/policies/active", headers=headers)
    assert active.status_code == 200, active.text
    assert len(active.json()) == 1
    assert active.json()[0]["version"] == "1.1.0"


def test_policy_thresholds_must_be_ordered(paari_client, monkeypatch):
    ctx = paari_client
    key = _issue_org_key(ctx, monkeypatch)
    headers = {"X-Paari-Control-Key": key, "X-Paari-Org": "default"}
    response = ctx.client.post("/control/v1/policies", headers=headers, json={
        "policy_name": "payment_execution", "version": "bad", "activate": True,
        "min_evidence_quality_bps": 8500, "observe_threshold_bps": 6000,
        "escalate_threshold_bps": 5000, "deny_threshold_bps": 9000,
        "require_signed_mandate": True,
    })
    assert response.status_code == 422


def test_strict_control_plane_is_in_payment_authorization_path(paari_client, monkeypatch):
    """An ALLOW requires both parent/user authority and agent/principal resource grants."""
    from tests.test_v2_governance import _signed_mandate_post, _user_keypair
    from tests.conftest import make_intent

    ctx = paari_client
    monkeypatch.setenv("PAARI_CONTROL_PLANE_ENFORCEMENT", "1")
    monkeypatch.setenv("PAARI_MODE", "autonomous")
    monkeypatch.setenv("PAARI_REQUIRE_SIGNED_MANDATE", "1")
    key = _issue_org_key(ctx, monkeypatch)
    headers = {"X-Paari-Control-Key": key, "X-Paari-Org": "default"}
    _ensure_org(ctx)

    # The parent must have an independently approved trust tier before this risk
    # baseline considers the evidence strong enough for automatic execution.
    db = ctx.Session()
    try:
        parent = db.query(models.ParentAuthority).filter_by(parent_id=ctx.parent_id).one()
        parent.trust_tier = "admin_approved"
        db.commit()
    finally:
        db.close()

    principal_resp = ctx.client.post("/control/v1/principals", headers=headers, json={
        "external_subject_id": "user-42", "identity_provider": "oidc:bank-example",
        "display_name": "Test principal",
    })
    assert principal_resp.status_code == 201, principal_resp.text
    principal_id = principal_resp.json()["principal_id"]
    activated = ctx.client.post(f"/control/v1/principals/{principal_id}/attest", headers=headers,
                                json={"attestation_reference": "kyc-verified-42"})
    assert activated.status_code == 200, activated.text

    # A real trusted identity-provider adapter must set assurance. The test seeds
    # the trusted-provider result directly because no identity provider is bundled.
    db = ctx.Session()
    try:
        row = db.query(models.PrincipalIdentity).filter_by(principal_id=principal_id).one()
        row.assurance_level = "high"
        db.commit()
    finally:
        db.close()

    resource_resp = ctx.client.post("/control/v1/resources", headers=headers, json={
        "resource_type": "bank_account", "provider_id": "razorpay",
        "external_resource_ref": "source_resource_42", "owner_principal_id": principal_id,
        "currency": "INR", "classification": "restricted", "metadata": {},
    })
    assert resource_resp.status_code == 201, resource_resp.text
    resource_id = resource_resp.json()["resource_id"]

    policy = ctx.client.post("/control/v1/policies", headers=headers, json={
        "policy_name": "payment_execution", "version": "e2e-1", "activate": True,
        "min_evidence_quality_bps": 8500, "observe_threshold_bps": 2500,
        "escalate_threshold_bps": 6000, "deny_threshold_bps": 9000,
        "require_signed_mandate": True,
    })
    assert policy.status_code == 201, policy.text

    now = datetime.now(timezone.utc)
    for subject_type, subject_id in (("principal", principal_id), ("agent", ctx.agent_id)):
        grant = ctx.client.post(f"/control/v1/resources/{resource_id}/grants", headers=headers, json={
            "subject_type": subject_type, "subject_id": subject_id,
            "actions": ["payment:execute"], "consent_reference": f"consent-{subject_type}-42",
            "valid_from": (now - timedelta(seconds=1)).isoformat(),
            "valid_until": (now + timedelta(days=10)).isoformat(),
        })
        assert grant.status_code == 201, grant.text

    user_private, user_public = _user_keypair()
    mandate = _signed_mandate_post(ctx, user_private, user_public, user_id="user-42")
    bind = ctx.client.post(f"/v1/mandates/{mandate['mandate_id']}/provider-binding", headers=_root_header(monkeypatch), json={
        "provider": "razorpay", "source_resource_id": resource_id,
        "provider_mandate_ref": "provider_mandate_ref_42", "provider_instrument_ref": "instrument_ref_42",
        "currency": "INR", "max_amount_minor_units": 200000,
        "expires_at": (now + timedelta(days=10)).isoformat(),
    })
    assert bind.status_code == 200, bind.text

    result = make_intent(ctx, amount=10000, suffix="strict-control-plane")
    assert result["decision"] == "allow", result

    # A strict transaction must not reach a provider merely because the runtime
    # minted a bounded authorization. In explicit envelope-required mode, consume
    # is blocked until a signed SAFR envelope has been processed and bound to this
    # exact persisted intent, decision and authorization.
    monkeypatch.setenv("PAARI_REQUIRE_SAFR_ENVELOPE", "1")
    from sdk.paari_agent.crypto import build_request_proof
    authorization_id = result["authorization"]["authorization_id"]
    consume_path = f"/v1/payments/authorizations/{authorization_id}/consume"
    proof = build_request_proof(ctx.agent_private, agent_id=ctx.agent_id,
                                access_token=ctx.session_token, method="POST", path=consume_path)
    blocked = ctx.client.post(consume_path, json={"session_token": ctx.session_token}, headers={
        "Authorization": f"Bearer {ctx.session_token}", "X-Paari-Proof": proof,
    })
    assert blocked.status_code == 403, blocked.text
    assert "processed SAFR envelope" in blocked.text

    db = ctx.Session()
    try:
        decision = db.query(models.ControlPlaneDecision).filter_by(intent_id=result["intent_id"]).one()
        assert decision.disposition == "AUTO_EXECUTE"
        assert decision.resource_id == resource_id
        assert decision.principal_id == principal_id
        from app.audit import verify_chain
        assert verify_chain(db, result["transaction_id"])
    finally:
        db.close()

    decision_list = ctx.client.get("/control/v1/decisions?disposition=AUTO_EXECUTE", headers=headers)
    assert decision_list.status_code == 200, decision_list.text
    assert any(item["intent_id"] == result["intent_id"] for item in decision_list.json())
    matching = next(item for item in decision_list.json() if item["intent_id"] == result["intent_id"])
    decision_detail = ctx.client.get(f"/control/v1/decisions/{matching['decision_id']}", headers=headers)
    assert decision_detail.status_code == 200, decision_detail.text
    assert decision_detail.json()["policy_version"] == "e2e-1"
    cross_tenant = ctx.client.get(f"/control/v1/decisions/{matching['decision_id']}", headers={
        "X-Paari-Control-Key": headers["X-Paari-Control-Key"], "X-Paari-Org": "other-org"})
    assert cross_tenant.status_code == 401

    # Tenant suspension is independently enforced by the payment decision path.
    db = ctx.Session()
    try:
        org = db.query(models.Organization).filter_by(org_id="default").one()
        org.status = "SUSPENDED"
        db.commit()
    finally:
        db.close()
    suspended_payment = make_intent(ctx, amount=10000, suffix="suspended-tenant")
    assert suspended_payment["decision"] == "deny", suspended_payment
    db = ctx.Session()
    try:
        suspended_decision = db.query(models.ControlPlaneDecision).filter_by(
            intent_id=suspended_payment["intent_id"]).one()
        assert suspended_decision.disposition == "DENY"
        assert "ORGANIZATION_OR_PARENT_NOT_TRUSTED" in suspended_decision.reason_codes
    finally:
        db.close()
