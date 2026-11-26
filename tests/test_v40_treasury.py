"""Paari v4.0: tenant-scoped atomic treasury exposure reservation tests."""
from datetime import datetime, timezone
import uuid

import pytest

from app import models, security
from app.treasury_service import (
    TreasuryLimitExceeded, TreasuryPolicyMissing,
    budget_summary, period_key, reserve_for_authorization,
    sync_reservation_after_transition,
)


def _intent_and_auth(db, ctx, amount: int, suffix: str):
    intent_id = f"v40-intent-{suffix}"
    intent = models.PaymentIntent(
        intent_id=intent_id, agent_id=ctx.agent_id, org_id="default",
        transaction_id=f"TXN-v40-{suffix}", idempotency_key=f"idem-v40-{suffix}",
        merchant="V40 Supplier", amount_minor_units=amount, currency="INR",
        action="make_payment", decision=models.GovernanceDecision.ALLOW,
        reasons=["v4.0 treasury test"],
    )
    db.add(intent)
    db.flush()
    auth = models.BoundedAuthorization(
        authorization_id=f"v40-auth-{suffix}", intent_id=intent_id,
        agent_id=ctx.agent_id, org_id="default", transaction_id=intent.transaction_id,
        merchant=intent.merchant, amount_minor_units=amount, currency="INR",
        token="test-token", expires_at=datetime.now(timezone.utc), max_usage=1, usage_count=0,
    )
    db.add(auth)
    db.flush()
    return intent, auth


def _policy(db, limit=1000, period="DAILY"):
    row = models.TreasuryBudgetPolicy(
        org_id="default", currency="INR", limit_minor_units=limit,
        period=period, status="ACTIVE",
    )
    db.add(row)
    db.flush()
    return row


def test_atomic_reservation_prevents_overspend_and_paid_commits(paari_client):
    ctx = paari_client
    db = ctx.Session()
    try:
        _policy(db, limit=1000)
        intent1, auth1 = _intent_and_auth(db, ctx, 700, uuid.uuid4().hex[:10])
        reservation = reserve_for_authorization(db, auth1)
        assert reservation.status == "RESERVED"
        db.commit()

        _, auth2 = _intent_and_auth(db, ctx, 400, uuid.uuid4().hex[:10])
        with pytest.raises(TreasuryLimitExceeded):
            reserve_for_authorization(db, auth2)
        db.rollback()

        bucket = db.query(models.TreasuryBudgetBucket).filter_by(org_id="default", currency="INR").one()
        assert bucket.reserved_minor_units == 700
        assert bucket.spent_minor_units == 0

        txn = models.ProviderTransaction(
            authorization_id=auth1.authorization_id, intent_id=intent1.intent_id,
            agent_id=ctx.agent_id, org_id="default", state="CAPTURED",
        )
        db.add(txn)
        db.flush()
        sync_reservation_after_transition(db, txn, "PAID")
        db.commit()

        db.refresh(bucket)
        db.refresh(reservation)
        assert reservation.status == "COMMITTED"
        assert bucket.reserved_minor_units == 0
        assert bucket.spent_minor_units == 700

        _, auth3 = _intent_and_auth(db, ctx, 400, uuid.uuid4().hex[:10])
        with pytest.raises(TreasuryLimitExceeded):
            reserve_for_authorization(db, auth3)
        db.rollback()
    finally:
        db.close()


def test_definitive_terminal_failure_releases_reservation(paari_client):
    ctx = paari_client
    db = ctx.Session()
    try:
        _policy(db, limit=1000)
        intent, auth = _intent_and_auth(db, ctx, 600, uuid.uuid4().hex[:10])
        reservation = reserve_for_authorization(db, auth)
        txn = models.ProviderTransaction(
            authorization_id=auth.authorization_id, intent_id=intent.intent_id,
            agent_id=ctx.agent_id, org_id="default", state="DECLINED",
        )
        db.add(txn)
        db.flush()
        sync_reservation_after_transition(db, txn, "DECLINED")
        db.commit()
        db.refresh(reservation)
        bucket = db.query(models.TreasuryBudgetBucket).filter_by(org_id="default", currency="INR").one()
        assert reservation.status == "RELEASED"
        assert bucket.reserved_minor_units == 0
        assert bucket.spent_minor_units == 0
    finally:
        db.close()


def test_unknown_and_failed_states_keep_exposure_reserved(paari_client):
    ctx = paari_client
    db = ctx.Session()
    try:
        _policy(db, limit=1000)
        intent, auth = _intent_and_auth(db, ctx, 400, uuid.uuid4().hex[:10])
        reservation = reserve_for_authorization(db, auth)
        txn = models.ProviderTransaction(
            authorization_id=auth.authorization_id, intent_id=intent.intent_id,
            agent_id=ctx.agent_id, org_id="default", state="PROVIDER_UNKNOWN",
        )
        db.add(txn)
        db.flush()
        sync_reservation_after_transition(db, txn, "PROVIDER_UNKNOWN")
        sync_reservation_after_transition(db, txn, "FAILED")
        db.commit()
        db.refresh(reservation)
        bucket = db.query(models.TreasuryBudgetBucket).filter_by(org_id="default", currency="INR").one()
        assert reservation.status == "RESERVED"
        assert bucket.reserved_minor_units == 400
    finally:
        db.close()


def test_daily_period_buckets_roll_by_utc_date():
    from datetime import datetime, timezone
    first = datetime(2026, 11, 25, 23, 59, tzinfo=timezone.utc)
    second = datetime(2026, 11, 26, 0, 1, tzinfo=timezone.utc)
    assert period_key("DAILY", first) == "2026-11-25"
    assert period_key("DAILY", second) == "2026-11-26"
    assert period_key("MONTHLY", second) == "2026-11"
    assert period_key("WEEKLY", second).startswith("2026-W")


def test_treasury_policy_api_is_tenant_scoped(paari_client, monkeypatch):
    ctx = paari_client
    monkeypatch.setattr(security, "_ADMIN_API_KEY", "v40-root-testing-only")
    db = ctx.Session()
    try:
        if not db.query(models.Organization).filter_by(org_id="default").first():
            db.add(models.Organization(org_id="default", name="V40 Test Organization"))
            db.commit()
    finally:
        db.close()
    from datetime import timedelta
    issued = ctx.client.post("/control/v1/admin-keys",
        headers={"X-Admin-Api-Key": "v40-root-testing-only"},
        json={"org_id": "default", "scopes": ["control:read", "control:write"],
              "expires_at": (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()})
    assert issued.status_code == 201, issued.text
    headers = {"X-Paari-Control-Key": issued.json()["secret"], "X-Paari-Org": "default"}
    response = ctx.client.put("/control/v1/treasury/budgets/INR", headers=headers,
                              json={"limit_minor_units": 250000, "period": "DAILY", "status": "ACTIVE"})
    assert response.status_code == 200, response.text
    assert response.json()["limit_minor_units"] == 250000
    assert response.json()["available_minor_units"] == 250000
    assert ctx.client.get("/control/v1/treasury/budgets", headers=headers).json()[0]["currency"] == "INR"
    db = ctx.Session()
    try:
        _, auth = _intent_and_auth(db, ctx, 100, uuid.uuid4().hex[:10])
        reserve_for_authorization(db, auth)
        db.commit()
    finally:
        db.close()
    period_change = ctx.client.put("/control/v1/treasury/budgets/INR", headers=headers,
        json={"limit_minor_units": 250000, "period": "MONTHLY", "status": "ACTIVE"})
    assert period_change.status_code == 409, period_change.text
    changed = dict(headers, **{"X-Paari-Org": "another-tenant"})
    assert ctx.client.get("/control/v1/treasury/budgets", headers=changed).status_code == 401


def test_budget_required_mode_fails_closed_when_policy_missing(paari_client, monkeypatch):
    from app.treasury_service import reserve_for_authorization
    ctx = paari_client
    db = ctx.Session()
    try:
        _, auth = _intent_and_auth(db, ctx, 100, uuid.uuid4().hex[:10])
        monkeypatch.setenv("PAARI_REQUIRE_TREASURY_BUDGET", "1")
        with pytest.raises(TreasuryPolicyMissing):
            reserve_for_authorization(db, auth)
        db.rollback()
    finally:
        db.close()
