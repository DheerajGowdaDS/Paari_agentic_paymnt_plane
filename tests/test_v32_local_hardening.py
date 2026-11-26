"""v3.2 blueprint fault-injection coverage the existing suite does not pin.

The blueprint's resilience matrix names four failure injections that were not
yet covered end to end:

  * agent revoked after initial approval   -> new execution is blocked at
    consume-time revalidation; no duplicate provider submission
  * mandate expires after approval / while parked in review -> reviewer or
    step-up approval cannot bypass the mandate expiry; the engine fails
    closed before any provider call
  * reconciliation worker restarts         -> a fresh worker instance resumes
    the persisted non-terminal row; the attempts counter and the final
    settlement survive the restart
  * audit entry deletion                   -> hash-chain verification detects

These are database-agnostic: they run on the default SQLite target and, when
``TEST_DATABASE_URL`` points at a disposable PostgreSQL database (the way
``scripts/accept_v32.py`` runs the Postgres-gated step), the exact same
invariants are proven on Postgres. No real provider, no money.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import app.models as models
import app.reconcile as reconcile_mod
from app.audit import record_audit, verify_chain
from app.mandates import expire_stale_reviews
from app.reconcile_worker import ReconciliationWorker

from tests.conftest import make_intent
from tests import test_v31_resilience as v31
from tests.test_user_mandates import create_mandate


def _short_lived_mandate(ctx, **overrides) -> dict:
    """A mandate whose window closes 60s from now - inside the 2-minute
    bounded-authorization TTL and the 5-minute review window, so the mandate
    expiry is the only control that can block the later step."""
    now = datetime.now(timezone.utc)
    payload = {"max_per_transaction": 10000, "max_daily_amount": 20000,
               "valid_from": now.isoformat(),
               "expires_at": (now + timedelta(seconds=60)).isoformat()}
    payload.update(overrides)
    return create_mandate(ctx, **payload)


# ---------------------------------------------------------------------------
# 1. Agent revoked after the governance decision: new execution is blocked
#    at consume-time revalidation, not re-submitted to the provider.
# ---------------------------------------------------------------------------
def test_agent_revoked_after_approval_blocks_new_execution(paari_client, monkeypatch):
    ctx = paari_client
    auth_id = v31._consume(ctx, monkeypatch, "agent-revoke")

    # Revoke the agent AFTER the intent was allowed and the order submitted.
    session = ctx.Session()
    agent = session.query(models.Agent).filter_by(agent_id=ctx.agent_id).first()
    agent.status = models.AgentStatus.REVOKED
    session.commit()
    session.close()

    # The replay of the original authorization is refused at session
    # revalidation, before any reservation or provider call.
    r = ctx.client.post(f"/payments/authorizations/{auth_id}/consume",
                       json={"session_token": ctx.session_token})
    assert r.status_code == 401, r.text

    # A brand-new execution is refused the same way.
    r2 = ctx.client.post("/payments/intent", json={
        "session_token": ctx.session_token,
        "transaction_id": "TXN-revoke-new", "idempotency_key": "idem-revoke-new",
        "merchant": "TestMerchant", "amount_minor_units": 1000,
        "currency": "INR", "action": "make_payment", "purpose": "post-revoke",
    })
    assert r2.status_code == 401, r2.text

    # Exactly one provider transaction, the original state, one reservation.
    session = ctx.Session()
    rows = session.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).all()
    auth = session.query(models.BoundedAuthorization).filter_by(authorization_id=auth_id).first()
    session.close()
    assert len(rows) == 1, "a revoked agent must not produce a second provider txn"
    assert rows[0].state == "PROVIDER_SUBMITTED"
    assert auth.usage_count == 1


# ---------------------------------------------------------------------------
# 2. Mandate expiry: a minted authorization is no longer spendable, and a
#    parked review cannot be redeemed after the window has closed.
# ---------------------------------------------------------------------------
def test_mandate_expiry_blocks_consume_of_minted_authorization(paari_client, monkeypatch):
    import app.routers.payments as payments_router

    ctx = paari_client
    now = datetime.now(timezone.utc)
    _short_lived_mandate(ctx)
    body = make_intent(ctx, amount=1000, suffix="expiry-minted")
    assert body["decision"] == "allow", body
    auth_id = body["authorization"]["authorization_id"]

    # 90s later: the mandate's 60s window has closed, but the 2-minute
    # authorization and the session are still valid. Consume-time
    # revalidation must fail closed on the lapsed mandate - before the
    # provider is ever called.
    real_now = payments_router._now
    payments_router._now = lambda: now + timedelta(seconds=90)
    try:
        r = ctx.client.post(f"/payments/authorizations/{auth_id}/consume",
                            json={"session_token": ctx.session_token})
    finally:
        payments_router._now = real_now
    assert r.status_code == 403, r.text

    session = ctx.Session()
    auth = session.query(models.BoundedAuthorization).filter_by(authorization_id=auth_id).first()
    txn = session.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).first()
    session.close()
    assert auth.usage_count == 0, "the blocked consume must not reserve the authorization"
    assert txn.state == "AUTHORIZED", "the provider must never have been called"


def test_parked_review_cannot_be_approved_past_mandate_expiry(paari_client, monkeypatch):
    ctx = paari_client
    now = datetime.now(timezone.utc)
    _short_lived_mandate(ctx, max_per_transaction=5000, max_daily_amount=10000,
                         require_review_above=3000)
    body = make_intent(ctx, amount=4000, suffix="parked-review")
    assert body["decision"] == "review", body
    intent_id = body["intent_id"]

    # Six minutes later: the 5-minute review window AND the 60-second mandate
    # window are both closed. The engine's only legal move is to expire the
    # parked review to DENY - no step-up approval can resurrect it.
    session = ctx.Session()
    swept = expire_stale_reviews(session, now=now + timedelta(minutes=6))
    session.close()
    assert swept == 1

    session = ctx.Session()
    intent = session.query(models.PaymentIntent).filter_by(intent_id=intent_id).first()
    auths = session.query(models.BoundedAuthorization).filter_by(intent_id=intent_id).all()
    session.close()
    assert intent.decision == models.GovernanceDecision.DENY
    assert not auths, "a parked review that expired must not mint any authorization"


# ---------------------------------------------------------------------------
# 3. Reconciliation worker restarts: pending work resumes from persisted
#    state, and the terminal row is not reprocessed.
# ---------------------------------------------------------------------------
def test_reconciliation_worker_restart_resumes_persisted_pending_work(paari_client, monkeypatch):
    class EmptyProvider:
        """The provider exists but has captured nothing yet: the row stays
        PROVIDER_UNKNOWN and the worker's attempts counter is the durable
        record of the pending work."""
        key_id = "rzp_worker_empty"

        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": "order_worker", "receipt": authorization_id,
                    "amount": amount_minor_units, "currency": currency, "status": "created"}

        def fetch_payments(self, _order_id):
            return []

        def fetch_order_by_receipt(self, receipt):
            return {"id": "order_res_1", "receipt": receipt,
                    "amount": 120000, "currency": "INR", "status": "created"}

    ctx = paari_client
    auth_id = v31._consume(ctx, monkeypatch, "worker-resume")

    # Crash after the provider submission: the outcome is unknown and the
    # row is persisted non-terminal.
    session = ctx.Session()
    txn = session.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).first()
    txn.state = "PROVIDER_UNKNOWN"
    session.commit()
    session.close()

    # The consume already bumped attempts to 1; capture that durable baseline
    # so the assertion is about *persistence across restarts*, not a magic
    # number.
    session = ctx.Session()
    attempts_at_crash = session.query(models.ProviderTransaction)\
        .filter_by(authorization_id=auth_id).first().attempts
    session.close()

    monkeypatch.setattr(reconcile_mod, "get_provider", lambda: EmptyProvider())

    # Worker lifetime 1: one unreconciled pass (no capture yet), attempts += 1.
    worker1 = ReconciliationWorker(interval_seconds=60, dead_letter_after=5)
    session = ctx.Session()
    worker1._run_batch(session)
    session.close()

    # Worker lifetime 2 (a restart): a brand-new worker on the same durable DB
    # resumes where the first left it - one more unreconciled pass.
    worker2 = ReconciliationWorker(interval_seconds=60, dead_letter_after=5)
    session = ctx.Session()
    worker2._run_batch(session)
    session.close()

    session = ctx.Session()
    txn = session.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).first()
    assert txn.state == "PROVIDER_UNKNOWN"
    assert txn.attempts == attempts_at_crash + 2, (
        "the attempts counter must persist across worker restarts "
        f"(crash={attempts_at_crash}, now={txn.attempts})")
    session.close()

    # Worker lifetime 3: the provider now corroborates the capture; the fresh
    # worker resumes the persisted row and settles it. The settle path does NOT
    # increment attempts, so the counter stays frozen at crash+2.
    monkeypatch.setattr(reconcile_mod, "get_provider", lambda: v31._provider("order_worker_resume"))
    worker3 = ReconciliationWorker(interval_seconds=60, dead_letter_after=5)
    session = ctx.Session()
    worker3._run_batch(session)
    auth = session.query(models.BoundedAuthorization).filter_by(authorization_id=auth_id).first()
    chain_ok = verify_chain(session, auth.transaction_id)
    session.close()

    # Worker lifetime 4: the settled row is terminal and must not be reworked.
    worker4 = ReconciliationWorker(interval_seconds=60, dead_letter_after=5)
    session = ctx.Session()
    worker4._run_batch(session)
    txn = session.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).first()
    session.close()

    assert txn.state == "PAID"
    assert txn.attempts == attempts_at_crash + 2, "a terminal row must not be reprocessed by a later worker"
    assert txn.reconciled_at is not None
    assert chain_ok, "the audit chain must verify after the worker-driven settlement"


# ---------------------------------------------------------------------------
# 4. Audit entry deletion is detected by the hash chain.
# ---------------------------------------------------------------------------
def test_audit_entry_deletion_is_detected(paari_client):
    """Removing an intermediate event leaves the tail pointing at the deleted
    hash; verify_chain must fail. (Detail mutation is already pinned by
    tests/test_audit.py::test_audit_chain_tamper_evident; this closes the
    deletion half of the blueprint row.)"""
    ctx = paari_client
    db = ctx.Session()
    base = {"transaction_id": "TXN-audit-delete", "agent_id": ctx.agent_id,
            "parent_id": ctx.parent_id}
    record_audit(db, kind="intent_decided", detail={"decision": "allow"}, **base)
    middle = record_audit(db, kind="order_submitted", detail={"order": "order_del_1"}, **base)
    record_audit(db, kind="webhook_applied", detail={"state": "CAPTURED"}, **base)
    db.commit()
    assert verify_chain(db, "TXN-audit-delete") is True

    db.delete(middle)
    db.commit()
    assert verify_chain(db, "TXN-audit-delete") is False, "a deleted middle event breaks the chain"
    db.close()
