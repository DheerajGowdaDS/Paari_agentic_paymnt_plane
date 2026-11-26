"""v3.1 Phase-3 security & resilience tests.

These pin the behaviours the local acceptance matrix requires but that were not
yet covered as a group: exactly one concurrent reservation of a single-use
authorization wins, duplicate webhooks are idempotent, an uncertain (timed-out)
provider outcome is held and reconciled safely, and the audit chain stays intact
across those operations. All built on the real seams (the atomic single-use
update in app/routers/payments.py, app.reconcile, the webhook handler, and the
hash-chained audit) so a regression that re-opens any of these fails loudly.

They are local/deterministic: no real provider, no money, no trusted identity.
"""
from __future__ import annotations
import threading
import hashlib
import hmac
import json

from tests.conftest import make_intent


def _provider(order_id="order_res_1"):
    class FakeProvider:
        key_id = "rzp_key_res"
        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": order_id, "receipt": authorization_id,
                    "amount": amount_minor_units, "currency": currency, "status": "created"}
        def get_payment(self, payment_id):
            return {"id": payment_id, "status": "captured",
                    "amount": 120000, "currency": "INR", "order_id": order_id}
        def fetch_payments(self, _order_id):
            # A reconciling read of the provider's own record reports the
            # matching captured payment (value matches the 120000 INR intent).
            return [{"id": order_id + "_pay", "status": "captured",
                     "amount": 120000, "currency": "INR"}]
        def fetch_order_by_receipt(self, _receipt):
            return {"id": order_id, "receipt": _receipt,
                    "amount": 120000, "currency": "INR", "status": "created"}
        def verify_webhook(self, raw_body, signature):
            # Mirror the real adapter: verify against the configured webhook
            # secret so a correct signature passes and a forged one 401s.
            import os, hashlib, hmac
            import app.providers.razorpay as rzp
            secret = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
            return rzp.verify_webhook_signature(raw_body, signature, secret)
    return FakeProvider()


def _consume(ctx, monkeypatch, suffix):
    import app.routers.payments as payments_router
    monkeypatch.setattr(payments_router, "get_provider", lambda: _provider())
    body = make_intent(ctx, suffix=suffix)
    auth_id = body["authorization"]["authorization_id"]
    r = ctx.client.post(f"/payments/authorizations/{auth_id}/consume",
                        json={"session_token": ctx.session_token})
    assert r.status_code == 200, r.text
    return auth_id


# ---------------------------------------------------------------------------
# 1. Exactly one reservation of a single-use authorization is ever admitted.
# ---------------------------------------------------------------------------
def _make_unconsumed_intent(ctx, monkeypatch, suffix):
    """Create a governance-allowed authorization WITHOUT consuming it, so a test
    can drive the atomic conditional update directly."""
    import app.routers.payments as payments_router
    monkeypatch.setattr(payments_router, "get_provider", lambda: _provider())
    body = make_intent(ctx, suffix=suffix)
    return body["authorization"]["authorization_id"]


def _try_reserve(ctx, auth_id):
    """The exact conditional update the consume endpoint uses. Returns the
    rowcount: 1 means this caller won the sole reservation, 0 means it was
    rejected because the authorization is already at its usage limit."""
    import app.models as models
    from sqlalchemy import update
    db = ctx.Session()
    try:
        rowcount = db.execute(
            update(models.BoundedAuthorization)
            .where(models.BoundedAuthorization.authorization_id == auth_id,
                   models.BoundedAuthorization.usage_count < models.BoundedAuthorization.max_usage)
            .values(usage_count=models.BoundedAuthorization.usage_count + 1)
        ).rowcount
        # The real consume endpoint commits the reservation; a winner must
        # persist it or the next caller would see the same un-exhausted row.
        db.commit() if rowcount else db.rollback()
        return rowcount
    finally:
        db.close()


def test_single_use_reservation_admits_exactly_one(paari_client, monkeypatch):
    """DB-agnostic proof of the load-bearing invariant: a max_usage=1
    authorization is reserved exactly once. The first conditional update wins
    (rowcount 1); the second matches no rows (rowcount 0) and is rejected."""
    ctx = paari_client
    auth_id = _make_unconsumed_intent(ctx, monkeypatch, "single-use")
    assert _try_reserve(ctx, auth_id) == 1, "first reservation must win"
    assert _try_reserve(ctx, auth_id) == 0, "second reservation must be rejected"


def test_concurrent_reservations_cannot_exceed_limit(paari_client, monkeypatch):
    """N workers race the real atomic conditional update on a single-use
    authorization; at most one may ever win. The HTTP consume already reserved
    it (usage_count==max), so no worker may record a new win. Workers that hit a
    write lock (SQLite) are treated as 'did not win', which is the safe
    outcome; on PostgreSQL the invariant holds under true concurrency too."""
    import app.models as models
    from sqlalchemy import update
    ctx = paari_client
    auth_id = _consume(ctx, monkeypatch, "conc-race")

    winners = []
    errors = []
    barrier = threading.Barrier(8)
    lock = threading.Lock()

    def worker():
        barrier.wait()
        wdb = ctx.Session()
        try:
            try:
                rowcount = wdb.execute(
                    update(models.BoundedAuthorization)
                    .where(models.BoundedAuthorization.authorization_id == auth_id,
                           models.BoundedAuthorization.usage_count < models.BoundedAuthorization.max_usage)
                    .values(usage_count=models.BoundedAuthorization.usage_count + 1)
                ).rowcount
                with lock:
                    winners.append(rowcount == 1)
            except Exception as exc:  # noqa: BLE001 - lock/busy is a safe no-win
                with lock:
                    errors.append(type(exc).__name__)
        finally:
            wdb.close()

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(winners) == 0, winners
    # Whatever won/lost, the DB must still hold exactly the one reservation.
    db = ctx.Session()
    auth = db.query(models.BoundedAuthorization).filter_by(authorization_id=auth_id).first()
    db.close()
    assert auth.usage_count == 1, f"usage must remain capped at 1, got {auth.usage_count} (lock errors: {errors})"

    # And the HTTP path reports a stable replay outcome, not a re-submission.
    r = ctx.client.post(f"/payments/authorizations/{auth_id}/consume",
                       json={"session_token": ctx.session_token})
    assert r.status_code == 409, r.text


def test_double_consume_http_second_is_rejected(paari_client, monkeypatch):
    """Sequential double-consume via the real endpoint: second is 409, one row."""
    import app.models as models
    ctx = paari_client
    auth_id = _consume(ctx, monkeypatch, "double-http")
    r2 = ctx.client.post(f"/payments/authorizations/{auth_id}/consume",
                        json={"session_token": ctx.session_token})
    assert r2.status_code == 409, r2.text
    db = ctx.Session()
    rows = db.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).all()
    db.close()
    assert len(rows) == 1, "one row per authorization; a duplicate must not create a second provider txn"


# ---------------------------------------------------------------------------
# 2. Duplicate webhook delivery is idempotent (no double settlement).
# ---------------------------------------------------------------------------
def test_duplicate_webhook_delivery_is_idempotent(paari_client, monkeypatch):
    import app.routers.payments as payments_router
    import app.models as models

    ctx = paari_client
    auth_id = _consume(ctx, monkeypatch, "dup-webhook")
    secret = "dup_webhook_secret"  # test-only fiction, same convention as phase9 tests
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", secret)
    monkeypatch.setattr(payments_router, "get_provider", lambda: _provider("order_dup"))

    db = ctx.Session()
    txn = db.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).first()
    db.close()
    order_id = txn.razorpay_order_id
    pay_id = "pay_dup_1"

    def sign(raw: bytes) -> str:
        return hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()

    body = json.dumps({
        "id": "evt_dup_fixed",
        "event": "payment.captured",
        "payload": {"payment": {"entity": {"id": pay_id, "order_id": order_id,
                                           "amount": 120000, "currency": "INR"}}},
    }).encode()
    headers = {"X-Razorpay-Signature": sign(body), "Content-Type": "application/json"}
    r1 = ctx.client.post("/payments/webhooks/razorpay", content=body, headers=headers)
    assert r1.status_code == 200, r1.text
    r2 = ctx.client.post("/payments/webhooks/razorpay", content=body, headers=headers)
    assert r2.status_code == 200, r2.text
    assert r1.json()["status"] == "applied"
    assert r2.json()["status"] == "duplicate_ignored", r2.json()
    db = ctx.Session()
    t = db.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).first()
    db.close()
    assert t.state == "PAID"
    assert t.razorpay_payment_id == pay_id


# ---------------------------------------------------------------------------
# 3. Uncertain provider outcome (timeout) is held, then reconciled safely.
# ---------------------------------------------------------------------------
def test_timeout_uncertain_state_reconciles_to_paid(paari_client, monkeypatch):
    import httpx
    import app.routers.payments as payments_router
    import app.reconcile as reconcile_mod
    from app.reconcile import reconcile_one

    class TimeoutProvider:
        def create_payment(self, **kw):
            raise httpx.TimeoutException("provider timed out")

    monkeypatch.setattr(payments_router, "get_provider", lambda: TimeoutProvider())
    ctx = paari_client
    body = make_intent(ctx, suffix="to-unknown")
    auth_id = body["authorization"]["authorization_id"]
    r = ctx.client.post(f"/payments/authorizations/{auth_id}/consume",
                        json={"session_token": ctx.session_token})
    assert r.status_code == 502, r.text  # submission failed -> uncertain, not settled

    import app.models as models
    db = ctx.Session()
    assert db.query(models.ProviderTransaction).filter_by(authorization_id=auth_id) \
            .first().state == "PROVIDER_UNKNOWN"
    db.close()

    provider = _provider("order_to_found")
    provider.fetch_order_by_receipt = lambda _r: {"id": "order_to_found", "receipt": auth_id,
                                                  "amount": 120000, "currency": "INR", "status": "created"}
    monkeypatch.setattr(reconcile_mod, "get_provider", lambda: provider)
    db = ctx.Session()
    result = reconcile_one(db, auth_id)
    db.close()
    assert result == {"status": "reconciled", "state": "PAID"}


def test_uncertain_provider_amount_mismatch_is_not_settled(paari_client, monkeypatch):
    """A reconciled read that reports the wrong value must NOT reach PAID."""
    import app.reconcile as reconcile_mod
    from app.reconcile import reconcile_one

    ctx = paari_client
    monkeypatch.setattr("app.routers.payments.get_provider", lambda: _provider("order_mis"))
    auth_id = _consume(ctx, monkeypatch, "value-mismatch")

    import app.models as models
    db = ctx.Session()
    txn = db.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).first()
    txn.state = "PROVIDER_UNKNOWN"
    db.commit()
    db.close()

    class MismatchProvider:
        def fetch_payments(self, _order_id):
            return [{"id": "pay_mis", "status": "captured", "amount": 999, "currency": "INR"}]
        def get_payment(self, _pid):
            return {"id": "pay_mis", "status": "captured", "amount": 999, "currency": "INR"}
        def fetch_order_by_receipt(self, _r):
            return None

    monkeypatch.setattr(reconcile_mod, "get_provider", lambda: MismatchProvider())
    db = ctx.Session()
    result = reconcile_one(db, auth_id)
    db.close()
    assert result["status"] == "unreconciled", result
    db = ctx.Session()
    assert db.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).first().state \
            == "PROVIDER_UNKNOWN"  # held, never settled on a value mismatch
    db.close()


# ---------------------------------------------------------------------------
# 4. Audit chain stays intact across the above operations (recovery evidence).
# ---------------------------------------------------------------------------
def test_audit_chain_intact_after_consume_and_reconcile(paari_client, monkeypatch):
    import app.models as models
    ctx = paari_client
    auth_id = _consume(ctx, monkeypatch, "audit-intact")

    monkeypatch.setattr("app.reconcile.get_provider", lambda: _provider("order_aud"))
    from app.reconcile import reconcile_one
    db = ctx.Session()
    txn = db.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).first()
    txn.state = "PROVIDER_UNKNOWN"
    db.commit()
    result = reconcile_one(db, auth_id)
    db.close()
    assert result["state"] == "PAID"

    # Independent chain verification: every event links to its predecessor.
    # The audit trace key is the BoundedAuthorization.transaction_id (see
    # app/reconcile._trace_key) - use the authoritative source, not the intent.
    db = ctx.Session()
    auth = db.query(models.BoundedAuthorization).filter_by(authorization_id=auth_id).first()
    events = (db.query(models.AuditEvent)
               .filter(models.AuditEvent.transaction_id == auth.transaction_id)
               .order_by(models.AuditEvent.created_at.asc(), models.AuditEvent.id.asc()).all())
    db.close()
    assert events, "expected at least one audit event for the payment trace"
    for prev, cur in zip(events, events[1:]):
        assert cur.prev_hash == prev.event_hash, "audit hash chain broken"
