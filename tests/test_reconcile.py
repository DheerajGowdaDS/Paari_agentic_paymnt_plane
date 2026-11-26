"""Task 3: reconciliation job + UNKNOWN recovery via receipt."""
import pytest

from tests.conftest import make_intent


class FakeProvider:
    """Router-seam fake; per-test behavior via attributes."""

    order_id = "order_rec_1"
    payment = {
        "id": "pay_rec_1", "status": "captured", "order_id": "order_rec_1",
        "amount": 120000, "currency": "INR",
    }
    receipt_order = None

    def create_payment(self, authorization_id, amount_minor_units, currency, notes):
        return {"id": self.order_id, "receipt": authorization_id, "amount": amount_minor_units, "currency": currency, "status": "created"}

    def get_payment(self, payment_id):
        return self.payment

    def fetch_payments(self, order_id):
        return [self.payment]

    def fetch_order_by_receipt(self, receipt):
        return self.receipt_order


def _consume(ctx, monkeypatch, provider, suffix):
    import app.routers.payments as payments_router
    import app.reconcile as reconcile_mod

    monkeypatch.setattr(payments_router, "get_provider", lambda: provider)
    monkeypatch.setattr(reconcile_mod, "get_provider", lambda: provider)
    body = make_intent(ctx, suffix=suffix)
    auth_id = body["authorization"]["authorization_id"]
    r = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
    )
    assert r.status_code == 200, r.text
    return auth_id


def _txn(ctx, auth_id):
    import app.models as models

    db = ctx.Session()
    txn = db.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).first()
    db.close()
    return txn


def test_reconciler_adopts_captured_without_webhook(paari_client, monkeypatch):
    from app.reconcile import reconcile_one

    ctx = paari_client
    provider = FakeProvider()
    auth_id = _consume(ctx, monkeypatch, provider, "rec-captured")

    import app.models as models
    db = ctx.Session()
    txn = db.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).first()
    txn.state = "PAYMENT_PENDING"
    db.commit()
    db.close()

    db = ctx.Session()
    result = reconcile_one(db, auth_id)
    db.close()
    assert result == {"status": "reconciled", "state": "PAID"}
    txn = _txn(ctx, auth_id)
    assert txn.state == "PAID"
    assert txn.razorpay_payment_id == "pay_rec_1"
    assert txn.reconciled_at is not None


def test_reconciler_recovers_unknown_via_receipt(paari_client, monkeypatch):
    import httpx
    import app.routers.payments as payments_router
    import app.reconcile as reconcile_mod
    from app.reconcile import reconcile_one

    class TimeoutProvider:
        def create_payment(self, **kwargs):
            raise httpx.TimeoutException("no response")

    monkeypatch.setattr(payments_router, "get_provider", lambda: TimeoutProvider())
    ctx = paari_client
    body = make_intent(ctx, suffix="rec-unknown")
    auth_id = body["authorization"]["authorization_id"]
    r = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
    )
    assert r.status_code == 502, r.text
    assert _txn(ctx, auth_id).state == "PROVIDER_UNKNOWN"

    provider = FakeProvider()
    provider.receipt_order = {"id": "order_receipt_found", "receipt": auth_id, "amount": 120000, "currency": "INR"}
    provider.payment = {
        "id": "pay_late_1", "status": "captured", "order_id": "order_receipt_found",
        "amount": 120000, "currency": "INR",
    }
    monkeypatch.setattr(payments_router, "get_provider", lambda: provider)
    monkeypatch.setattr(reconcile_mod, "get_provider", lambda: provider)

    db = ctx.Session()
    result = reconcile_one(db, auth_id)
    db.close()
    assert result == {"status": "reconciled", "state": "PAID"}
    txn = _txn(ctx, auth_id)
    assert txn.razorpay_order_id == "order_receipt_found"


def test_reconciler_leaves_terminal_alone(paari_client):
    from app.reconcile import reconcile_one

    ctx = paari_client
    db = ctx.Session()
    result = reconcile_one(db, "auth-that-does-not-exist")
    db.close()
    assert result["status"] == "not_found"


@pytest.mark.parametrize("missing_field", ["amount", "currency"])
@pytest.mark.parametrize("entry_point", ["reconcile", "confirm_capture"])
def test_provider_capture_missing_value_is_not_settled(
    paari_client, monkeypatch, missing_field, entry_point
):
    import app.models as models
    from app.reconcile import confirm_capture, reconcile_one

    ctx = paari_client
    auth_id = _consume(ctx, monkeypatch, FakeProvider(), f"missing-{entry_point}-{missing_field}")
    payment = {
        "id": "pay_missing_value",
        "status": "captured",
        "amount": 120000,
        "currency": "INR",
    }
    del payment[missing_field]

    class IncompleteProvider:
        def get_payment(self, _payment_id):
            return payment

        def fetch_payments(self, _order_id):
            return [payment]

        def fetch_order_by_receipt(self, _receipt):
            return None

    monkeypatch.setattr("app.reconcile.get_provider", lambda: IncompleteProvider())
    db = ctx.Session()
    try:
        txn = db.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).one()
        if entry_point == "reconcile":
            txn.state = "PROVIDER_UNKNOWN"
            db.commit()
            result = reconcile_one(db, auth_id)
            assert result["status"] == "unreconciled"
            expected_state = "PROVIDER_UNKNOWN"
        else:
            txn.state = "CAPTURED"
            txn.razorpay_payment_id = payment["id"]
            db.commit()
            confirm_capture(db, IncompleteProvider(), txn, auth_id)
            expected_state = "CAPTURED"

        db.refresh(txn)
        assert txn.state == expected_state
    finally:
        db.close()


def test_reconcile_endpoint_requires_owner(paari_client, monkeypatch):
    ctx = paari_client
    provider = FakeProvider()
    auth_id = _consume(ctx, monkeypatch, provider, "rec-owner")
    _, other_token, _, _ = ctx.register_extra_agent(suffix="-rec-other")
    r = ctx.client.post(
        f"/v1/reconcile/{auth_id}", json={"session_token": other_token}
    )
    assert r.status_code == 403, r.text
    r = ctx.client.post(
        f"/v1/reconcile/{auth_id}", json={"session_token": ctx.session_token}
    )
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "PAID"
