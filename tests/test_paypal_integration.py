from tests.conftest import make_intent


class FakePayPalProvider:
    provider_name = "paypal"

    def __init__(self):
        self.payment = {
            "id": "PAYPALCAPTURE1",
            "status": "captured",
            "amount": 120000,
            "currency": "INR",
        }
        self.verified_headers = None
        self.capture_calls = []

    def create_payment(self, authorization_id, amount_minor_units, currency, notes):
        return {
            "id": "PAYPALORDER1",
            "receipt": authorization_id,
            "amount": amount_minor_units,
            "currency": currency,
            "status": "created",
            "approval_url": "https://paypal.test/approve",
        }

    def provenance(self):
        return {
            "provider_name": "paypal",
            "provider_environment": "test",
            "provider_key_id_prefix": "paypal-test",
            "provider_api_base": "https://api-m.sandbox.paypal.com",
        }

    def verify_webhook(self, raw_body, signature="", *, headers=None):
        self.verified_headers = headers
        return headers is not None and headers.get("paypal-transmission-id") == "tx-1"

    def get_payment(self, payment_id):
        assert payment_id == self.payment["id"]
        return self.payment

    def capture_order(self, order_id, authorization_id):
        self.capture_calls.append((order_id, authorization_id))
        return {"id": order_id, "status": "completed"}

    def fetch_payments(self, order_id):
        return [self.payment]

    def fetch_order_by_receipt(self, receipt):
        return None

    def refund(self, payment_id, amount_minor_units):
        return {"id": "refund-1"}

    def reconcile(self, authorization_id):
        return {"found": False, "order": None}


def _paypal_capture_event(*, amount="1200.00", currency="INR"):
    return {
        "id": "WH-PAYPAL-1",
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "resource": {
            "id": "PAYPALCAPTURE1",
            "status": "COMPLETED",
            "amount": {"value": amount, "currency_code": currency},
            "supplementary_data": {"related_ids": {"order_id": "PAYPALORDER1"}},
        },
    }


def _paypal_approved_event():
    return {
        "id": "WH-PAYPAL-APPROVED-1",
        "event_type": "CHECKOUT.ORDER.APPROVED",
        "resource": {
            "id": "PAYPALORDER1",
            "status": "APPROVED",
            "purchase_units": [{
                "custom_id": "auth-placeholder",
                "amount": {"value": "1200.00", "currency_code": "INR"},
            }],
        },
    }


def _create_paypal_order(ctx, monkeypatch, provider, suffix):
    import app.routers.payments as payments_router

    monkeypatch.setattr(payments_router, "_provider_for", lambda _db, _org: provider)
    body = make_intent(ctx, suffix=suffix)
    auth_id = body["authorization"]["authorization_id"]
    response = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["provider_name"] == "paypal"
    assert result["provider_order_id"] == "PAYPALORDER1"
    assert result["approval_url"] == "https://paypal.test/approve"
    return auth_id


def test_paypal_capture_webhook_is_verified_and_directly_confirmed(paari_client, monkeypatch):
    ctx = paari_client
    provider = FakePayPalProvider()
    auth_id = _create_paypal_order(ctx, monkeypatch, provider, "paypal-capture")
    response = ctx.client.post(
        "/v1/payments/webhooks/paypal",
        json=_paypal_capture_event(),
        headers={"PAYPAL-TRANSMISSION-ID": "tx-1"},
    )

    assert response.status_code == 200, response.text
    assert response.json() == {"status": "applied", "state": "PAID"}
    assert provider.verified_headers["paypal-transmission-id"] == "tx-1"

    import app.models as models
    with ctx.Session() as db:
        txn = db.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).one()
        assert txn.provider_name == "paypal"
        assert txn.provider_order_id == "PAYPALORDER1"
        assert txn.provider_payment_id == "PAYPALCAPTURE1"
        assert txn.state == "PAID"


def test_paypal_capture_webhook_rejects_mismatched_amount(paari_client, monkeypatch):
    ctx = paari_client
    provider = FakePayPalProvider()
    _create_paypal_order(ctx, monkeypatch, provider, "paypal-mismatch")
    response = ctx.client.post(
        "/v1/payments/webhooks/paypal",
        json=_paypal_capture_event(amount="1.00"),
        headers={"PAYPAL-TRANSMISSION-ID": "tx-1"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "rejected_value_mismatch"


def test_paypal_approved_order_is_captured_server_side(paari_client, monkeypatch):
    ctx = paari_client
    provider = FakePayPalProvider()
    auth_id = _create_paypal_order(ctx, monkeypatch, provider, "paypal-approved")
    event = _paypal_approved_event()
    event["resource"]["purchase_units"][0]["custom_id"] = auth_id
    response = ctx.client.post(
        "/v1/payments/webhooks/paypal",
        json=event,
        headers={"PAYPAL-TRANSMISSION-ID": "tx-1"},
    )

    assert response.status_code == 200, response.text
    assert response.json() == {"status": "applied", "state": "PAID"}
    assert provider.capture_calls == [("PAYPALORDER1", auth_id)]
