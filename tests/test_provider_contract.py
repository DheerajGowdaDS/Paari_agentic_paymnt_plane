import json

import httpx
import pytest

from app.providers.base import PaymentProvider


def _paypal_client(handler):
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="https://api-m.sandbox.paypal.com",
    )


def test_razorpay_and_paypal_implement_the_shared_payment_provider_contract():
    from app.providers.paypal import PayPalAdapter
    from app.providers.razorpay import RazorpayAdapter

    required_methods = (
        "create_payment",
        "get_payment",
        "fetch_payments",
        "fetch_order_by_receipt",
        "verify_webhook",
        "refund",
        "reconcile",
    )
    for adapter_type in (RazorpayAdapter, PayPalAdapter):
        assert issubclass(adapter_type, PaymentProvider)
        for method in required_methods:
            assert getattr(adapter_type, method) is not getattr(PaymentProvider, method)


def test_default_provider_selection_and_health_provenance_support_paypal(monkeypatch):
    monkeypatch.setenv("PAARI_DEFAULT_PROVIDER", "paypal")
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "paypal-client-default")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "paypal-secret-default")
    monkeypatch.setenv("PAYPAL_WEBHOOK_ID", "paypal-webhook-default")
    monkeypatch.setenv("PAYPAL_ENV", "sandbox")

    from app.main import provider_identity
    from app.providers.base import get_provider
    from app.providers.paypal import PayPalAdapter

    adapter = get_provider()
    assert isinstance(adapter, PayPalAdapter)
    identity = provider_identity()
    assert identity["provider_name"] == "paypal"
    assert identity["provider"] == "real-paypal(sandbox)"


def test_paypal_create_order_uses_operation_idempotency_and_normalizes_response():
    from app.providers.paypal import PayPalAdapter

    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(200, json={"access_token": "token", "expires_in": 300})
        assert request.url.path == "/v2/checkout/orders"
        assert request.headers["PayPal-Request-Id"]
        payload = json.loads(request.content)
        assert payload["intent"] == "CAPTURE"
        assert payload["purchase_units"][0]["custom_id"] == "auth-paypal-1"
        return httpx.Response(201, json={
            "id": "PAYPALORDER1",
            "status": "PAYER_ACTION_REQUIRED",
            "purchase_units": [{
                "custom_id": "auth-paypal-1",
                "amount": {"currency_code": "USD", "value": "12.34"},
            }],
            "links": [{"rel": "payer-action", "href": "https://paypal.test/approve"}],
        })

    client = _paypal_client(handler)
    try:
        adapter = PayPalAdapter(client=client, client_id="client", client_secret="secret")
        order = adapter.create_payment("auth-paypal-1", 1234, "USD", None)
        repeated = adapter.create_payment("auth-paypal-1", 1234, "USD", None)
    finally:
        client.close()

    assert order["id"] == "PAYPALORDER1"
    assert order["receipt"] == "auth-paypal-1"
    assert order["amount"] == 1234
    assert order["currency"] == "USD"
    assert order["approval_url"] == "https://paypal.test/approve"
    assert repeated["id"] == order["id"]
    create_requests = [request for request in requests if request.url.path == "/v2/checkout/orders"]
    assert create_requests[0].headers["PayPal-Request-Id"] == create_requests[1].headers["PayPal-Request-Id"]


def test_paypal_webhook_verification_uses_paypal_verification_api():
    from app.providers.paypal import PayPalAdapter

    event = {"id": "WH-EVENT-1", "event_type": "PAYMENT.CAPTURE.COMPLETED", "resource": {}}
    headers = {
        "paypal-auth-algo": "SHA256withRSA",
        "paypal-cert-url": "https://api.paypal.com/cert",
        "paypal-transmission-id": "transmission-1",
        "paypal-transmission-sig": "signature",
        "paypal-transmission-time": "2026-10-30T00:00:00Z",
    }

    def handler(request):
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(200, json={"access_token": "token", "expires_in": 300})
        assert request.url.path == "/v1/notifications/verify-webhook-signature"
        body = json.loads(request.content)
        assert body["webhook_id"] == "webhook-id"
        assert body["webhook_event"] == event
        assert body["transmission_id"] == "transmission-1"
        return httpx.Response(200, json={"verification_status": "SUCCESS"})

    client = _paypal_client(handler)
    try:
        adapter = PayPalAdapter(
            client=client, client_id="client", client_secret="secret", webhook_id="webhook-id",
        )
        assert adapter.verify_webhook(
            json.dumps(event).encode(), "", headers=headers,
        )
    finally:
        client.close()


def test_paypal_order_capture_uses_a_stable_operation_idempotency_key():
    from app.providers.paypal import PayPalAdapter

    capture_requests = []

    def handler(request):
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(200, json={"access_token": "token", "expires_in": 300})
        capture_requests.append(request)
        assert request.url.path == "/v2/checkout/orders/PAYPALORDER1/capture"
        return httpx.Response(201, json={"id": "PAYPALORDER1", "status": "COMPLETED"})

    client = _paypal_client(handler)
    try:
        adapter = PayPalAdapter(client=client, client_id="client", client_secret="secret")
        first = adapter.capture_order("PAYPALORDER1", "auth-paypal-capture")
        second = adapter.capture_order("PAYPALORDER1", "auth-paypal-capture")
    finally:
        client.close()

    assert first["status"] == "completed"
    assert second["status"] == "completed"
    assert capture_requests[0].headers["PayPal-Request-Id"] == capture_requests[1].headers["PayPal-Request-Id"]


@pytest.mark.parametrize("value,expected", [("12.34", 1234), ("100", 10000), ("1.234", 1234)])
def test_paypal_amount_conversion_uses_currency_minor_units(value, expected):
    from app.providers.paypal import paypal_amount_to_minor_units

    assert paypal_amount_to_minor_units(value, "USD" if value != "1.234" else "KWD") == expected


# ---------------------------------------------------------------------------
# Shared adapter-contract matrix.
#
# Every concrete adapter is driven through the same scenarios so a new provider
# cannot pass review by only overriding the abstract methods. Each adapter is
# exercised against its real request/response shapes with MockTransport; the
# idempotency *mechanism* stays provider-specific (Razorpay receipt vs PayPal
# request ID) while the observable contract is identical.
# ---------------------------------------------------------------------------

def _razorpay_payment():
    return {"id": "pay_contract", "status": "captured", "amount": 1234, "currency": "INR"}


def _razorpay_contract_client(requests):
    state = {"created": False}

    def handler(request):
        requests.append(request)
        path = request.url.path
        if path == "/orders" and request.method == "POST":
            payload = json.loads(request.content)
            if state["created"]:
                return httpx.Response(400, json={"error": {"description": "receipt already exists"}})
            state["created"] = True
            return httpx.Response(200, json={
                "id": "order_contract", "receipt": payload["receipt"],
                "amount": payload["amount"], "currency": payload["currency"], "status": "created",
            })
        if path == "/orders":
            assert request.url.params.get("receipt") == "auth-contract"
            return httpx.Response(200, json={"items": [{
                "id": "order_contract", "receipt": "auth-contract",
                "amount": 1234, "currency": "INR", "status": "created",
            }]})
        if path == "/orders/order_contract/payments":
            return httpx.Response(200, json={"items": [_razorpay_payment()]})
        if path == "/payments/pay_contract":
            return httpx.Response(200, json=_razorpay_payment())
        if path == "/payments/pay_contract/refund":
            return httpx.Response(200, json={"id": "rfnd_contract", "amount": 1234})
        raise AssertionError(f"unexpected Razorpay request {request.method} {path}")

    return httpx.Client(
        transport=httpx.MockTransport(handler), base_url="https://api.razorpay.test",
    )


def _paypal_capture():
    return {
        "id": "pay_contract",
        "status": "COMPLETED",
        "amount": {"value": "12.34", "currency_code": "USD"},
        "supplementary_data": {"related_ids": {"order_id": "order_contract"}},
    }


def _paypal_order(*, status, amount, custom_id):
    return {
        "id": "order_contract",
        "status": status,
        "purchase_units": [{
            "custom_id": custom_id,
            "amount": amount,
            "payments": {"captures": [_paypal_capture()]},
        }],
        "links": [{"rel": "payer-action", "href": "https://paypal.test/approve"}],
    }


def _paypal_contract_client(requests):
    def handler(request):
        requests.append(request)
        path = request.url.path
        if path == "/v1/oauth2/token":
            return httpx.Response(200, json={"access_token": "token", "expires_in": 300})
        if path == "/v2/checkout/orders" and request.method == "POST":
            payload = json.loads(request.content)
            unit = payload["purchase_units"][0]
            return httpx.Response(201, json=_paypal_order(
                status="PAYER_ACTION_REQUIRED", amount=unit["amount"], custom_id=unit["custom_id"],
            ))
        if path == "/v2/checkout/orders/order_contract":
            return httpx.Response(200, json=_paypal_order(
                status="APPROVED", amount={"value": "12.34", "currency_code": "USD"},
                custom_id="auth-contract",
            ))
        if path == "/v2/payments/captures/pay_contract":
            return httpx.Response(200, json=_paypal_capture())
        if path == "/v2/payments/captures/pay_contract/refund":
            return httpx.Response(201, json={"id": "rfnd_contract", "status": "COMPLETED"})
        raise AssertionError(f"unexpected PayPal request {request.method} {path}")

    return httpx.Client(
        transport=httpx.MockTransport(handler), base_url="https://api-m.sandbox.paypal.com",
    )


def _assert_shared_adapter_contract(adapter, currency):
    created = adapter.create_payment(
        "auth-contract", 1234, currency, {"paari_transaction_id": "TXN-contract"},
    )
    assert created["id"] == "order_contract"
    assert created["receipt"] == "auth-contract"
    assert created["amount"] == 1234
    assert created["currency"] == currency

    duplicate = adapter.create_payment("auth-contract", 1234, currency, None)
    assert duplicate["id"] == created["id"]

    payment = adapter.get_payment("pay_contract")
    assert payment["status"] == "captured"
    assert payment["amount"] == 1234
    assert payment["currency"] == currency

    attempts = adapter.fetch_payments("order_contract")
    assert isinstance(attempts, list) and attempts
    assert attempts[0]["id"] == "pay_contract"

    refund = adapter.refund("pay_contract", 1234)
    assert refund["id"] == "rfnd_contract"

    reconciled = adapter.reconcile("auth-contract")
    assert {"found", "order"} <= set(reconciled)
    assert isinstance(reconciled["found"], bool)

    assert adapter.verify_webhook(b"{}", "", headers={}) is False


def test_razorpay_satisfies_the_shared_adapter_contract():
    from app.providers.razorpay import RazorpayAdapter

    requests = []
    client = _razorpay_contract_client(requests)
    try:
        _assert_shared_adapter_contract(RazorpayAdapter(client=client), "INR")
    finally:
        client.close()

    creates = [r for r in requests if r.url.path == "/orders" and r.method == "POST"]
    assert creates, requests
    assert all("X-Razorpay-Idempotency-Key" not in r.headers for r in creates)
    assert json.loads(creates[0].content)["receipt"] == "auth-contract"
    assert any(r.url.path == "/orders" and r.url.params.get("receipt") == "auth-contract"
               for r in requests)


def test_paypal_satisfies_the_shared_adapter_contract():
    from app.providers.paypal import PayPalAdapter

    requests = []
    client = _paypal_contract_client(requests)
    try:
        _assert_shared_adapter_contract(
            PayPalAdapter(client=client, client_id="client", client_secret="secret"), "USD",
        )
    finally:
        client.close()

    creates = [r for r in requests
               if r.url.path == "/v2/checkout/orders" and r.method == "POST"]
    assert len(creates) == 2, requests
    assert creates[0].headers["PayPal-Request-Id"] == creates[1].headers["PayPal-Request-Id"]


def test_default_org_provider_routing_honors_configured_default_provider(monkeypatch):
    """`get_provider_for_org(db, "default")` must not bypass PAARI_DEFAULT_PROVIDER."""
    from app.provider_accounts import get_provider_for_org
    from app.providers.paypal import PayPalAdapter

    monkeypatch.setenv("PAARI_DEFAULT_PROVIDER", "paypal")
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "client")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "secret")
    monkeypatch.setenv("PAYPAL_WEBHOOK_ID", "webhook-id")

    class NoTenantLookup:
        def query(self, *_args, **_kwargs):
            raise AssertionError("the default org must not query a tenant provider account")

    assert isinstance(get_provider_for_org(NoTenantLookup(), "default"), PayPalAdapter)