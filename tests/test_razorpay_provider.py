import pytest


def test_verify_webhook_signature_accepts_valid_hmac():
    import hashlib, hmac
    from app.providers.razorpay import verify_webhook_signature
    secret = "whsec_test"
    body = b'{"event":"payment.captured"}'
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_webhook_signature(body, sig, secret) is True
    assert verify_webhook_signature(body, "0" * 64, secret) is False


def test_webhook_verification_needs_only_the_webhook_secret(monkeypatch):
    """A signature check should depend on the signing secret and nothing else.

    This used to route through `get_config()`, which raises when the API key id
    and secret are unset, and the exception was caught and returned as `False`.
    The result was a webhook-only listener - the correct hardened topology for a
    publicly reachable receiver - rejecting every genuine delivery with 401,
    looking exactly like it was successfully fending off forgeries.
    """
    import hashlib
    import hmac
    import os

    from app.providers.razorpay import RazorpayAdapter

    secret = "wh-only-secret"  # noqa: S105 (test-only fiction)
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", secret)
    for absent in ("RAZORPAY_KEY_ID", "RAZORPAY_KEY_SECRET"):
        assert os.environ.get(absent) is None, f"{absent} leaked into the test env"

    body = b'{"id":"evt_1","event":"payment.captured"}'
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    adapter = RazorpayAdapter()
    assert adapter.verify_webhook(body, signature) is True
    # ...and a forgery is still refused, or the True above proves nothing.
    assert adapter.verify_webhook(body, "0" * 64) is False
    assert adapter.verify_webhook(body + b" ", signature) is False


def test_webhook_verification_reports_absent_secret_as_unconfigured(monkeypatch):
    """No secret configured must not be silently 'verified false' forever."""
    from app.providers.razorpay import RazorpayAdapter

    monkeypatch.delenv("RAZORPAY_WEBHOOK_SECRET", raising=False)
    assert RazorpayAdapter().verify_webhook(b"{}", "x") is False


def test_duplicate_order_submission_recovers_matching_receipt():
    import httpx

    from app.providers.razorpay import RazorpayAdapter

    requests = []

    def handler(request):
        requests.append(request)
        if request.method == "POST":
            return httpx.Response(400, json={
                "error": {"description": "Duplicate request. This request has already been processed."}
            })
        return httpx.Response(200, json={"items": [{
            "id": "order_existing",
            "receipt": "auth-stable-123",
            "amount": 2500,
            "currency": "INR",
            "status": "created",
        }]})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://x.test")
    try:
        order = RazorpayAdapter(client=client).create_payment(
            authorization_id="auth-stable-123",
            amount_minor_units=2500,
            currency="INR",
            notes=None,
        )
    finally:
        client.close()

    assert order["id"] == "order_existing"
    assert [request.method for request in requests] == ["POST", "GET"]
    assert "X-Razorpay-Idempotency-Key" not in requests[0].headers


def test_order_server_error_without_receipt_recovery_remains_ambiguous():
    import httpx

    from app.providers.razorpay import RazorpayAdapter

    def handler(request):
        if request.method == "POST":
            return httpx.Response(503, json={"error": "temporarily unavailable"})
        return httpx.Response(200, json={"items": []})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="https://x.test")
    try:
        with pytest.raises(httpx.TransportError):
            RazorpayAdapter(client=client).create_payment(
                authorization_id="auth-server-error",
                amount_minor_units=2500,
                currency="INR",
                notes=None,
            )
    finally:
        client.close()
