import json

import respx
from httpx import Response

from app.integrations.setu.client import SetuAAClient


def _configure_setu(monkeypatch):
    monkeypatch.setenv("SETU_AA_CLIENT_ID", "setu-client-id")
    monkeypatch.setenv("SETU_AA_CLIENT_SECRET", "setu-client-secret")
    monkeypatch.setenv("SETU_AA_PRODUCT_INSTANCE_ID", "setu-product-instance")


@respx.mock
def test_account_availability_uses_cached_oauth_token_and_product_instance(monkeypatch):
    _configure_setu(monkeypatch)
    token_route = respx.post("https://uat.setu.co/api/v2/auth/token").mock(
        return_value=Response(200, json={"success": True, "data": {"token": "setu-token", "expiresIn": 1800}})
    )
    availability_route = respx.post("https://fiu-sandbox.setu.co/v2/account-availability").mock(
        return_value=Response(200, json={"accounts": [], "traceId": "trace-1"})
    )

    result = SetuAAClient().account_availability("9999999999")

    assert result["traceId"] == "trace-1"
    assert token_route.called
    request = availability_route.calls.last.request
    assert request.headers["Authorization"] == "Bearer setu-token"
    assert request.headers["x-product-instance-id"] == "setu-product-instance"
    assert json.loads(request.content) == {"mobileNumber": "9999999999"}


@respx.mock
def test_create_consent_uses_setu_aa_sandbox_path(monkeypatch):
    _configure_setu(monkeypatch)
    respx.post("https://uat.setu.co/api/v2/auth/token").mock(
        return_value=Response(200, json={"success": True, "data": {"token": "setu-token", "expiresIn": 1800}})
    )
    consent_route = respx.post("https://fiu-sandbox.setu.co/v2/consents").mock(
        return_value=Response(200, json={"id": "consent-1", "status": "PENDING", "url": "https://fiu-sandbox.setu.co/consents/webview/consent-1"})
    )
    payload = {"vua": "9999999999@setu", "consentDuration": {"unit": "MONTH", "value": "1"}}

    result = SetuAAClient().create_consent(payload)

    assert result["id"] == "consent-1"
    assert json.loads(consent_route.calls.last.request.content) == payload
