import respx
from httpx import Response

from app.integrations.mastercard.client import MastercardClient


@respx.mock
def test_mastercard_authentication_sends_standard_user_agent(monkeypatch):
    monkeypatch.setenv("MASTERCARD_PARTNER_ID", "partner-test")
    monkeypatch.setenv("MASTERCARD_PARTNER_SECRET", "secret-test")
    monkeypatch.setenv("MASTERCARD_APP_KEY", "app-test")
    route = respx.post("https://api.finicity.com/aggregation/v2/partners/authentication").mock(
        return_value=Response(200, json={"token": "sandbox-token"})
    )

    MastercardClient()._headers()

    assert route.called
    assert route.calls.last.request.headers["User-Agent"].startswith("Mozilla/5.0")
