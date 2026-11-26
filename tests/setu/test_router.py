from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.integrations.setu import router as setu_router


def _client(monkeypatch) -> TestClient:
    monkeypatch.setenv("PAARI_ADMIN_API_KEY", "local-admin-key")
    app = FastAPI()
    app.include_router(setu_router.router)
    return TestClient(app)


def test_status_reports_setu_configuration_without_secrets(monkeypatch):
    monkeypatch.setenv("SETU_AA_ENABLED", "true")
    monkeypatch.setenv("SETU_AA_CLIENT_ID", "client")
    monkeypatch.setenv("SETU_AA_CLIENT_SECRET", "secret")
    monkeypatch.setenv("SETU_AA_PRODUCT_INSTANCE_ID", "instance")

    response = _client(monkeypatch).get("/integrations/setu-aa/status")

    assert response.status_code == 200
    assert response.json() == {"enabled": True, "credentials_configured": True, "mode": "sandbox"}


def test_create_consent_requires_admin_key(monkeypatch):
    monkeypatch.setenv("SETU_AA_ENABLED", "true")

    response = _client(monkeypatch).post("/integrations/setu-aa/consents", json={"vua": "9999999999@setu"})

    assert response.status_code == 401
