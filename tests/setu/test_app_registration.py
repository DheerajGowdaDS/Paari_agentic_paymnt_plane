from fastapi.testclient import TestClient

from app.main import app


def test_setu_status_route_is_mounted(monkeypatch):
    monkeypatch.setenv("SETU_AA_ENABLED", "false")

    response = TestClient(app).get("/integrations/setu-aa/status")

    assert response.status_code == 200
    assert response.json()["enabled"] is False
