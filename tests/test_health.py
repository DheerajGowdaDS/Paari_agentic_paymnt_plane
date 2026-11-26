"""Task G2: rich health check."""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_returns_env_and_db_status():
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert "env" in body
    assert "database" in body


def test_readiness_fails_closed_when_strict_governance_is_disabled(monkeypatch):
    monkeypatch.delenv("PAARI_CONTROL_PLANE_ENFORCEMENT", raising=False)
    monkeypatch.delenv("PAARI_RECEIVER_ENFORCEMENT", raising=False)
    monkeypatch.delenv("PAARI_FEDERATION_ENFORCEMENT", raising=False)
    monkeypatch.delenv("PAARI_REQUIRE_SIGNED_MANDATE", raising=False)
    monkeypatch.delenv("PAARI_REQUIRE_SAFR_ENVELOPE", raising=False)
    r = client.get("/health/ready")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "not_ready"
    assert "control_plane_enforcement" in body["blocking_checks"]
    assert "signed_mandates_required" in body["blocking_checks"]
    assert "receiver_enforcement" in body["blocking_checks"]
    assert "federation_enforcement" in body["blocking_checks"]
    assert "safr_envelope_required" in body["blocking_checks"]


def test_readiness_does_not_treat_liveness_as_production_readiness():
    live = client.get("/health")
    ready = client.get("/health/ready")
    assert live.status_code == 200
    assert ready.status_code in (200, 503)
    assert "checks" in ready.json()
    assert "production_launch_blockers" in ready.json()


def _ready_env(monkeypatch):
    monkeypatch.setenv("PAARI_CONTROL_PLANE_ENFORCEMENT", "1")
    monkeypatch.setenv("PAARI_RECEIVER_ENFORCEMENT", "1")
    monkeypatch.setenv("PAARI_FEDERATION_ENFORCEMENT", "1")
    monkeypatch.setenv("PAARI_REQUIRE_SIGNED_MANDATE", "1")
    monkeypatch.setenv("PAARI_REQUIRE_SAFR_ENVELOPE", "1")
    monkeypatch.setenv("PAARI_ADMIN_API_KEY", "A" * 48)
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_AbCdEf123456")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "test-secret-with-enough-entropy")
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", "test-webhook-secret-48-characters")


def test_readiness_positive_control_with_non_placeholder_credentials(monkeypatch):
    _ready_env(monkeypatch)
    r = client.get("/health/ready")
    assert r.status_code == 200, r.json()
    assert r.json()["status"] == "ready"
    assert r.json()["checks"]["signing_backend_healthy"] is True


def test_readiness_rejects_placeholder_provider_key_id(monkeypatch):
    _ready_env(monkeypatch)
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_REPLACE_ME")
    r = client.get("/health/ready")
    assert r.status_code == 503
    assert "razorpay_test_or_live_key_present" in r.json()["blocking_checks"]


def test_readiness_rejects_placeholder_webhook_secret(monkeypatch):
    _ready_env(monkeypatch)
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", "{your-webhook-secret}")
    r = client.get("/health/ready")
    assert r.status_code == 503
    assert "webhook_secret_present" in r.json()["blocking_checks"]


def test_readiness_rejects_placeholder_admin_key(monkeypatch):
    _ready_env(monkeypatch)
    monkeypatch.setenv("PAARI_ADMIN_API_KEY", "<generate-a-random-admin-key>")
    r = client.get("/health/ready")
    assert r.status_code == 503
    assert "strong_admin_key_present" in r.json()["blocking_checks"]


def test_health_reports_principal_identity_provider_is_not_configured():
    body = client.get("/health").json()
    status = body["principal_identity_provider"]
    assert status["configured"] is False
    assert status["trusted_evidence"] is False
    assert status["status"] == "not_configured"
