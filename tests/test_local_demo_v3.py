"""v3.0 sandbox safety, framework dispositions and evidence integrity."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from local_demo.core import SCENARIOS, EvidenceStore, decision_preview
from local_demo.portal import create_app, safe_demo_env
from local_demo.database_guards import guarded_database_url


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_every_safr_disposition_fixture_is_authentic_and_matches_expectation(name):
    result = decision_preview(name)
    assert result["disposition"] == result["expected"]
    assert result["provider_executed"] is False
    assert result["sandbox_only"] is True
    assert result["envelope_verified"] is (name != "deny_signature")


def test_append_only_audit_chain_detects_modified_evidence(tmp_path):
    p = tmp_path / "ledger.sqlite3"
    store = EvidenceStore(p)
    store.append("decision", decision_preview("auto_execute"))
    store.append("decision", decision_preview("deny_limit"))
    assert store.verify()["verified"] is True
    with sqlite3.connect(p) as db:
        with pytest.raises(sqlite3.DatabaseError):
            db.execute("DELETE FROM events")
        db.execute("DROP TRIGGER no_update_events")
        db.execute("UPDATE events SET payload = ? WHERE id = 1", ('{"forged":true}',))
    assert store.verify()["verified"] is False


def test_demo_environment_strips_external_secrets_and_cannot_load_dotenv_values(tmp_path):
    env = safe_demo_env(tmp_path, {"RAZORPAY_KEY_SECRET": "secret", "KILO_API_KEY": "llm-secret",
                                   "PAARI_ENV": "prod-live", "PAARI_LIVE": "1",
                                   "PAARI_DATABASE_URL": "postgresql://prod-db/customer"})
    assert env["PAARI_ENV"] == "sandbox"
    assert env["PAARI_LIVE"] == "0"
    assert env["RAZORPAY_KEY_SECRET"] == ""
    assert env["KILO_API_KEY"] == ""
    assert env["PAARI_DATABASE_URL"] == ""


def test_launcher_refuses_unsafe_database_targets():
    for url in ["postgresql://db.example.org/customers", "postgresql://localhost/live",
                "sqlite:////tmp/production.sqlite3", "mysql://localhost/paari_demo"]:
        with pytest.raises(ValueError):
            guarded_database_url(url)
    assert guarded_database_url("postgresql+psycopg://paari:dev@127.0.0.1:5432/paari_demo")


def test_portal_csrf_and_policy_endpoints(tmp_path):
    token = "local-portal-test-token"
    app = create_app(tmp_path, demo_api_token=token)
    client = TestClient(app, base_url="http://127.0.0.1:8765")
    assert client.get("/").status_code == 404  # No frontend in backend edition
    assert client.post("/api/policy/auto_execute").status_code == 403
    assert client.post("/api/policy/auto_execute", headers={"x-paari-demo-token": token,
                         "origin": "https://attacker.example"}).status_code == 403
    reply = client.post("/api/policy/auto_execute", headers={"x-paari-demo-token": token})
    assert reply.status_code == 200, reply.text
    assert reply.json()["disposition"] == "AUTO_EXECUTE"
    assert client.get("/api/audit").json()["verification"]["verified"] is True


def test_structured_review_requires_authority_and_times_out(tmp_path):
    from local_demo.reviews import ReviewQueue
    store = EvidenceStore(tmp_path / "events.sqlite3")
    queue = ReviewQueue(tmp_path / "reviews.sqlite3", store, "reviewer-secret")
    r = queue.request("escalate")
    with pytest.raises(PermissionError):
        queue.resolve(r["id"], decision="approve", reviewer_code="wrong", reviewer="local-reviewer")
    resolved = queue.resolve(r["id"], decision="approve", reviewer_code="reviewer-secret", reviewer="local-reviewer")
    assert resolved["status"] == "approved_preview"
    with pytest.raises(ValueError):
        queue.resolve(r["id"], decision="approve", reviewer_code="reviewer-secret", reviewer="local-reviewer")
    assert store.verify()["verified"] is True
    with pytest.raises(ValueError):
        queue.request("deny_limit")


def test_reviewer_timeout_never_allows_payment(tmp_path):
    from local_demo.reviews import ReviewQueue
    from datetime import datetime, timedelta, timezone
    store = EvidenceStore(tmp_path / "events.sqlite3")
    queue = ReviewQueue(tmp_path / "reviews.sqlite3", store, "reviewer-secret")
    item = queue.request("escalate")
    with sqlite3.connect(tmp_path / "reviews.sqlite3") as db:
        db.execute("UPDATE reviews SET expires_at = ? WHERE id = ?",
                   ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), item["id"]))
    assert queue.resolve(item["id"], decision="approve", reviewer_code="reviewer-secret",
                         reviewer="local-reviewer")["status"] == "expired"
