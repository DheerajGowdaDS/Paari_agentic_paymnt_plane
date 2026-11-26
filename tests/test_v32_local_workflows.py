"""v3.2 local full-workflow + human-escalation acceptance.

Locks the two new guided dashboard workflows (``POST /api/full_workflow`` and
``POST /api/escalation/simulate``) so a regression that silently drops a stage,
re-introduces a payment-authority leak, or lets the escalation state machine
accept a second resolve fails loudly. The expired-review and missing-authority
edge cases were already covered by tests/test_local_demo_v3.py; these tests add
the composed-workflow surface v3.2 introduced.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from local_demo.portal import create_app


def _client(tmp_path):
    token = "workflow-test-token"
    app = create_app(tmp_path, demo_api_token=token)
    client = TestClient(app, base_url="http://127.0.0.1:8765")
    return client, {"x-paari-demo-token": token}


def test_catalog_advertises_guided_workflows(tmp_path):
    client, _ = _client(tmp_path)
    cat = client.get("/api/catalog").json()
    assert {w["key"] for w in cat["workflows"]} == {"full_workflow", "escalation"}


def test_full_workflow_walks_all_stages_and_appends_audit(tmp_path):
    client, headers = _client(tmp_path)
    r = client.post("/api/full_workflow", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["outcome"] == "PASS" and body["all_passed"] is True
    stages = {s["stage"]: s["passed"] for s in body["stages"]}
    # The exact stage map the v3.2 plan calls for: onboarding -> mandate ->
    # governance (all four) -> execution/settlement -> audit proof.
    assert set(stages) == {
        "onboarding_and_signed_envelope", "governance_dispositions",
        "mandate_expiry_revocation_fail_closed", "execution_and_settlement_lifecycle",
        "audit_evidence"}, stages
    assert all(stages.values()), "every guided-workflow stage must pass"
    # No provider is ever executed by the guided flow.
    assert body["provider_executed"] is False and body["sandbox_only"] is True
    # It appended a verifiable audit event.
    audit = client.get("/api/audit").json()
    assert audit["verification"]["verified"] is True
    kinds = [rec["kind"] for rec in audit["records"]]
    assert "safr_full_workflow" in kinds


def test_escalation_simulate_covers_authority_and_fail_closed(tmp_path):
    client, headers = _client(tmp_path)
    r = client.post("/api/escalation/simulate", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    results = body["results"]
    assert results["missing_authority"]["status"] == "rejected"
    assert results["approved_preview"]["status"] == "approved_preview"
    assert results["approved_preview"]["provider_executed"] is False
    assert results["double_resolve"]["status"] == "refused"
    assert results["denied"]["status"] == "denied"
    assert body["all_passed"] is True and body["outcome"] == "PASS"
