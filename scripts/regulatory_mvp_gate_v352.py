"""Fail-closed Paari v3.5.2 local regulator-facing MVP acceptance gate.

This script deliberately refuses to promote a green unit-test run into a
verified strict live MVP. The mandatory Level-A gates are (1) all C01-C14
explicit tests, (2) focused security regressions, (3) disposable PostgreSQL
plus real HTTP/provider/recovery suite, (4) one externally observed strict
reviewed-intent transaction with signed SAFR envelope, provider reconciliation,
receiver signed acknowledgement and recomputed audit chain.

No bank credit or real-money claim is made. Exit 0 only when all mandatory gates
PASS. Missing infrastructure, skipped tests, expected failures, absent live
transaction and timeouts always yield NO-GO, exit 2.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_CASE_IDS = tuple(f"C{i:02d}" for i in range(1, 15))
TARGETED = [
    "tests/test_e2e_mvp_acceptance.py",
    "tests/test_v35_regulatory_review.py",
    "tests/test_v35_independent_receiver_sandbox.py",
    "tests/test_v35_receiver_http_process.py",
    "tests/test_v35_federated_governance.py",
    "tests/test_v34_receivers.py",
    "tests/test_v33_acceptance_integrity.py",
    "tests/test_control_plane_engine.py",
    "tests/test_audit.py",
    "tests/test_webhook_value_guard.py",
    "tests/test_webhook_org_isolation.py",
    "tests/test_transitions.py",
]


def examine_junit(xml_file: Path) -> dict:
    """Reject every mandatory missing/skipped/xfail case irrespective of pytest RC."""
    tree = ET.parse(xml_file)
    tests = tree.findall(".//testcase")
    found = {}
    for test in tests:
        name = test.attrib.get("name", "")
        for cid in REQUIRED_CASE_IDS:
            if name.startswith(f"test_{cid.lower()}_"):
                found.setdefault(cid, []).append(test)
    checks = {}
    for cid in REQUIRED_CASE_IDS:
        rows = found.get(cid, [])
        checks[cid] = (len(rows) == 1 and
                       not any(row.find(tag) is not None for row in rows for tag in ("failure", "error", "skipped")))
    all_unskipped = all(not any(t.find(tag) is not None for tag in ("skipped", "failure", "error"))
                        for t in tests)
    return {"cases": checks, "required_case_count": len(found),
            "all_targets_unskipped_and_passing": all_unskipped,
            "testcase_count": len(tests),
            "status": "PASS" if all(checks.values()) and all_unskipped and len(tests) else "FAIL"}


def run_cmd(cmd: list[str], *, timeout: int = 300, env=None) -> dict:
    try:
        result = subprocess.run(cmd, cwd=ROOT, env=env or os.environ.copy(),
                                capture_output=True, text=True, timeout=timeout,
                                encoding="utf-8", errors="replace")
        return {"status": "PASS" if result.returncode == 0 else "FAIL",
                "return_code": result.returncode, "output_tail":
                (result.stdout + "\n" + result.stderr)[-3000:]}
    except subprocess.TimeoutExpired:
        return {"status": "FAIL", "reason": "Timed out; no acceptance evidence"}


def _live_evidence(base: str, org: str, key: str, intent_id: str) -> dict:
    import httpx
    parsed = urlsplit(base)
    if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        return {"status": "FAIL", "reason": "Only loopback local runtime is supported by this acceptance gate"}
    headers = {"X-Paari-Org": org, "X-Paari-Control-Key": key}
    try:
        with httpx.Client(timeout=12, follow_redirects=False, trust_env=False) as client:
            er = client.get(base.rstrip("/")+"/control/v1/receivers/payment-evidence/"+intent_id, headers=headers)
            er.raise_for_status()
            cr = client.get(base.rstrip("/")+"/control/v1/federation/contexts/"+intent_id, headers=headers)
            cr.raise_for_status()
            e, c = er.json(), cr.json()
    except Exception as exc:
        return {"status": "FAIL", "reason": str(exc)[:300]}
    audit = e.get("audit_events") or []
    kinds = {record.get("kind") for record in audit}
    review = e.get("human_review") or {}
    auth = e.get("authorization") or {}
    provider = e.get("provider") or {}
    checks = {
        "tenant_bound": e.get("org_id") == org,
        "signed_context_valid": c.get("signature_valid") is True,
        "context_not_spendable": (c.get("payload") or {}).get("execution_authority") is False,
        "reviewer_signed_approval": review.get("status") == "APPROVED" and "human_review_approved" in kinds,
        "fresh_safr_envelope_consumed": "safr_envelope_consumed_for_execution" in kinds,
        "single_use_auth": auth.get("usage_count") == 1 and auth.get("max_usage") == 1,
        "provider_reconciled_paid": provider.get("state") == "PAID" and bool(provider.get("reconciled_at")),
        "receiver_signed_ack_evidence": bool(e.get("receiver_attestations")),
        "audit_chain_verified": e.get("audit_chain_valid") is True,
    }
    return {"status": "PASS" if all(checks.values()) else "FAIL", "checks": checks,
            "receiver_credit_proven": False,
            "note": "A signed acceptance is not independently proven beneficiary credit"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", default="docs/REGULATORY_MVP_GATE_V352.json")
    parser.add_argument("--with-postgres", action="store_true")
    parser.add_argument("--quick", action="store_true", help="Fast targeted diagnostic only; never yields a verified release verdict")
    parser.add_argument("--paari-url")
    parser.add_argument("--intent-id")
    parser.add_argument("--org")
    args = parser.parse_args()
    report = {"release": "Paari v3.5.2 MVP hardening",
              "created_at_utc": datetime.now(timezone.utc).isoformat(),
              "level": "A_LOCAL_SIMULATED", "live_money_tested": False,
              "beneficiary_credit_independently_verified": False,
              "gates": {}}
    with tempfile.TemporaryDirectory(prefix="paari_regulatory_gate_") as temp:
        junit = Path(temp)/"pytest.xml"
        chosen = (["tests/test_e2e_mvp_acceptance.py",
                   "tests/test_v35_regulatory_review.py",
                   "tests/test_v35_independent_receiver_sandbox.py",
                   "tests/test_v35_receiver_http_process.py",
                   "tests/test_v352_acceptance_gate_integrity.py"] if args.quick else TARGETED)
        test_run = run_cmd([sys.executable, "-m", "pytest", *chosen,
                            "--maxfail=1", "-q", "--disable-warnings",
                            f"--junitxml={junit}"], timeout=140 if args.quick else 330)
        if junit.exists():
            quality = examine_junit(junit)
            quality["pytest_return_code"] = test_run.get("return_code")
            if test_run["status"] != "PASS": quality["status"] = "FAIL"
            quality["output_tail"] = test_run.get("output_tail", "")[-1100:]
        else:
            quality = {"status": "FAIL", "reason": "No JUnit artifact", "output_tail": test_run.get("output_tail")}
        report["gates"]["explicit_e2e_and_security"] = quality
    report["gates"]["comprehensive_security_regressions"] = (
        {"status": "PENDING", "reason": "Quick diagnostic excludes full required security matrix"}
        if args.quick else {"status": quality["status"], "reason": "Full selected security matrix"})
    if args.with_postgres:
        dsn = os.getenv("PAARI_PG_DSN", "")
        # A live database cannot ever be used as a target for destructive tests.
        from app.database import assert_disposable_database_url
        if not dsn:
            report["gates"]["postgres_provider_recovery"] = {"status": "FAIL", "reason": "PAARI_PG_DSN missing"}
        else:
            try:
                assert_disposable_database_url(dsn, "Regulatory acceptance Postgres reset")
                env = os.environ.copy();env["PAARI_PG_DSN"] = dsn
                report["gates"]["postgres_provider_recovery"] = run_cmd(
                    [sys.executable, "scripts/accept_v33.py"], timeout=1000, env=env)
            except Exception as exc:
                report["gates"]["postgres_provider_recovery"] = {"status": "FAIL", "reason": str(exc)[:300]}
    else:
        report["gates"]["postgres_provider_recovery"] = {"status": "PENDING", "reason": "Run with --with-postgres and a disposable PAARI_PG_DSN"}
    if all((args.paari_url, args.intent_id, args.org, os.getenv("PAARI_ORG_CONTROL_KEY"))):
        report["gates"]["strict_reviewed_payment_http_evidence"] = _live_evidence(
            args.paari_url, args.org, os.environ["PAARI_ORG_CONTROL_KEY"], args.intent_id)
    else:
        report["gates"]["strict_reviewed_payment_http_evidence"] = {
            "status": "PENDING", "reason": "Provide --paari-url --intent-id --org and PAARI_ORG_CONTROL_KEY for actual strict reviewed payment proof"}
    report["gates"]["uninterrupted_strict_federated_http_journey"] = {
        "status": "PENDING",
        "reason": "Requires one fresh independent HTTP sequence: source agent and user signatures, three-party agreements, SAFR reviewed release, actual provider capture/reconcile, separate receiver process, PG and verified audit without direct DB intervention. No verified composite runner exists in this package."
    }
    report["gates"]["independent_beneficiary_credit"] = {
        "status": "NOT_CLAIMED", "reason": "Level B requires independent beneficiary ledger/chain finality; not in Level A"}
    report["level_a_verified"] = all(report["gates"][k]["status"] == "PASS" for k in
                                     ("explicit_e2e_and_security", "comprehensive_security_regressions", "postgres_provider_recovery", "strict_reviewed_payment_http_evidence", "uninterrupted_strict_federated_http_journey"))
    report["verdict"] = "LEVEL_A_LOCAL_MVP_VERIFIED" if report["level_a_verified"] else "LOCAL_MVP_NOT_YET_VERIFIED"
    target = (ROOT/args.report).resolve() if not Path(args.report).is_absolute() else Path(args.report)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(json.dumps({"verdict": report["verdict"],
                      "gates": {k:v["status"] for k,v in report["gates"].items()},
                      "report": str(target)}, indent=2))
    return 0 if report["level_a_verified"] else 2


if __name__ == "__main__":
    sys.exit(main())
