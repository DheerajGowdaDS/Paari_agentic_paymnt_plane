"""Offline SAFR v3.1/v3.2 local-release verifier.

    python scripts/verify_local_demo.py             # fast policy/lifecycle/audit + guided workflows
    python scripts/verify_local_demo.py --full      # additionally run both real HTTP E2Es

The full E2Es run with cleared provider secrets and only local test services.
Do not interpret simulated PAID as transfer of real money.

The v3.2 additions (the guided dashboard workflows and the human-escalation
lifecycle) are verified in-process through the portal's own FastAPI routes - no
HTTP server and no provider - and use a separate evidence store so they do not
perturb the deterministic 13-entry (10 dispositions + 3 lifecycle) chain.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from local_demo.core import SCENARIOS, LIFECYCLE_DEMOS, EvidenceStore, decision_preview, lifecycle_preview  # noqa: E402
from local_demo.portal import E2E, safe_demo_env  # noqa: E402


def _verify_guided_workflows(home: Path) -> bool:
    """Drive the two v3.2 guided dashboard workflows through the portal's own
    FastAPI routes (in-process TestClient). Proves onboarding -> mandate -> all
    four governance outcomes -> execution/settlement -> audit, and the full
    human-escalation lifecycle (missing authority, single resolve, approve/deny,
    fail-closed), each appending a verifiable audit event."""
    from fastapi.testclient import TestClient
    from local_demo.portal import create_app

    token = "offline-backend-verifier-token"
    app = create_app(home, demo_api_token=token)
    client = TestClient(app, base_url="http://127.0.0.1:8765")
    headers = {"x-paari-demo-token": token}

    ok = True
    wf = client.post("/api/full_workflow", headers=headers)
    wf_ok = wf.status_code == 200 and wf.json().get("all_passed") is True
    ok = ok and wf_ok
    print(f"[{'PASS' if wf_ok else 'FAIL'}] full_workflow: guided SAFR workflow "
          f"{wf.json().get('outcome') if wf_ok else 'FAILED'} "
          f"({sum(1 for s in wf.json().get('stages', []) if s['passed'])}/{len(wf.json().get('stages', []))} stages)")

    esc = client.post("/api/escalation/simulate", headers=headers)
    esc_ok = esc.status_code == 200 and esc.json().get("all_passed") is True
    ok = ok and esc_ok
    good = sum(1 for v in esc.json().get("results", {}).values()
               if v.get("status") in ("rejected", "refused", "approved_preview", "denied"))
    total = len(esc.json().get("results", {}))
    print(f"[{'PASS' if esc_ok else 'FAIL'}] escalation_simulate: human-escalation lifecycle "
          f"{esc.json().get('outcome') if esc_ok else 'FAILED'} ({good}/{total} cases)")

    # Both guided runs append to the portal's own store; it must still verify.
    verdict = client.get("/api/audit").json()["verification"]
    audit_ok = verdict["verified"] is True
    ok = ok and audit_ok
    print(f"[{'PASS' if audit_ok else 'FAIL'}] guided-workflow audit chain: {verdict['entries']} verified entries")
    return ok


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true", help="additionally run both real HTTP E2Es (2-4 minutes)")
    opts = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="paari_v3_check_") as p:
        store = EvidenceStore(Path(p)/"checks.sqlite3")
        for name in SCENARIOS:
            result = decision_preview(name)
            if result["disposition"] != result["expected"]:
                print(f"[FAIL] {name} returned unexpected disposition {result['disposition']}")
                return 1
            if result["envelope_verified"] == (name == "deny_signature"):
                print(f"[FAIL] {name} signature/origin assertion wrong")
                return 1
            store.append("safr_policy_preview", result)
            print(f"[PASS] {name}: {result['disposition']} {','.join(result['reason_codes'])}")
        for name in LIFECYCLE_DEMOS:
            result = lifecycle_preview(name)
            if result["outcome"] != "PASS" or result["passed"] is not True:
                print(f"[FAIL] {name} lifecycle demo did not reach expected outcome {result['expected']}")
                return 1
            store.append("safr_lifecycle_demo", result)
            print(f"[PASS] {name}: lifecycle demo {result['expected']} ({result['outcome']})")
        audit = store.verify()
        expected_entries = len(SCENARIOS) + len(LIFECYCLE_DEMOS)
        if not audit["verified"] or audit["entries"] != expected_entries:
            print(f"[FAIL] Audit chain {audit} (expected {expected_entries})")
            return 1
        print(f"[PASS] SAFR audit chain: {audit['entries']} verified entries")

        # v3.2: the two guided dashboard workflows, in their own store so the
        # deterministic 13-entry chain above is untouched.
        guide_home = Path(p) / "guided"
        if not _verify_guided_workflows(guide_home):
            return 1

        if opts.full:
            for name, spec in E2E.items():
                print(f"[RUN] {name} — local simulated provider; no real money", flush=True)
                cmd = [sys.executable, *spec["command"]]
                try:
                    r = subprocess.run(cmd, cwd=ROOT, env=safe_demo_env(Path(p)),
                                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=240)
                except subprocess.TimeoutExpired:
                    print(f"[FAIL] {name}: timed out")
                    return 1
                output = (r.stdout or "") + (r.stderr or "")
                if r.returncode or "[FAIL]" in output or "ABORT:" in output or "PAID" not in output or "PASS" not in output:
                    print(f"[FAIL] {name}: exit={r.returncode}\n{output[-2000:]}")
                    return 1
                print(f"[PASS] {name}: provider E2E reached simulated PAID with controls")
    print("PAARI v3.2 LOCAL DEMONSTRATION CHECKS PASSED — NOT A PRODUCTION CERTIFICATION")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
