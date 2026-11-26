"""v3.3 complete acceptance pipeline: run the full gate + E2E harnesses and
capture exit codes, log tails, and transaction evidence into one report.

This is the "execute the complete acceptance pipeline on the exact packaged
release" deliverable. It runs, in sequence:

    1. scripts/accept_v33.py            (full local acceptance gate; PostgreSQL
                                         is mandatory for a full pass)
    2. scripts/pg_e2e_workflow.py       (Postgres-first settlement + concurrency
                                         + duplicate webhook)
    3. scripts/recovery_e2e.py         (kill the service mid-flight, recover,
                                         no duplicate execution)

and writes a machine-readable report (JSON) plus a human summary that records,
for EACH step: the command, its exit code, a bounded tail of its combined
stdout/stderr, and the step-specific verdict marker. After the pipeline it
reads the persistent Postgres database once to capture concrete transaction
evidence (the last settled PAID transaction, its order id, audit chain status,
and the provider provenance), so a reviewer can see the actual settled rows
rather than trusting a printed banner.

Nothing here moves real money: every settlement is the local provider simulator.
The pipeline is only meaningful when PostgreSQL is reachable; it REFUSES to
fake a green on a SQLite-only environment.

    python scripts/accept_v33_pipeline.py
    python scripts/accept_v33_pipeline.py --report-dir .agnes/work/acceptance_v33
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PG_DSN = os.environ.get(
    "PAARI_PG_DSN", "postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test")

_LOG_TAIL = 2000  # bounded tail of each step's output kept in the report


def _pg_available() -> bool:
    m = re.search(r"@([0-9.]+):(\d+)/", PG_DSN)
    if not m:
        return False
    host, port = m.group(1), int(m.group(2))
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


def _run_step(name: str, cmd: list[str], env: dict | None = None,
              verdict_marker: str | None = None) -> dict:
    print(f"\n{'='*72}\n[PIPELINE STEP] {name}\n  $ {' '.join(cmd)}\n{'='*72}", flush=True)
    start = time.time()
    proc = subprocess.run(cmd, cwd=ROOT, env=env or os.environ,
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace")
    elapsed = round(time.time() - start, 2)
    combined = (proc.stdout or "") + ("\n[STDERR]\n" + proc.stderr if proc.stderr else "")
    tail = combined[-_LOG_TAIL:]
    if verdict_marker:
        # Boundary-aware match: the marker must not be a *prefix* of a longer
        # token. This closes the substring false-green where the downgraded
        # verdict "LOCAL_ACCEPTANCE_PASSED_WITH_POSTGRES_SKIPPED" would
        # otherwise satisfy the marker "LOCAL_ACCEPTANCE_PASSED".
        pat = r"(?<!\w)" + re.escape(verdict_marker) + r"(?!\w)"
        marker_ok = re.search(pat, combined) is not None
    else:
        marker_ok = (proc.returncode == 0)
    # A step only PASSES when the marker is present AND the process exited 0.
    passed = marker_ok and (proc.returncode == 0)
    step = {
        "name": name,
        "command": cmd,
        "exit_code": proc.returncode,
        "elapsed_seconds": elapsed,
        "verdict_marker": verdict_marker,
        "verdict_marker_found": marker_ok,
        "passed": passed,
        "log_tail": tail,
    }
    print(tail, flush=True)
    print(f"[{'OK' if passed else 'FAIL'}] {name} -> exit={proc.returncode}, "
          f"marker={'found' if marker_ok else 'missing'}, {elapsed}s", flush=True)
    return step


def _transaction_evidence() -> dict:
    """Read the persistent DB once and capture concrete settled-transaction proof.

    `transaction_id` lives on `payment_intents` (the governance row); the
    provider settlement row is `provider_transactions` (keyed by `intent_id`).
    The two are joined on `intent_id` so the evidence carries the transaction
    id without referencing a column that does not exist on either table.
    """
    try:
        import psycopg
        pg_url = PG_DSN.replace("postgresql+psycopg://", "postgresql://", 1)
        conn = psycopg.connect(pg_url)
        cur = conn.cursor()
        cur.execute(
            "SELECT pt.authorization_id, pi.transaction_id, pt.state, pt.razorpay_order_id, "
            "pt.provider_environment FROM provider_transactions pt "
            "JOIN payment_intents pi ON pi.intent_id = pt.intent_id "
            "WHERE pt.state='PAID' ORDER BY pt.updated_at DESC LIMIT 5")
        paid = [dict(zip(["authorization_id", "transaction_id", "state", "order_id", "provider_environment"], r))
                for r in cur.fetchall()]
        cur.execute("SELECT count(*) AS c FROM provider_transactions")
        txn_total = cur.fetchone()[0]
        cur.execute("SELECT count(*) AS c FROM audit_events")
        audit_total = cur.fetchone()[0]
        conn.close()
        # Verify the newest paid transaction's audit chain with the app's own verifier.
        chain_ok = None
        if paid:
            from app.database import get_engine
            from sqlalchemy.orm import sessionmaker
            from app.audit import verify_chain
            eng = get_engine(PG_DSN)
            s = sessionmaker(bind=eng)()
            try:
                chain_ok = verify_chain(s, paid[0]["transaction_id"])
            finally:
                s.close()
                eng.dispose()
        return {"paid_transactions": paid, "provider_transaction_rows": txn_total,
                "audit_event_rows": audit_total,
                "latest_paid_audit_chain_verified": chain_ok,
                "provider_environment": (paid[0]["provider_environment"] if paid else None),
                "ok": True}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "ok": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", default=str(ROOT / ".agnes" / "work" / "acceptance_v33"),
                        help="Where to write the pipeline report JSON + summary")
    parser.add_argument("--allow-skip-pg", action="store_true",
                        help="Pass through to accept_v33 so a missing Postgres downgrades "
                             "the gate verdict instead of failing the pipeline")
    opts = parser.parse_args()
    report_dir = Path(opts.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    pg_on = _pg_available()
    print(f"[pipeline] PostgreSQL reachable: {pg_on} (DSN: {PG_DSN.split('@')[-1] if '@' in PG_DSN else PG_DSN})", flush=True)

    steps: list[dict] = []

    # 1. The full acceptance gate. PostgreSQL is mandatory for a FULL pass; the
    #    --allow-skip-pg flag (user choice) downgrades it to a skipped verdict.
    accept_cmd = [sys.executable, "scripts/accept_v33.py"]
    if opts.allow_skip_pg:
        accept_cmd.append("--allow-skip-pg")
    steps.append(_run_step("accept_v33 (full local acceptance gate)", accept_cmd,
                           verdict_marker="LOCAL_ACCEPTANCE_PASSED"))

    # 2 + 3. The dedicated Postgres E2E harnesses (only meaningful with PG up).
    if pg_on:
        env_pg = {**os.environ, "PAARI_PG_DSN": PG_DSN}
        steps.append(_run_step("pg_e2e_workflow (Postgres settlement + concurrency + duplicate webhook)",
                               [sys.executable, "scripts/pg_e2e_workflow.py"], env=env_pg,
                               verdict_marker="POSTGRES-FIRST E2E GREEN"))
        steps.append(_run_step("recovery_e2e (service crash + durable recovery, no duplicate execution)",
                               [sys.executable, "scripts/recovery_e2e.py"], env=env_pg,
                               verdict_marker="RECOVERY E2E GREEN"))
    else:
        reason = ("PostgreSQL is not reachable. Full local acceptance requires Postgres; "
                  "this pipeline cannot demonstrate persistence/concurrency/recovery. "
                  "Start the Postgres service (docker-compose.local.yml) and re-run, or "
                  "pass --allow-skip-pg to record a downgraded acceptance verdict.")
        print(f"\n[SKIP] Postgres E2E steps - {reason}", flush=True)
        for name in ("pg_e2e_workflow", "recovery_e2e"):
            steps.append({"name": name, "exit_code": None, "skipped": True,
                          "reason": reason, "passed": False})

    evidence = _transaction_evidence() if pg_on else {"skipped": "PostgreSQL not reachable"}

    # A GREEN pipeline verdict requires BOTH all steps passing AND valid
    # transaction evidence when PostgreSQL is reachable. Missing/broken DB
    # evidence must not be silently ignored: it means the persistent-payment
    # guarantee was not actually demonstrated, so the pipeline fails.
    evidence_ok = (not pg_on) or (isinstance(evidence, dict) and evidence.get("ok") is True
                                  and not evidence.get("error"))
    passed = all(s.get("passed") for s in steps) and pg_on and evidence_ok
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "postgres_dsn": PG_DSN.split("@")[-1] if "@" in PG_DSN else PG_DSN,
        "postgres_reachable": pg_on,
        "evidence_ok": evidence_ok,
        "steps": steps,
        "transaction_evidence": evidence,
        "pipeline_green": passed,
    }
    json_path = report_dir / "acceptance_v33_report.json"
    json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    _write_summary(report, report_dir / "acceptance_v33_summary.md")

    print("\n" + "=" * 72, flush=True)
    print(" PAARI v3.3 ACCEPTANCE PIPELINE", flush=True)
    print("=" * 72, flush=True)
    for s in steps:
        state = "skipped" if s.get("skipped") else ("PASS" if s.get("passed") else "FAIL")
        print(f"  [{state}] {s['name']} (exit={s.get('exit_code')})", flush=True)
    ev_state = ("ok" if evidence_ok else ("not required" if not pg_on else "FAILED/missing"))
    print(f"TRANSACTION EVIDENCE {ev_state}" + (f" ({evidence.get('error')})" if (isinstance(evidence, dict) and evidence.get("error")) else ""), flush=True)
    print(f"REPORT     {json_path}", flush=True)
    if passed:
        print("PIPELINE GREEN - full local acceptance incl. PostgreSQL + crash recovery + valid DB evidence", flush=True)
        return 0
    reasons = []
    if any(not s.get("passed") for s in steps):
        reasons.append("failing steps")
    if not pg_on:
        reasons.append("PostgreSQL not reachable")
    if not evidence_ok:
        reasons.append("transaction evidence missing/invalid")
    print(f"PIPELINE RED - {', '.join(reasons) or 'see the report'}", flush=True)
    return 1


def _write_summary(report: dict, path: Path) -> None:
    lines = ["# Paari v3.3 Acceptance Pipeline Report", ""]
    lines.append(f"- Generated: {report['generated_at']}")
    lines.append(f"- PostgreSQL: {report['postgres_dsn']} (reachable: {report['postgres_reachable']})")
    lines.append(f"- Pipeline verdict: **{'GREEN' if report['pipeline_green'] else 'RED'}**")
    lines.append("")
    lines.append("## Steps")
    for s in report["steps"]:
        if s.get("skipped"):
            lines.append(f"- **{s['name']}** - SKIPPED: {s.get('reason')}")
        else:
            lines.append(f"- **{s['name']}** - {'PASS' if s.get('passed') else 'FAIL'} "
                         f"(exit={s.get('exit_code')}, {s.get('elapsed_seconds')}s, "
                         f"marker '{s.get('verdict_marker')}' "
                         f"{'found' if s.get('verdict_marker_found') else 'missing'})")
    lines.append("")
    lines.append("## Transaction evidence (read from the persistent database)")
    ev = report["transaction_evidence"]
    if ev.get("skipped"):
        lines.append(f"- {ev['skipped']}")
    elif ev.get("error"):
        lines.append(f"- evidence read failed: {ev['error']}")
    else:
        lines.append(f"- provider_transaction rows: {ev.get('provider_transaction_rows')}")
        lines.append(f"- audit_event rows: {ev.get('audit_event_rows')}")
        lines.append(f"- latest PAID settlement provenance: "
                     f"{ev.get('provider_environment')} (simulated, no real money)")
        for t in ev.get("paid_transactions", [])[:5]:
            lines.append(f"  - PAID {t.get('transaction_id')} order={t.get('order_id')} "
                         f"auth={str(t.get('authorization_id'))[:8]}")
        lines.append(f"- latest PAID audit chain verified: {ev.get('latest_paid_audit_chain_verified')}")
    lines.append("")
    lines.append("> Every settlement above is the local provider simulator; no real money moved.")
    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
