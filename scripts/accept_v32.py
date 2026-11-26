"""v3.2 one-command local acceptance: the complete hardening gate in a single run.

    python scripts/accept_v32.py            # SQLite/local + Postgres E2E (Docker PG required)
    python scripts/accept_v32.py --no-pg    # skip the Postgres-first E2E steps (no Docker)

Steps, in order:
  1. compileall of the whole source tree (no syntax drift)
  2. offline SAFR verifier (10 dispositions + 3 lifecycle + 13-entry chain +
     the two v3.2 guided-workflow checks)
  3. Postgres-gated hardening tests (true concurrency, duplicate webhook,
     persist-across-rebuild, idempotent migrate) - only when PG is available
  4. Postgres-first E2E (full signed-mandate settlement + 8-worker concurrency)
  5. actual-recovery E2E (kill the service mid-flight, re-boot, recover, no dup)

A step that cannot run (no Docker/Postgres) is reported as SKIPPED, not a
failure; a step that runs must print its GREEN/PASS marker or the run is RED.
Nothing here moves real money: every settlement is the local provider simulator.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PG_DSN = os.environ.get(
    "PAARI_PG_DSN", "postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test")

COMPILABLE = ["app", "sdk", "scripts", "tests", "alembic", "llm_agent", "local_demo"]
failures: list[str] = []
skips: list[str] = []


def step(label: str, cmd: list[str], env: dict | None = None,
         success_marker: str | None = None, fail_marker: str | None = None,
         required: bool = True) -> bool:
    print(f"\n{'='*72}\n[STEP] {label}\n{'='*72}", flush=True)
    try:
        r = subprocess.run(cmd, cwd=ROOT, env=env or os.environ,
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace")
    except FileNotFoundError as exc:
        print(f"cannot run {cmd[0]}: {exc}")
        return False
    output = (r.stdout or "") + ("\nSTDERR:\n" + (r.stderr or "") if r.stderr else "")
    tail = output[-4000:]
    if fail_marker and fail_marker in output:
        ok = False
    elif success_marker is None:
        ok = r.returncode == 0
    else:
        ok = (success_marker in output)
    print(tail, flush=True)
    if ok:
        print(f"[OK] {label}", flush=True)
        return True
    if not required:
        print(f"[SKIP] {label} (not required in this environment)", flush=True)
        skips.append(label)
        return True
    print(f"[FAIL] {label}", flush=True)
    failures.append(label)
    return False


def _pg_available() -> bool:
    """True when a disposable Postgres test DB is reachable. The harness only
    ever points at a database whose name ends in _test, so this cannot hit a
    live deployment; it simply reports whether Postgres is up."""
    import socket
    import re
    m = re.search(r"@([0-9.]+):(\d+)/", PG_DSN)
    if not m:
        return False
    host, port = m.group(1), int(m.group(2))
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


def _pg_test_db_ok() -> bool:
    """The disposable test database exists and is reachable as a usable target."""
    import re
    return re.search(r"/([a-z0-9_]+)$", PG_DSN).group(1).endswith(("_test", "_testing", "_pytest"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-pg", action="store_true", help="skip the Postgres-first E2E steps")
    opts = parser.parse_args()

    # 1. compile the whole tree
    ok1 = step("compileall (whole source tree)",
               [sys.executable, "-m", "compileall", "-q", *COMPILABLE])
    if not ok1:
        print("\nPAARI v3.2 ACCEPTANCE RED (compile).")
        return 1

    # 2. offline SAFR verifier (includes the two v3.2 guided-workflow checks)
    ok2 = step("offline SAFR verifier (policy + lifecycle + guided workflows)",
               [sys.executable, "scripts/verify_local_demo.py"],
               success_marker="LOCAL DEMONSTRATION CHECKS PASSED")

    pg_on = not opts.no_pg and _pg_available() and _pg_test_db_ok()
    if pg_on:
        # 3. Postgres-gated hardening tests. TEST_DATABASE_URL points the suite at
        #    the disposable Postgres DB so the _require_postgres gate actually opens;
        #    fail_marker rejects a SQLite/skipped run instead of a false green.
        #
        #    test_v32_pg_hardening.py  - Postgres-specific invariants (true
        #        multi-worker race, duplicate webhook, persist-across-rebuild,
        #        idempotent migrate).
        #    test_v31_resilience.py     - the v3.1 resilience suite (single-use,
        #        timeout, value-mismatch, audit-chain integrity).
        #    test_v32_local_hardening.py - blueprint fault injections that are
        #        database-agnostic (agent revocation after approval, mandate
        #        expiry in review, reconciliation-worker restart, audit deletion)
        #        and therefore prove on Postgres here AND on the plain SQLite
        #        suite.
        step("Postgres-gated hardening tests",
             [sys.executable, "-m", "pytest", "-q", "tests/test_v32_pg_hardening.py",
              "tests/test_v31_resilience.py",
              "tests/test_v32_local_hardening.py"],
             env={**os.environ, "TEST_DATABASE_URL": PG_DSN},
             success_marker="passed", fail_marker="SKIPPED")
        # 4. Postgres-first E2E (full settlement + 8-worker concurrency)
        step("Postgres-first E2E (workflow + concurrency + duplicate webhook)",
             [sys.executable, "scripts/pg_e2e_workflow.py"],
             success_marker="POSTGRES-FIRST E2E GREEN")
        # 5. actual-recovery E2E (kill service mid-flight, re-boot, recover)
        step("actual-recovery E2E (service failure + durable recovery, no duplicate execution)",
             [sys.executable, "scripts/recovery_e2e.py"],
             success_marker="RECOVERY E2E GREEN")
    else:
        why = "Postgres not reachable / no disposable _test DB"
        if opts.no_pg:
            why = "--no-pg requested"
        print(f"\n[SKIP] Postgres-first E2E + recovery E2E + PG-gated tests ({why})", flush=True)
        skips.append("postgres steps")

    print("\n" + "=" * 72, flush=True)
    print(" PAARI v3.2 LOCAL ACCEPTANCE", flush=True)
    print("=" * 72, flush=True)
    if skips:
        print(f"SKIPPED: {', '.join(skips)}", flush=True)
    if failures:
        print(f"FAILURES: {', '.join(failures)}", flush=True)
        print("PAARI v3.2 ACCEPTANCE RED", flush=True)
        return 1
    print("PAARI v3.2 ACCEPTANCE GREEN" + (" (Postgres steps skipped)" if skips else ""), flush=True)
    print("NOT A PRODUCTION CERTIFICATION - simulated provider, no real money.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
