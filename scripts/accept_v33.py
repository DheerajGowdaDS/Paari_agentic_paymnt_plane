"""v3.3 one-command local acceptance gate.

    python scripts/accept_v33.py                 # full local acceptance (PostgreSQL MANDATORY)
    python scripts/accept_v33.py --allow-skip-pg # downgraded: report PG skips, not failures

PostgreSQL is a MANDATORY part of full local acceptance. By default the gate
FAILS (exit 1) if the Postgres workflow / concurrency / crash-recovery /
strict-golden-flow / dashboard steps cannot run, because skipping them would let
an operator claim a "pass" for a platform whose persistent-payment guarantees
were never actually demonstrated on the primary database. `--allow-skip-pg`
explicitly downgrades the verdict to LOCAL_ACCEPTANCE_PASSED_WITH_POSTGRES_
SKIPPED so a genuinely-absent-infrastructure situation is labelled as such and
can never be mistaken for a full pass.

Mandatory steps (any failure -> RED, exit 1):
  1. compileall of the whole source tree (no syntax drift)
  2. offline SAFR verifier (policy + lifecycle + guided workflows)
  3. full SQLite test suite (Postgres-gated tests SKIP, not fail, on SQLite)
  4. v3.3 read-only `--verify` proof (no DDL/DML)
  5. Postgres-gated hardening tests (true concurrency, duplicate webhook,
     persist-across-rebuild, idempotent migrate, v3.2 fault injections,
     v3.3 identity evidence states)   [MANDATORY when PG is reachable]
  6. Postgres-first E2E (full signed-mandate settlement + 8-worker concurrency)
  7. actual-recovery E2E (kill the service mid-flight, re-boot, recover, no dup)
  8. strict SAFR Golden Payment Flow (AUTO_EXECUTE + two fail-closed gates)
  9. dashboard-driven operator workflow (API-backed, independently DB-verified)
  10. complete SAFR disposition coverage (AUTO_EXECUTE/OBSERVE/ESCALATE/DENY
      through the integrated runtime, incl. approval != spending authority)
  11. refund lifecycle E2E (PAID -> REFUNDED via the real refund endpoint,
      terminal, double-refund refused)

The gate prints LOCAL_ACCEPTANCE_PASSED only when every mandatory step passed.
When `--allow-skip-pg` is set and the Postgres steps are skipped, it instead
prints LOCAL_ACCEPTANCE_PASSED_WITH_POSTGRES_SKIPPED and still exits 0, but the
skipped steps are listed separately. Nothing here moves real money: every
settlement is the local provider simulator.
"""
from __future__ import annotations

import argparse
import os
import re
import socket
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
mandatory_pass: list[str] = []
pg_pass: list[str] = []
pg_skipped: list[str] = []


def _pg_available() -> bool:
    """True when a disposable Postgres test DB host is reachable. The harness only
    ever points at a database whose name ends in _test, so this cannot hit a live
    deployment; it reports whether Postgres is up."""
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
    m = re.search(r"/([a-z0-9_]+)$", PG_DSN)
    return bool(m and m.group(1).endswith(("_test", "_testing", "_pytest")))


def step(label: str, cmd: list[str], env: dict | None = None,
         success_marker: str | None = None, fail_marker: str | None = None,
         skip_when: bool = False) -> bool:
    """Run one gate step. `skip_when=True` downgrades a failed step to a recorded
    skip (used only for the optional Postgres steps under --allow-skip-pg).
    Otherwise any failure is a hard failure that blocks the verdict."""
    print(f"\n{'='*72}\n[STEP] {label}\n{'='*72}", flush=True)
    r = subprocess.run(cmd, cwd=ROOT, env=env or os.environ,
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    output = (r.stdout or "") + ("\nSTDERR:\n" + (r.stderr or "") if r.stderr else "")
    print(output[-4000:], flush=True)
    if fail_marker and fail_marker in output:
        ok = False
    elif success_marker is None:
        ok = (r.returncode == 0)
    else:
        # A success marker printed in the output is NOT, by itself, a pass.
        # The step must also exit 0. This closes the false-green defect where a
        # process that prints its "GREEN" banner and then crashes / exits
        # non-zero would otherwise be classified as passed.
        ok = (success_marker in output) and (r.returncode == 0)
    if ok:
        print(f"[OK] {label}", flush=True)
        if skip_when:
            pg_pass.append(label)
        else:
            mandatory_pass.append(label)
        return True
    if skip_when:
        print(f"[SKIP] {label} (not required in this environment)", flush=True)
        pg_skipped.append(label)
        return True
    print(f"[FAIL] {label}", flush=True)
    failures.append(label)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-skip-pg", action="store_true",
                        help="Downgrade PostgreSQL from mandatory to skippable. The verdict "
                             "becomes LOCAL_ACCEPTANCE_PASSED_WITH_POSTGRES_SKIPPED, not a full pass.")
    parser.add_argument("--no-pg", action="store_true",
                        help="Deprecated alias for --allow-skip-pg.")
    opts = parser.parse_args()
    allow_skip_pg = opts.allow_skip_pg or opts.no_pg

    # 1. compile the whole tree (mandatory)
    ok1 = step("compileall (whole source tree)",
               [sys.executable, "-m", "compileall", "-q", *COMPILABLE])
    if not ok1:
        print("\nPAARI v3.3 LOCAL ACCEPTANCE RED (compile).")
        return 1

    # 2. offline SAFR verifier (mandatory)
    ok2 = step("offline SAFR verifier (policy + lifecycle + guided workflows)",
               [sys.executable, "scripts/verify_local_demo.py"],
               success_marker="LOCAL DEMONSTRATION CHECKS PASSED")
    if not ok2:
        print("\nPAARI v3.3 LOCAL ACCEPTANCE RED (SAFR verifier).")
        return 1

    # 3. full SQLite suite (mandatory). Postgres-gated tests skip, not fail.
    ok3 = step("full test suite (mandatory core)",
               [sys.executable, "-m", "pytest", "-q"],
               success_marker="passed", fail_marker="failed")
    if not ok3:
        print("\nPAARI v3.3 LOCAL ACCEPTANCE RED (test suite).")
        return 1

    # 4. read-only --verify proof (mandatory, database-agnostic scratch target).
    ok4 = step("v3.3 read-only --verify proof (no DDL/DML)",
               [sys.executable, "-m", "pytest", "-q", "tests/test_v33_readonly_verify.py"],
               success_marker="passed", fail_marker="failed")
    if not ok4:
        print("\nPAARI v3.3 LOCAL ACCEPTANCE RED (read-only verify).")
        return 1

    pg_reachable = _pg_available() and _pg_test_db_ok()

    # PostgreSQL is MANDATORY for full local acceptance. If it is reachable, the
    # Postgres steps run and are mandatory. If it is NOT reachable, the outcome
    # depends on --allow-skip-pg:
    #   default          -> HARD FAILURE (full acceptance cannot be claimed)
    #   --allow-skip-pg  -> the steps are skipped and the verdict is downgraded
    if pg_reachable:
        pg_skip = False
        # 5. Postgres-gated hardening tests. TEST_DATABASE_URL opens the gate;
        #    fail_marker rejects a SQLite/skipped run instead of a false green.
        step("Postgres-gated hardening tests (concurrency + recovery + identity)",
             [sys.executable, "-m", "pytest", "-q",
              "tests/test_v32_pg_hardening.py",
              "tests/test_v31_resilience.py",
              "tests/test_v32_local_hardening.py",
              "tests/test_v33_identity_evidence_states.py"],
             env={**os.environ, "TEST_DATABASE_URL": PG_DSN},
             success_marker="passed", fail_marker="SKIPPED")
        # 6. Postgres-first E2E (full settlement + 8-worker concurrency)
        step("Postgres-first E2E (workflow + concurrency + duplicate webhook)",
             [sys.executable, "scripts/pg_e2e_workflow.py"],
             success_marker="POSTGRES-FIRST E2E GREEN")
        # 7. actual-recovery E2E (kill service mid-flight, re-boot, recover)
        step("actual-recovery E2E (service failure + durable recovery, no duplicate execution)",
             [sys.executable, "scripts/recovery_e2e.py"],
             success_marker="RECOVERY E2E GREEN")
        # 8. strict SAFR Golden Payment Flow (AUTO_EXECUTE + fail-closed gates)
        step("strict SAFR Golden Payment Flow (identity -> mandate -> envelope -> AUTO_EXECUTE -> PAID)",
             [sys.executable, "scripts/golden_flow_e2e.py"],
             success_marker="STRICT SAFR GOLDEN FLOW GREEN")
        # 9. dashboard-driven operator workflow (API-backed, independently DB-verified)
        step("dashboard-driven operator workflow (portal + independent Postgres proof)",
             [sys.executable, "scripts/dashboard_operator.py"],
             success_marker="DASHBOARD OPERATOR WORKFLOW GREEN")
        # 10. complete SAFR disposition coverage through the integrated runtime
        step("complete SAFR disposition coverage (AUTO/OBSERVE/ESCALATE/DENY + approval != authority)",
             [sys.executable, "scripts/safr_disposition_coverage.py"],
             success_marker="SAFR DISPOSITION COVERAGE GREEN")
        # 11. refund lifecycle E2E (PAID -> REFUNDED, terminal, double-refund refused)
        step("refund lifecycle E2E (PAID -> REFUNDED via the real refund endpoint, no double refund)",
             [sys.executable, "scripts/refund_chargeback_e2e.py"],
             success_marker="REFUND E2E GREEN")
    else:
        pg_skip = True
        why = ("PostgreSQL not reachable / no disposable _test DB. Full local "
               "acceptance requires Postgres; use --allow-skip-pg only to "
               "downgrade the verdict when the infrastructure is genuinely absent.")
        if allow_skip_pg:
            pg_skipped.append("postgres steps (workflow + concurrency + recovery + golden flow + dashboard)")
            print(f"\n[SKIP] {why} (--allow-skip-pg set: verdict downgraded)", flush=True)
        else:
            failures.append("postgresql-infrastructure (MANDATORY, not skipped)")
            print(f"\n[FAIL] {why} (PostgreSQL is MANDATORY for full local acceptance; "
                  f"pass --allow-skip-pg to explicitly downgrade)", flush=True)

    # ------------------------------------------------------------------
    print("\n" + "=" * 72, flush=True)
    print(" PAARI v3.3 LOCAL ACCEPTANCE", flush=True)
    print("=" * 72, flush=True)
    if failures:
        print(f"FAILURES: {', '.join(failures)}", flush=True)
        print("PAARI v3.3 LOCAL ACCEPTANCE FAILED", flush=True)
        return 1
    print(f"MANDATORY PASSED ({len(mandatory_pass)}): {', '.join(mandatory_pass)}", flush=True)
    if pg_pass:
        print(f"POSTGRES STEPS PASSED ({len(pg_pass)}): {', '.join(pg_pass)}", flush=True)
    if pg_skipped:
        print(f"POSTGRES STEPS SKIPPED (--allow-skip-pg): {', '.join(pg_skipped)}", flush=True)
        print("PAARI v3.3 LOCAL_ACCEPTANCE_PASSED_WITH_POSTGRES_SKIPPED (downgraded verdict)", flush=True)
        print("LOCAL SIMULATED CORE ONLY - PostgreSQL persistence NOT demonstrated this run.", flush=True)
        return 0
    print("PAARI v3.3 LOCAL_ACCEPTANCE_PASSED", flush=True)
    print("LOCAL SIMULATED PLATFORM ONLY - simulated provider, no real money.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
