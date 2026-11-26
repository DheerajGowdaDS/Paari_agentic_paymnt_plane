"""v3.3 dashboard-driven operator workflow, independently verified.

Proves the blueprint's "integrated Paari Control Center" requirement in its
strongest, least-trust form:

    * one operator action (a single POST to the portal's /api/operator/
      golden_flow endpoint, authenticated exactly the way the browser is)
      drives a COMPLETE payment through the persistent backend + the local
      provider simulator, AND
    * the harness then DISCONNECTS from the portal and independently reads the
      persistent Postgres database to confirm the portal's self-report:
      the provider transaction really is PAID, the payment intent really
      exists, the audit chain really verifies, and no disconnected preview
      record or hardcoded success flag is involved.

If the portal reported PAID but the database did not, this harness fails.
That is precisely the guard against "hardcoded success responses or
disconnected preview records". No real money moves; settlement is the local
simulator.

    python scripts/dashboard_operator.py
    PAARI_PG_DSN=postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test \
        python scripts/dashboard_operator.py
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sdk"))

import httpx  # noqa: E402

AMOUNT = 50_000  # must match the portal's operator golden-flow amount
failures: list[str] = []


def check(name: str, ok: bool, evidence) -> bool:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {json.dumps(evidence, default=str)[:300]}", flush=True)
    if not ok:
        failures.append(name)
    return ok


def _require_disposable_dsn(dsn: str) -> None:
    from app.database import assert_disposable_database_url
    assert_disposable_database_url(dsn, "run the v3.3 dashboard operator workflow")
    print(f"[note] Postgres target: {dsn.split('@')[-1] if '@' in dsn else dsn}", flush=True)


def _reset_public_schema(dsn: str) -> None:
    import psycopg
    raw = dsn.replace("postgresql+psycopg://", "postgresql://", 1)
    conn = psycopg.connect(raw)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE")
            cur.execute("CREATE SCHEMA public")
    finally:
        conn.close()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def start_backend(dsn: str, stub_base: str) -> tuple[str, list[subprocess.Popen], Path, str]:
    """Start the stub provider and a persistent Postgres backend (standard mode,
    signed mandate required - the local golden posture). Returns
    (base_url, processes, sign_key, admin_key)."""
    processes: list[subprocess.Popen] = []
    admin_key = "local-v33-op-" + uuid.uuid4().hex[:24]
    sign_key = ROOT / "_tmp_dash_op_signing_key.pem"
    if sign_key.exists():
        sign_key.unlink()
    env = {**os.environ,
           "PAARI_ENV": "sandbox", "PAARI_LIVE": "0", "PAARI_MODE": "standard",
           "PAARI_CONTROL_PLANE_ENFORCEMENT": "0",
           "PAARI_REQUIRE_SIGNED_MANDATE": "1", "PAARI_REQUIRE_SAFR_ENVELOPE": "0",
           "PAARI_ADMIN_API_KEY": admin_key, "PAARI_SIGNING_KEY_PATH": str(sign_key),
           "PAARI_SIGNING_BACKEND": "local_pem", "PAARI_AGENTIC_PROVIDER": "",
           "RAZORPAY_KEY_ID": "rzp_test_SIM_<REDACTED>", "RAZORPAY_KEY_SECRET": "simulated-secret",
           "RAZORPAY_WEBHOOK_SECRET": "stub_webhook_secret", "RAZORPAY_API_BASE": stub_base,
           "DATABASE_URL": dsn, "ALEMBIC_URL": dsn, "PAARI_DATABASE_URL": dsn,
           "PYTHONIOENCODING": "utf-8"}
    migrated = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"],
                              cwd=ROOT, env=env, capture_output=True, text=True)
    if migrated.returncode != 0:
        for p in processes:
            p.terminate()
        sys.exit(f"ABORT: alembic upgrade head failed\n{(migrated.stderr or '')[-1200:]}")
    server_port = _free_port()
    processes.append(subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
         "--port", str(server_port)], cwd=ROOT, env=env))
    base_url = f"http://127.0.0.1:{server_port}"
    deadline = time.time() + 45
    while time.time() < deadline:
        try:
            health = httpx.get(f"{base_url}/health", timeout=2)
            if health.status_code == 200 and health.json().get("database") == "up":
                return base_url, processes, sign_key, admin_key
        except httpx.HTTPError:
            pass
        time.sleep(1)
    for p in processes:
        p.terminate()
    sys.exit(f"ABORT: backend never became healthy at {base_url}")


def start_portal(home: Path, backend_url: str, stub_base: str, admin_key: str) -> tuple[str, int, None]:
    """Run the portal in a background thread on a free loopback port, wired to the
    live backend + stub so the operator flow is fully API-backed."""
    import uvicorn
    from local_demo.portal import create_app
    app = create_app(home, backend_url=backend_url,
                     provider_stub_base=stub_base, admin_api_key=admin_key,
                     reviewer_code=uuid.uuid4().hex[:12],
                     demo_api_token=os.environ["PAARI_DEMO_API_TOKEN"])
    portal_port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=portal_port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    portal_url = f"http://127.0.0.1:{portal_port}"
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            if httpx.get(portal_url + "/api/status", timeout=2).status_code == 200:
                return portal_url, portal_port, server
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    sys.exit("ABORT: portal never became reachable")


def main() -> int:
    dsn = os.environ.get("PAARI_PG_DSN",
                         "postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test")
    if not dsn.startswith("postgresql"):
        sys.exit("ABORT: PAARI_PG_DSN must be a PostgreSQL URL (the operator proof is Postgres-backed).")
    _require_disposable_dsn(dsn)
    _reset_public_schema(dsn)

    stub_port = _free_port()
    stub_base = f"http://127.0.0.1:{stub_port}/v1"
    stub_proc = subprocess.Popen([sys.executable, str(ROOT / "scripts" / "stub_razorpay.py"), str(stub_port)],
                                 cwd=ROOT)
    processes: list[subprocess.Popen] = []
    sign_key = Path("")
    server = None
    home = ROOT / ".agnes" / "work" / "dash_op_home"
    home.mkdir(parents=True, exist_ok=True)
    try:
        backend_url, processes, sign_key, admin_key = start_backend(dsn, stub_base)
        check("0. persistent Postgres backend healthy", True, {"backend": backend_url})

        api_token = uuid.uuid4().hex + uuid.uuid4().hex
        os.environ["PAARI_DEMO_API_TOKEN"] = api_token
        portal_url, portal_port, server = start_portal(home, backend_url, stub_base, admin_key)
        check("1. portal up and wired to the live backend + simulator", True, {"portal": portal_url})

        # Exercise the API directly using a privately provisioned operator token.
        csrf = api_token

        r = httpx.post(portal_url + "/api/operator/golden_flow",
                       headers={"x-paari-demo-token": csrf}, timeout=90)
        if r.status_code != 200:
            sys.exit(f"ABORT: operator golden flow returned HTTP {r.status_code}: {r.text[:300]}")
        portal_report = r.json()
        txn = portal_report["transaction_id"]
        auth_id = portal_report["authorization_id"]
        check("2. portal operator workflow completed (live API, no preview records)",
              portal_report.get("reconcile_state") in ("PAID", "terminal"),
              {"transaction_id": txn, "decision": portal_report.get("decision"),
               "reconcile_state": portal_report.get("reconcile_state"),
               "settlement_source": portal_report.get("settlement_source")})

        # NOW disconnect from the portal and independently verify against Postgres.
        import psycopg
        pg_url = dsn.replace("postgresql+psycopg://", "postgresql://", 1)
        conn = psycopg.connect(pg_url)
        cur = conn.cursor()
        cur.execute("SELECT state, razorpay_order_id FROM provider_transactions WHERE authorization_id=%s",
                    (auth_id,))
        row = cur.fetchone()
        cur.execute("SELECT count(*) FROM payment_intents WHERE transaction_id=%s", (txn,))
        intent_rows = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM audit_events WHERE transaction_id=%s", (txn,))
        audit_rows = cur.fetchone()[0]
        conn.close()

        check("3. independent Postgres proof: provider transaction really is PAID",
              row is not None and row[0] == "PAID" and row[1],
              {"state": row[0] if row else None, "order_id": row[1] if row else None})
        check("4. independent Postgres proof: the intent + audit trail are persisted",
              intent_rows >= 1 and audit_rows >= 1,
              {"payment_intents": intent_rows, "audit_events": audit_rows})

        # Verify the hash chain with the app's own verifier (not a string match).
        from app.database import get_engine
        from sqlalchemy.orm import sessionmaker
        from app.audit import verify_chain
        eng = get_engine(dsn)
        S = sessionmaker(bind=eng)
        s = S()
        chain_ok = verify_chain(s, txn)
        s.close()
        eng.dispose()
        check("5. independent Postgres proof: audit hash chain verifies through the portal txn",
              chain_ok is True, {"chain_verified": chain_ok})

        # The portal's self-report must agree with the database (no divergence).
        check("6. portal report matches the database (no disconnected preview record)",
              (portal_report.get("audit_chain_verified") in (True, "true")) and chain_ok is True
              and portal_report.get("reconcile_state") in ("PAID", "terminal"),
              {"portal_chain": portal_report.get("audit_chain_verified"),
               "db_chain": chain_ok, "portal_state": portal_report.get("reconcile_state")})
    finally:
        if server is not None:
            server.should_exit = True
        for p in reversed(processes):
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        stub_proc.terminate()
        try:
            stub_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            stub_proc.kill()
        if sign_key and sign_key.exists():
            sign_key.unlink()

    verdict = "PAARI v3.3 DASHBOARD OPERATOR WORKFLOW GREEN" if not failures else \
        f"PAARI v3.3 DASHBOARD OPERATOR WORKFLOW RED: {failures}"
    print("\n" + "=" * 68, flush=True)
    print(" PAARI v3.3 DASHBOARD-DRIVEN OPERATOR WORKFLOW (POSTGRES)", flush=True)
    print("=" * 68, flush=True)
    print("OPERATOR     one portal action -> complete persistent golden payment", flush=True)
    print("PROOF        portal self-report cross-checked against independent Postgres reads", flush=True)
    print("SETTLEMENT   simulated PAID (local provider; no real money)", flush=True)
    print("=" * 68, flush=True)
    print(verdict, flush=True)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
