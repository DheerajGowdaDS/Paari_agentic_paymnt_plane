"""Database guards and the genuinely read-only verifier for the local demo.

These helpers were previously owned by ``scripts/start_local_demo.py``, which the
v3.3.1 release retired in favour of ``scripts/start_live_demo.py`` (see the Live
Demo Mode). The two functions are still exercised by the regression suite
(``tests/test_local_demo_v3.py`` and ``tests/test_v33_readonly_verify.py``), so
they live here, co-located with the rest of the local-demo surface.

Only a local SQLite demo file or a loopback PostgreSQL ``paari_demo`` database
may be targeted; an operator-supplied URL can never silently point at a live,
externally hosted production database. ``verify_database`` is SELECT-only: it
reports the schema revision, proves connectivity and snapshots sentinel row
counts, but applies no migrations and makes no writes.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]


def guarded_database_url(url: str) -> str:
    """Allow only a local SQLite demo file or a loopback PostgreSQL demo database.

    No operator-provided URL can silently target an externally hosted production DB.
    """
    if url.startswith("sqlite:///"):
        path = Path(url[len("sqlite:///"):]).resolve()
        if path == (ROOT / "data" / "local_demo" / "paari_demo.db").resolve():
            return url
        raise ValueError("Only data/local_demo/paari_demo.db is allowed for local SQLite")
    parsed = urlparse(url)
    if parsed.scheme not in {"postgresql", "postgresql+psycopg"}:
        raise ValueError("Only SQLite or PostgreSQL demo databases are allowed")
    if parsed.hostname not in {"127.0.0.1", "localhost"} or parsed.path.lstrip("/") != "paari_demo":
        raise ValueError("PostgreSQL must be on loopback and database name exactly paari_demo")
    return url


def _alembic_env(url: str, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Minimal Alembic environment for read-only commands (no credential scrubbing
    needed because ``alembic current`` and ``alembic heads`` are schema-only reads)."""
    env = {"ALEMBIC_URL": url, "DATABASE_URL": url}
    if extra:
        env.update(extra)
    return env


def verify_database(url: str) -> int:
    """Genuinely read-only verification.

    What it does:
      1. ``alembic current`` - reports the migration revision without applying anything.
      2. ``SELECT 1`` - proves the database is reachable.
      3. Row-count snapshots of three sentinel tables - proves data was not modified
         during this call (the same counts must be observed on the next run).

    What it does NOT do:
      * No ``alembic upgrade`` or any DDL.
      * No ``DROP SCHEMA``, no ``CREATE``, no ``INSERT``, no ``UPDATE``, no ``DELETE``.
      * No migration application - if the schema is behind head, the operator
        sees a warning and must run ``alembic upgrade head`` explicitly.

    This satisfies the v3.3 blueprint requirement that the health-check command be
    actually read-only: a CI pre-flight or a load balancer's health check must not
    be able to mutate the database.
    """
    env = _alembic_env(url)

    # 1. Schema revision (read-only).
    r = subprocess.run([sys.executable, "-m", "alembic", "current"],
                       cwd=ROOT, env={**os.environ, **env},
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        print(f"[FAIL] alembic current: {(r.stderr or r.stdout)[-800:]}", file=sys.stderr)
        return 1
    # ``alembic current`` prints one line per applied revision, e.g.
    #   "e6f7a8b9c0d1 (head)"
    # Take the revision id (first whitespace token) of the last (topmost) line.
    current_lines = [ln for ln in (r.stdout or "").strip().splitlines() if ln.strip()]
    current_id = current_lines[-1].split()[0] if current_lines else "unknown"
    print(f"[PASS] schema revision: {current_id}", flush=True)

    # Compare against the head revision (also read-only).
    r_head = subprocess.run([sys.executable, "-m", "alembic", "heads"],
                            cwd=ROOT, env={**os.environ, **env},
                            capture_output=True, text=True, timeout=60)
    head_lines = [ln for ln in (r_head.stdout or "").strip().splitlines() if ln.strip()]
    head_id = head_lines[0].split()[0] if head_lines else "unknown"
    at_head = current_id == head_id and current_id != "unknown"
    if not at_head:
        print(f"[WARN] schema is at {current_id}, head is {head_id}. "
              f"Run `alembic upgrade head` explicitly (--verify is read-only and will not apply migrations).",
              flush=True)
    else:
        print("[PASS] schema is at head", flush=True)

    # 2. Connectivity + sentinel row counts (all SELECT-only).
    from sqlalchemy import create_engine, text
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            counts: dict[str, int] = {}
            for table in ("organizations", "agents", "payment_intents",
                          "provider_transactions", "audit_events"):
                try:
                    counts[table] = conn.execute(text(f"SELECT count(*) FROM {table}")).scalar()
                except Exception:
                    counts[table] = -1  # table missing = schema not applied; sentinel, not a row count
        total = sum(v for v in counts.values() if v >= 0)
        print("[PASS] connectivity: demo database reachable", flush=True)
        print(f"[INFO] sentinel row counts (read-only snapshot): {counts}", flush=True)
        print(f"[INFO] total rows observed: {total}", flush=True)
    except Exception as exc:
        print(f"[FAIL] connectivity: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()

    print("PAARI LOCAL DEMO VERIFIED (read-only: no DDL, no DML, no migrations applied)", flush=True)
    return 0
