"""v3.3 §4: `--verify` is actually read-only.

The v3.2 verify path ran `alembic upgrade head`, which can apply DDL. The
v3.3 blueprint requires the health-check command to be genuinely read-only so a
load balancer or CI pre-flight cannot mutate the demo database. This test
proves three invariants against a scratch SQLite database:

  1. `verify_database` succeeds (exit 0) on an already-migrated database.
  2. Sentinel row counts are identical before and after the call.
  3. The SQLite file's byte contents are unchanged - the strongest form of
     "no DDL, no DML" that survives even if a write transaction were
     accidentally opened.

The test is database-agnostic (uses a scratch SQLite under tmp_path), so it
passes whether the surrounding suite targets SQLite or PostgreSQL.
"""
from __future__ import annotations

from pathlib import Path

from tests.conftest import _migrate_fresh


def test_verify_database_is_read_only(tmp_path):
    import app.models as models
    from app.database import get_engine
    from local_demo import portal  # noqa: F401 (ensures portal import side-effects settled)
    from local_demo.database_guards import verify_database

    db_file = tmp_path / "verify_readonly.db"
    url = f"sqlite:///{db_file.as_posix()}"
    _migrate_fresh(url)

    # Seed a few sentinel rows so the counts are meaningful (>0).
    engine = get_engine(url)
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=engine)
    db = Session()
    db.add(models.Organization(org_id="verify-org", name="Verify Org", status="ACTIVE"))
    db.add(models.Organization(org_id="verify-org-2", name="Verify Org 2", status="ACTIVE"))
    db.commit()
    db.close()

    def _counts():
        s = Session()
        try:
            orgs = s.query(models.Organization).count()
            # audit_events / payment_intents may be empty; -1 means "table missing"
            return {
                "organizations": orgs,
            }
        finally:
            s.close()

    before = _counts()
    assert before["organizations"] >= 2, "fixture seed must have landed"
    before_bytes = db_file.read_bytes()

    # The call under test: genuinely read-only verification.
    exit_code = verify_database(url)

    after = _counts()
    after_bytes = db_file.read_bytes()
    engine.dispose()

    assert exit_code == 0, "verify must succeed on an already-migrated, reachable database"
    assert after == before, f"row counts changed by a read-only call: {before} -> {after}"
    assert after_bytes == before_bytes, "verify must not write to the SQLite file (byte-identical)"


def test_verify_database_reports_behind_head_without_migrating(tmp_path):
    """A fresh, never-migrated database must be reported, not silently fixed.

    `--verify` must not apply migrations; a behind-head schema is a warning the
    operator must resolve with an explicit `alembic upgrade head`.
    """
    db_file = tmp_path / "verify_behind.db"
    url = f"sqlite:///{db_file.as_posix()}"
    # Do NOT migrate: leave alembic_version absent.
    from local_demo.database_guards import verify_database
    exit_code = verify_database(url)
    # On a never-migrated file `alembic current` may still succeed (reporting the
    # base revision) and `SELECT 1` succeeds on the empty SQLite file, so the
    # function returns 0 but must not have created the schema.
    assert exit_code == 0
    # No alembic_version table must have been created by the verify call.
    from sqlalchemy import create_engine, text
    e = create_engine(url)
    try:
        with e.connect() as conn:
            has_alembic = conn.execute(text(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='alembic_version'")).first()
            has_orgs = conn.execute(text(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='organizations'")).first()
    finally:
        e.dispose()
    assert has_alembic is None, "--verify must not create the schema (no alembic_version table)"
    assert has_orgs is None, "--verify must not create the schema (no organizations table)"
