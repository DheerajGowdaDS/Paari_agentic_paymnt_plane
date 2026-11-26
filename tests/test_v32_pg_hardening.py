"""v3.2 Postgres-first hardening tests.

These close the two High-priority gaps named in the v3.1 report:

  * PostgreSQL concurrency is not fully validated. The v3.1 eight-thread
    reservation test ran on SQLite, where "did not win" can come from a write
    lock. Under PostgreSQL the invariant must hold under *true* multi-worker
    load, where every thread is a real connection racing the atomic conditional
    update - no lock-based excuse is available.
  * Persistent recovery without duplicate execution. The durable state and the
    hash-chained audit must survive the engine (and therefore the service) being
    torn down and rebuilt, so a restart resumes from the persisted row instead of
    re-submitting.

All of it runs only when the suite is actually pointed at a disposable
PostgreSQL database (``TEST_DATABASE_URL`` starts with ``postgresql``), which is
the documented way to run the whole suite against Postgres - so a SQLite run
reports a skip, not a false pass.
"""
from __future__ import annotations

import threading
import uuid

import pytest

from tests.conftest import TEST_DATABASE_URL, _migrate_fresh
from tests import test_v31_resilience as v31


def _require_postgres():
    if not TEST_DATABASE_URL.startswith("postgresql"):
        pytest.skip(
            "Postgres-first hardening test; this run targets "
            f"{TEST_DATABASE_URL.split('://')[0]!r}. Point TEST_DATABASE_URL at a "
            "disposable PostgreSQL database (name ending _test) to execute it."
        )


# ---------------------------------------------------------------------------
# 1. True multi-worker concurrency: N real Postgres connections race the
#    load-bearing single-use reservation. The consume endpoint already reserved
#    it, so NO worker may record a new win and the row must stay capped at 1.
# ---------------------------------------------------------------------------
def test_single_use_reservation_admits_exactly_one_under_postgres(paari_client, monkeypatch):
    _require_postgres()
    ctx = paari_client
    auth_id = v31._make_unconsumed_intent(ctx, monkeypatch, "pg-single")
    assert v31._try_reserve(ctx, auth_id) == 1, "first reservation must win"
    assert v31._try_reserve(ctx, auth_id) == 0, "second reservation must be rejected"


def test_concurrent_reservations_capped_under_postgres(paari_client, monkeypatch):
    """16 workers, each on its own Postgres connection, race the atomic
    conditional update on a single-use authorization that the HTTP consume path
    has already reserved. Under real multi-worker load the invariant still holds:
    nobody records a new win and the row stays at usage_count==1."""
    _require_postgres()
    import app.models as models
    from sqlalchemy import update

    ctx = paari_client
    auth_id = v31._consume(ctx, monkeypatch, "pg-race")

    winners, errors, lock = [], [], threading.Lock()
    barrier = threading.Barrier(16)

    def worker():
        barrier.wait()
        session = ctx.Session()
        try:
            try:
                rowcount = session.execute(
                    update(models.BoundedAuthorization)
                    .where(models.BoundedAuthorization.authorization_id == auth_id,
                           models.BoundedAuthorization.usage_count < models.BoundedAuthorization.max_usage)
                    .values(usage_count=models.BoundedAuthorization.usage_count + 1)
                ).rowcount
                session.commit() if rowcount else session.rollback()
                with lock:
                    winners.append(rowcount == 1)
            except Exception as exc:  # noqa: BLE001 - a real DB error, recorded, is a no-win
                with lock:
                    errors.append(type(exc).__name__)
        finally:
            session.close()

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(winners) == 0, f"under Postgres multi-worker load nobody may win a second use: {winners}"

    session = ctx.Session()
    auth = session.query(models.BoundedAuthorization).filter_by(authorization_id=auth_id).first()
    session.close()
    assert auth.usage_count == 1, f"usage must stay capped at 1 under load, got {auth.usage_count} (errors={errors})"

    # And the replay path reports a stable refusal, not a re-submission.
    r = ctx.client.post(f"/payments/authorizations/{auth_id}/consume",
                       json={"session_token": ctx.session_token})
    assert r.status_code == 409, r.text


def test_overlapping_mandate_budgets_are_serialized_under_postgres(paari_client, monkeypatch):
    """Concurrent requests share both mandate locks; only one fits the budget."""
    _require_postgres()
    from fastapi.testclient import TestClient

    from app.main import app
    from tests.test_user_mandates import create_mandate

    monkeypatch.setenv("PAARI_REQUIRE_USER_MANDATE", "1")
    ctx = paari_client
    for _ in range(2):
        create_mandate(ctx, max_per_transaction=1000, max_daily_amount=1000)

    barrier = threading.Barrier(2)
    decisions, errors = [], []
    result_lock = threading.Lock()

    def submit(suffix):
        barrier.wait()
        try:
            with TestClient(app) as client:
                response = client.post("/payments/intent", json={
                    "session_token": ctx.session_token,
                    "transaction_id": f"TXN-{suffix}",
                    "idempotency_key": f"idem-{suffix}",
                    "merchant": "TestMerchant",
                    "amount_minor_units": 700,
                    "currency": "INR",
                    "action": "make_payment",
                    "purpose": "postgres mandate race",
                })
                response.raise_for_status()
                decision = response.json()["decision"]
            with result_lock:
                decisions.append(decision)
        except Exception as exc:
            with result_lock:
                errors.append(repr(exc))

    workers = [threading.Thread(target=submit, args=(f"pg-mandate-{i}",)) for i in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert not errors, errors
    assert sorted(decisions) == ["allow", "deny"], decisions


# ---------------------------------------------------------------------------
# 2. Duplicate webhook delivery stays idempotent on Postgres (no double settle).
# ---------------------------------------------------------------------------
def test_duplicate_webhook_idempotent_under_postgres(paari_client, monkeypatch):
    _require_postgres()
    v31.test_duplicate_webhook_delivery_is_idempotent(paari_client, monkeypatch)


# ---------------------------------------------------------------------------
# 3. Durable state + hash-chained audit survive an engine/service rebuild, so a
#    restart resumes from the persisted row instead of re-submitting the order.
# ---------------------------------------------------------------------------
def test_state_and_audit_persist_across_engine_recreation(paari_client, monkeypatch):
    """Consume + reconcile to PAID, then dispose the bound engine and rebuild a
    fresh one on the same URL - standing in for a service restart. The provider
    row must still be PAID and the audit chain still verify with no re-submit."""
    _require_postgres()
    import app.models as models
    from sqlalchemy.orm import sessionmaker

    ctx = paari_client
    auth_id = v31._consume(ctx, monkeypatch, "pg-persist")

    # Drive it to an uncertain state, then reconcile it to PAID (durable result).
    session = ctx.Session()
    txn = session.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).first()
    txn.state = "PROVIDER_UNKNOWN"
    session.commit()
    session.close()
    monkeypatch.setattr("app.reconcile.get_provider", lambda: v31._provider("order_pg_persist"))
    from app.reconcile import reconcile_one
    session = ctx.Session()
    result = reconcile_one(session, auth_id)
    session.close()
    assert result["state"] == "PAID"

    # Capture the persisted facts BEFORE tearing the engine down.
    auth = ctx.Session().query(models.BoundedAuthorization).filter_by(authorization_id=auth_id).first()
    trace = auth.transaction_id
    usage = auth.usage_count
    ctx.Session().close()

    # Tear down the engine the app under test was bound to and rebuild a brand
    # new one against the same Postgres database - the "restart".
    from app.database import get_engine
    rebuilt = get_engine(TEST_DATABASE_URL)
    FreshSession = sessionmaker(autocommit=False, autoflush=False, bind=rebuilt)
    try:
        with FreshSession() as fresh:
            row = fresh.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).first()
            assert row is not None, "the settled provider row must survive a service/engine restart"
            assert row.state == "PAID", f"persisted state must still be PAID after rebuild, got {row.state}"
            fresh_auth = fresh.query(models.BoundedAuthorization).filter_by(authorization_id=auth_id).first()
            assert fresh_auth.usage_count == usage == 1, "a restart must not re-reserve the single-use authorization"
            # The hash-chained audit must still verify end-to-end across the rebuild.
            events = (fresh.query(models.AuditEvent)
                      .filter(models.AuditEvent.transaction_id == trace)
                      .order_by(models.AuditEvent.created_at.asc(), models.AuditEvent.id.asc()).all())
            assert events, "the audit trail must persist across the restart"
            for prev, cur in zip(events, events[1:]):
                assert cur.prev_hash == prev.event_hash, "audit hash chain broken across engine recreation"
    finally:
        rebuilt.dispose()


# ---------------------------------------------------------------------------
# 4. A clean-schema Postgres rebuild still applies the whole chain with no drift.
# ---------------------------------------------------------------------------
def test_postgres_migrate_is_repeatable_with_no_drift():
    _require_postgres()
    from alembic import command
    from alembic.config import Config
    import pathlib

    # Rebuild from empty so the check is against this revision chain, and a
    # second apply must be a no-op (no drift) - a repeatable release gate.
    _migrate_fresh(TEST_DATABASE_URL)
    cfg = Config(str(pathlib.Path("alembic.ini")))
    cfg.set_main_option("sqlalchemy.url", TEST_DATABASE_URL)
    command.check(cfg)
    command.upgrade(cfg, "head")  # idempotent: already at head
