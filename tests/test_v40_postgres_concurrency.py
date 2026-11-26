"""Optional PostgreSQL race test for treasury conditional reservations.

Set PAARI_TEST_POSTGRES_URL to an explicitly disposable Postgres database whose
name ends in `_test`, `_testing`, or `_pytest`. The helper resets that database.
"""
import os
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import update
from sqlalchemy.orm import sessionmaker

POSTGRES_URL = os.environ.get("PAARI_TEST_POSTGRES_URL", "")
pytestmark = pytest.mark.skipif(not POSTGRES_URL, reason="PAARI_TEST_POSTGRES_URL not configured")


def test_postgres_atomic_shared_budget_conditional_update():
    from tests.conftest import _migrate_fresh
    from app.database import assert_disposable_database_url
    from app import models
    from sqlalchemy import create_engine

    assert POSTGRES_URL.startswith(("postgresql://", "postgresql+psycopg://")), (
        "PAARI_TEST_POSTGRES_URL must be a PostgreSQL URL"
    )
    assert_disposable_database_url(POSTGRES_URL, "run Paari's optional PostgreSQL treasury race test")
    _migrate_fresh(POSTGRES_URL)

    engine = create_engine(POSTGRES_URL, pool_size=20, max_overflow=0)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    tenant = "pg-race-" + uuid.uuid4().hex[:12]
    policy_id = "policy-" + uuid.uuid4().hex
    bucket_id = "bucket-" + uuid.uuid4().hex
    with SessionLocal() as session:
        session.add(models.TreasuryBudgetPolicy(
            policy_id=policy_id, org_id=tenant, currency="INR",
            limit_minor_units=1000, period="DAILY", status="ACTIVE"))
        session.flush()
        from app.treasury_service import period_key
        session.add(models.TreasuryBudgetBucket(
            bucket_id=bucket_id, policy_id=policy_id, org_id=tenant, currency="INR",
            period_key=period_key("DAILY"), limit_minor_units=1000,
            reserved_minor_units=0, spent_minor_units=0))
        session.commit()

    def try_reserve(_index):
        with SessionLocal() as session:
            changed = session.execute(
                update(models.TreasuryBudgetBucket)
                .where(
                    models.TreasuryBudgetBucket.bucket_id == bucket_id,
                    models.TreasuryBudgetBucket.reserved_minor_units
                    + models.TreasuryBudgetBucket.spent_minor_units + 100
                    <= models.TreasuryBudgetBucket.limit_minor_units,
                )
                .values(reserved_minor_units=models.TreasuryBudgetBucket.reserved_minor_units + 100)
            ).rowcount
            session.commit()
            return changed

    try:
        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(try_reserve, range(20)))
        assert sum(1 for count in results if count == 1) == 10
        with SessionLocal() as session:
            bucket = session.query(models.TreasuryBudgetBucket).filter_by(bucket_id=bucket_id).one()
            assert bucket.reserved_minor_units == 1000
            assert bucket.spent_minor_units == 0
    finally:
        engine.dispose()
