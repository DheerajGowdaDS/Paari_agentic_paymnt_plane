"""Atomic tenant-scoped treasury reservations.

Reservations are taken in the same database transaction that creates a bounded
payment authorization. The counter update is a conditional SQL UPDATE, so two
workers cannot both spend the same remaining ceiling. A provider-confirmed PAID
state moves reserved exposure to spent; declined/expired/cancelled executions
release it. FAILED and PROVIDER_UNKNOWN deliberately retain exposure because a
late provider confirmation may still prove that money moved.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import models


class TreasuryError(RuntimeError):
    code = "TREASURY_ERROR"


class TreasuryPolicyMissing(TreasuryError):
    code = "TREASURY_POLICY_MISSING"


class TreasuryPolicySuspended(TreasuryError):
    code = "TREASURY_POLICY_SUSPENDED"


class TreasuryLimitExceeded(TreasuryError):
    code = "TREASURY_LIMIT_EXCEEDED"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def period_key(period: str, now: datetime | None = None) -> str:
    now = (now or _now()).astimezone(timezone.utc)
    period = (period or "DAILY").upper()
    if period == "DAILY":
        return now.strftime("%Y-%m-%d")
    if period == "WEEKLY":
        iso = now.isocalendar()
        return f"{iso.year}-W{iso.week:02d}"
    if period == "MONTHLY":
        return now.strftime("%Y-%m")
    if period == "LIFETIME":
        return "LIFETIME"
    raise ValueError(f"Unsupported treasury period: {period}")


def _get_or_create_bucket(db: Session, policy: models.TreasuryBudgetPolicy,
                          now: datetime | None = None) -> models.TreasuryBudgetBucket:
    key = period_key(policy.period, now)
    bucket = db.query(models.TreasuryBudgetBucket).filter_by(
        org_id=policy.org_id, currency=policy.currency, period_key=key,
    ).with_for_update().first()
    if bucket:
        # The policy limit can be raised without losing counters. Keep bucket
        # limit in sync for the active period; a lower limit is enforced below.
        if bucket.limit_minor_units != policy.limit_minor_units:
            bucket.limit_minor_units = policy.limit_minor_units
            bucket.updated_at = now or _now()
        return bucket
    candidate = models.TreasuryBudgetBucket(
        policy_id=policy.policy_id, org_id=policy.org_id,
        currency=policy.currency, period_key=key,
        limit_minor_units=policy.limit_minor_units,
        reserved_minor_units=0, spent_minor_units=0,
        created_at=now or _now(), updated_at=now or _now(),
    )
    try:
        # A savepoint keeps the surrounding payment-intent transaction intact
        # if another worker creates the same period bucket concurrently.
        with db.begin_nested():
            db.add(candidate)
            db.flush()
        return candidate
    except IntegrityError:
        return db.query(models.TreasuryBudgetBucket).filter_by(
            org_id=policy.org_id, currency=policy.currency, period_key=key,
        ).with_for_update().one()


def reserve_for_authorization(db: Session, auth: models.BoundedAuthorization) -> models.TreasuryReservation | None:
    """Reserve shared tenant exposure for this authorization, atomically.

    No policy means legacy-compatible operation unless the deployment has set
    PAARI_REQUIRE_TREASURY_BUDGET=1, in which case it fails closed.
    """
    existing = db.query(models.TreasuryReservation).filter_by(
        authorization_id=auth.authorization_id,
    ).first()
    if existing:
        if (existing.org_id != auth.org_id or existing.amount_minor_units != auth.amount_minor_units
                or existing.currency != auth.currency):
            raise TreasuryLimitExceeded("Existing reservation does not match authorization bounds")
        return existing

    currency = auth.currency.upper()
    policy = db.query(models.TreasuryBudgetPolicy).filter_by(
        org_id=auth.org_id, currency=currency,
    ).with_for_update().first()
    if policy is None:
        if os.environ.get("PAARI_REQUIRE_TREASURY_BUDGET") == "1":
            raise TreasuryPolicyMissing(f"No treasury budget configured for {auth.org_id}/{currency}")
        return None
    if policy.status != "ACTIVE":
        raise TreasuryPolicySuspended(f"Treasury policy for {currency} is {policy.status}")

    now = _now()
    bucket = _get_or_create_bucket(db, policy, now)
    amount = int(auth.amount_minor_units)
    changed = db.execute(
        update(models.TreasuryBudgetBucket)
        .where(
            models.TreasuryBudgetBucket.bucket_id == bucket.bucket_id,
            models.TreasuryBudgetBucket.reserved_minor_units
            + models.TreasuryBudgetBucket.spent_minor_units + amount
            <= models.TreasuryBudgetBucket.limit_minor_units,
        )
        .values(
            reserved_minor_units=models.TreasuryBudgetBucket.reserved_minor_units + amount,
            updated_at=now,
        )
        .execution_options(synchronize_session=False)
    ).rowcount
    if changed != 1:
        db.refresh(bucket)
        available = max(0, bucket.limit_minor_units - bucket.spent_minor_units - bucket.reserved_minor_units)
        raise TreasuryLimitExceeded(
            f"Treasury ceiling exceeded for {currency}: requested {amount} minor units; "
            f"available {available} minor units in {bucket.period_key}"
        )

    # The SQL UPDATE used synchronize_session=False; refresh before recording
    # evidence so the audit detail reflects the committed counter values.
    db.refresh(bucket)

    reservation = models.TreasuryReservation(
        bucket_id=bucket.bucket_id, org_id=auth.org_id,
        intent_id=auth.intent_id, authorization_id=auth.authorization_id,
        currency=currency, period_key=bucket.period_key,
        amount_minor_units=amount, status="RESERVED", provider_state="AUTHORIZED",
        created_at=now,
    )
    db.add(reservation)
    db.flush()
    try:
        from app.audit import record_audit
        record_audit(
            db, transaction_id=auth.transaction_id, agent_id=auth.agent_id,
            parent_id=None, kind="treasury_exposure_reserved", org_id=auth.org_id,
            detail={"reservation_id": reservation.reservation_id,
                    "authorization_id": auth.authorization_id,
                    "intent_id": auth.intent_id, "currency": currency,
                    "amount_minor_units": amount, "period_key": bucket.period_key,
                    "reserved_minor_units": bucket.reserved_minor_units,
                    "spent_minor_units": bucket.spent_minor_units,
                    "limit_minor_units": bucket.limit_minor_units},
        )
    except Exception:
        # Audit append failures must abort authorization creation; caller owns
        # rollback and the counter update remains in the same transaction.
        raise
    return reservation


def sync_reservation_after_transition(db: Session, txn, new_state: str) -> None:
    """Finalize exposure inside the same transaction as a provider-state change."""
    state = str(new_state).upper()
    if state not in {"PAID", "DECLINED", "EXPIRED", "CANCELLED"}:
        return
    reservation = db.query(models.TreasuryReservation).filter_by(
        authorization_id=txn.authorization_id,
    ).with_for_update().first()
    if not reservation or reservation.status != "RESERVED":
        return
    bucket = db.query(models.TreasuryBudgetBucket).filter_by(
        bucket_id=reservation.bucket_id,
    ).with_for_update().first()
    if bucket is None:
        raise TreasuryError("Treasury reservation bucket is missing; refusing to finalize silently")

    amount = int(reservation.amount_minor_units)
    values = {
        "reserved_minor_units": models.TreasuryBudgetBucket.reserved_minor_units - amount,
        "updated_at": _now(),
    }
    status = "RELEASED"
    if state == "PAID":
        values["spent_minor_units"] = models.TreasuryBudgetBucket.spent_minor_units + amount
        status = "COMMITTED"
    changed = db.execute(
        update(models.TreasuryBudgetBucket)
        .where(models.TreasuryBudgetBucket.bucket_id == bucket.bucket_id,
               models.TreasuryBudgetBucket.reserved_minor_units >= amount)
        .values(**values)
        .execution_options(synchronize_session=False)
    ).rowcount
    if changed != 1:
        raise TreasuryError("Treasury reservation counter integrity check failed")

    now = _now()
    reservation.status = status
    reservation.provider_state = state
    reservation.finalized_at = now
    from app.audit import record_audit
    record_audit(
        db, transaction_id=txn.authorization_id, agent_id=txn.agent_id,
        parent_id=None, kind="treasury_exposure_committed" if status == "COMMITTED" else "treasury_exposure_released",
        org_id=txn.org_id,
        detail={"reservation_id": reservation.reservation_id,
                "authorization_id": txn.authorization_id,
                "intent_id": txn.intent_id, "provider_state": state,
                "reservation_status": status, "amount_minor_units": amount,
                "currency": reservation.currency, "period_key": reservation.period_key},
    )


def budget_summary(db: Session, org_id: str, currency: str) -> dict | None:
    policy = db.query(models.TreasuryBudgetPolicy).filter_by(
        org_id=org_id, currency=currency.upper(),
    ).first()
    if not policy:
        return None
    key = period_key(policy.period)
    bucket = db.query(models.TreasuryBudgetBucket).filter_by(
        org_id=org_id, currency=currency.upper(), period_key=key,
    ).first()
    reserved = bucket.reserved_minor_units if bucket else 0
    spent = bucket.spent_minor_units if bucket else 0
    return {
        "policy_id": policy.policy_id, "org_id": org_id,
        "currency": policy.currency, "period": policy.period,
        "period_key": key, "status": policy.status,
        "limit_minor_units": policy.limit_minor_units,
        "reserved_minor_units": reserved, "spent_minor_units": spent,
        "available_minor_units": max(0, policy.limit_minor_units - reserved - spent),
    }
