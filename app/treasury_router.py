"""Tenant-scoped treasury budget administration and exposure API."""
from __future__ import annotations
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import models
from app.database import get_db
from app.control_plane.router import _tenant
from app.treasury_service import budget_summary, period_key

router = APIRouter(prefix="/control/v1/treasury", tags=["treasury-control-plane"])


class BudgetUpsert(BaseModel):
    model_config = ConfigDict(extra="forbid")
    limit_minor_units: int = Field(gt=0, le=2_000_000_000)
    period: Literal["DAILY", "WEEKLY", "MONTHLY", "LIFETIME"] = "DAILY"
    status: Literal["ACTIVE", "SUSPENDED"] = "ACTIVE"


class BudgetStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["ACTIVE", "SUSPENDED"]
    reason: str = Field(min_length=5, max_length=300)


def _org(key: str, org: str, db: Session, write: bool = False) -> str:
    return _tenant(db, key, org, required_scope="control:write" if write else "control:read")


@router.put("/budgets/{currency}")
def upsert_budget(currency: str, req: BudgetUpsert,
                  x_paari_control_key: str = Header(default=""),
                  x_paari_org: str = Header(default=""),
                  db: Session = Depends(get_db)):
    org = _org(x_paari_control_key, x_paari_org, db, write=True)
    currency = currency.upper().strip()
    if not currency.isalpha() or not 3 <= len(currency) <= 10:
        raise HTTPException(422, "Currency must be an uppercase ISO-style currency code")
    row = db.query(models.TreasuryBudgetPolicy).filter_by(org_id=org, currency=currency).with_for_update().first()
    if row is None:
        row = models.TreasuryBudgetPolicy(org_id=org, currency=currency,
            limit_minor_units=req.limit_minor_units, period=req.period, status=req.status)
        db.add(row)
    else:
        # Never lower a current-period ceiling below reserved/spent exposure,
        # and never change the accounting window mid-period after activity: that
        # would create a fresh bucket and could reset an already-used ceiling.
        current_key = period_key(row.period)
        bucket = db.query(models.TreasuryBudgetBucket).filter_by(
            org_id=org, currency=currency, period_key=current_key,
        ).with_for_update().first()
        used = (bucket.reserved_minor_units + bucket.spent_minor_units) if bucket else 0
        if req.period != row.period and used > 0:
            raise HTTPException(409, "Treasury period cannot change while the current period has reserved or spent exposure")
        if req.limit_minor_units < used:
            raise HTTPException(409, "New treasury limit is below current reserved plus spent exposure")
        row.limit_minor_units = req.limit_minor_units
        row.period = req.period
        row.status = req.status
        from datetime import datetime, timezone
        row.updated_at = datetime.now(timezone.utc)
    try:
        db.flush()
        from app.audit import record_audit
        record_audit(db, transaction_id=f"treasury-policy:{org}:{currency}", agent_id="", parent_id=None,
            kind="treasury_policy_configured", org_id=org,
            detail={"currency": currency, "limit_minor_units": req.limit_minor_units,
                    "period": req.period, "status": req.status})
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Treasury policy already exists") from exc
    return budget_summary(db, org, currency)


@router.get("/budgets")
def list_budgets(x_paari_control_key: str = Header(default=""),
                 x_paari_org: str = Header(default=""), db: Session = Depends(get_db)):
    org = _org(x_paari_control_key, x_paari_org, db)
    policies = db.query(models.TreasuryBudgetPolicy).filter_by(org_id=org).order_by(
        models.TreasuryBudgetPolicy.currency.asc()).all()
    return [budget_summary(db, org, p.currency) for p in policies]


@router.get("/budgets/{currency}")
def get_budget(currency: str, x_paari_control_key: str = Header(default=""),
               x_paari_org: str = Header(default=""), db: Session = Depends(get_db)):
    org = _org(x_paari_control_key, x_paari_org, db)
    summary = budget_summary(db, org, currency.upper())
    if summary is None:
        raise HTTPException(404, "Treasury budget not configured")
    return summary


@router.post("/budgets/{currency}/status")
def change_budget_status(currency: str, req: BudgetStatus,
                         x_paari_control_key: str = Header(default=""),
                         x_paari_org: str = Header(default=""), db: Session = Depends(get_db)):
    org = _org(x_paari_control_key, x_paari_org, db, write=True)
    row = db.query(models.TreasuryBudgetPolicy).filter_by(
        org_id=org, currency=currency.upper()).with_for_update().first()
    if not row:
        raise HTTPException(404, "Treasury budget not configured")
    row.status = req.status
    from datetime import datetime, timezone
    row.updated_at = datetime.now(timezone.utc)
    from app.audit import record_audit
    record_audit(db, transaction_id=f"treasury-policy:{org}:{row.currency}", agent_id="", parent_id=None,
        kind="treasury_policy_status_changed", org_id=org,
        detail={"currency": row.currency, "status": row.status, "reason": req.reason})
    db.commit()
    return budget_summary(db, org, row.currency)


@router.get("/reservations/{authorization_id}")
def get_reservation(authorization_id: str,
                    x_paari_control_key: str = Header(default=""),
                    x_paari_org: str = Header(default=""), db: Session = Depends(get_db)):
    org = _org(x_paari_control_key, x_paari_org, db)
    row = db.query(models.TreasuryReservation).filter_by(
        org_id=org, authorization_id=authorization_id).first()
    if not row:
        raise HTTPException(404, "Treasury reservation not found")
    return {"reservation_id": row.reservation_id, "authorization_id": row.authorization_id,
            "intent_id": row.intent_id, "currency": row.currency,
            "period_key": row.period_key, "amount_minor_units": row.amount_minor_units,
            "status": row.status, "provider_state": row.provider_state,
            "created_at": row.created_at, "finalized_at": row.finalized_at}
