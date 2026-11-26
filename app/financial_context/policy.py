"""Open Finance context governance for Paari payment decisions.

Financial data is contextual evidence, never payment authority. By default,
Paari observes context availability/freshness and records provenance. An
organization may explicitly require a fresh, consent-bound snapshot by setting
PAARI_REQUIRE_FRESH_FINANCIAL_CONTEXT=1; that setting fails closed at payment
admission and provider-consumption time.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app import models
from app.governance import PolicyResult


def _enabled(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _max_age() -> timedelta:
    raw = os.getenv("PAARI_FINANCIAL_CONTEXT_MAX_AGE_HOURS", "24")
    try:
        hours = float(raw)
    except (TypeError, ValueError):
        hours = 24.0
    # Avoid zero/negative windows and unreasonable configuration mistakes.
    hours = min(max(hours, 0.25), 24 * 90)
    return timedelta(hours=hours)


@dataclass(frozen=True)
class FinancialContextDecision:
    status: str
    required: bool
    fresh: bool
    snapshot_id: str | None
    reason: str
    policy_result: PolicyResult


def evaluate_financial_context(
    db: Session,
    *,
    org_id: str,
    mandate: models.UserPaymentMandate | None,
    now: datetime | None = None,
) -> FinancialContextDecision:
    """Evaluate whether a mandate has usable, fresh, consented Setu context."""
    now = now or _now()
    required = _enabled("PAARI_REQUIRE_FRESH_FINANCIAL_CONTEXT")
    base_evidence = {"required": required, "max_age_hours": _max_age().total_seconds() / 3600}

    if mandate is None:
        status = "MISSING_MANDATE"
        reason = "No active user mandate is available to bind Open Finance context"
        result = PolicyResult(
            name="open_finance_context", passed=not required,
            detail=(reason if required else "Open Finance context is not linked because no mandate is present; observe-only posture"),
            evidence={**base_evidence, "status": status, "enforcement": "REQUIRE" if required else "OBSERVE"},
        )
        return FinancialContextDecision(status, required, False, None, reason, result)

    binding = db.query(models.SetuConsentMandateBinding).filter_by(
        org_id=org_id, mandate_id=mandate.mandate_id,
        subject_user_id=mandate.user_id, status="ACTIVE",
    ).order_by(models.SetuConsentMandateBinding.created_at.desc()).first()
    if binding is None:
        status = "NOT_CONNECTED"
        reason = "No active Setu consent-to-mandate binding exists"
        result = PolicyResult(
            name="open_finance_context", passed=not required,
            detail=(reason if required else "No Setu financial context is linked; observe-only posture"),
            evidence={**base_evidence, "status": status, "enforcement": "REQUIRE" if required else "OBSERVE"},
        )
        return FinancialContextDecision(status, required, False, None, reason, result)

    consent = db.query(models.SetuConsent).filter_by(
        org_id=org_id, setu_consent_id=binding.setu_consent_id, status="ACTIVE",
    ).first()
    if consent is None or (consent.consent_expires_at and consent.consent_expires_at <= now):
        status = "CONSENT_INACTIVE"
        reason = "Setu consent is revoked, expired or no longer active"
        result = PolicyResult(
            name="open_finance_context", passed=not required,
            detail=(reason if required else "Setu consent is inactive; context is ignored in observe-only posture"),
            evidence={**base_evidence, "status": status, "binding_id": binding.binding_id,
                      "enforcement": "REQUIRE" if required else "OBSERVE"},
        )
        return FinancialContextDecision(status, required, False, None, reason, result)

    snapshot = db.query(models.FinancialContextSnapshot).filter(
        models.FinancialContextSnapshot.org_id == org_id,
        models.FinancialContextSnapshot.setu_consent_id == consent.setu_consent_id,
        models.FinancialContextSnapshot.status.in_(["AVAILABLE", "PARTIAL"]),
    ).order_by(models.FinancialContextSnapshot.source_freshness_at.desc()).first()
    if snapshot is None:
        status = "AWAITING_DATA"
        reason = "No completed Setu financial-context snapshot is available"
        evidence = {**base_evidence, "status": status, "binding_id": binding.binding_id,
                    "setu_consent_id": consent.setu_consent_id,
                    "enforcement": "REQUIRE" if required else "OBSERVE"}
        result = PolicyResult(
            name="open_finance_context", passed=not required,
            detail=(reason if required else "Setu consent is active but no completed data snapshot is available; observe-only posture"),
            evidence=evidence,
        )
        return FinancialContextDecision(status, required, False, None, reason, result)

    freshness_at = snapshot.source_freshness_at
    age = (now - freshness_at) if freshness_at is not None else timedelta.max
    fresh = (freshness_at is not None and timedelta(minutes=-5) <= age <= _max_age()
             and snapshot.status == "AVAILABLE" and snapshot.completeness == "COMPLETE")
    status = "FRESH" if fresh else "STALE_OR_PARTIAL"
    reason = ("Fresh consented financial context is available" if fresh
              else "Financial context is stale, partial or incomplete")
    context = snapshot.normalized_context if isinstance(snapshot.normalized_context, dict) else {}
    accounts = context.get("accounts", []) if isinstance(context.get("accounts", []), list) else []
    currencies = sorted({str(x.get("currency")).upper() for x in accounts
                         if isinstance(x, dict) and x.get("currency")})
    evidence = {
        **base_evidence,
        "status": status,
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_digest": snapshot.raw_payload_digest,
        "binding_id": binding.binding_id,
        "setu_consent_id": consent.setu_consent_id,
        "account_count": len(accounts),
        "currencies": currencies,
        "completeness": snapshot.completeness,
        "source_freshness_at": freshness_at.isoformat() if freshness_at else None,
        "age_seconds": max(0, int(age.total_seconds())) if freshness_at else None,
        "enforcement": "REQUIRE" if required else "OBSERVE",
    }
    result = PolicyResult(
        name="open_finance_context",
        passed=(fresh or not required),
        detail=(reason if fresh or required else reason + "; context is observe-only"),
        evidence=evidence,
    )
    return FinancialContextDecision(status, required, fresh, snapshot.snapshot_id, reason, result)


def require_execution_financial_context(
    db: Session, *, intent: models.PaymentIntent, now: datetime | None = None
) -> None:
    """Recheck consent and freshness at execution when strict mode is enabled."""
    if not _enabled("PAARI_REQUIRE_FRESH_FINANCIAL_CONTEXT"):
        return
    if not intent.mandate_id:
        from fastapi import HTTPException
        raise HTTPException(403, "Execution requires a mandate-bound fresh Open Finance context")
    mandate = db.query(models.UserPaymentMandate).filter_by(
        org_id=intent.org_id, mandate_id=intent.mandate_id,
        status=models.MandateStatus.ACTIVE,
    ).first()
    decision = evaluate_financial_context(db, org_id=intent.org_id, mandate=mandate, now=now)
    if not decision.fresh:
        from fastapi import HTTPException
        raise HTTPException(403, "Execution blocked: " + decision.reason)
