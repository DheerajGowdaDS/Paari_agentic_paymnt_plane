"""Fail-closed receiver controls; called at intent and at execution time.

This module never declares a bank deposit or blockchain finality. It verifies
that the selected beneficiary can be targeted by this payer org and agent.
"""
from __future__ import annotations
import os
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app import models


def receiver_enforced() -> bool:
    return (os.environ.get("PAARI_RECEIVER_ENFORCEMENT") == "1"
            or os.environ.get("PAARI_REQUIRE_RECEIVER_PRECHECK") == "1"
            or os.environ.get("PAARI_LIVE") == "1"
            or os.environ.get("PAARI_ENV", "").lower() in {"prod", "prod-live"})


def receiver_precheck_required() -> bool:
    return (os.environ.get("PAARI_REQUIRE_RECEIVER_PRECHECK") == "1"
            or os.environ.get("PAARI_ENV", "").lower() in {"prod", "prod-live"}
            or os.environ.get("PAARI_LIVE") == "1")


def check_receiver(db: Session, *, org_id: str, beneficiary_id: str | None,
                   merchant: str, amount_minor_units: int, currency: str) -> tuple[bool, str]:
    if not beneficiary_id:
        return False, "receiver beneficiary ID is required"
    ben = db.query(models.ReceiverBeneficiary).filter_by(
        org_id=org_id, beneficiary_id=beneficiary_id).first()
    if not ben or ben.status != "ACTIVE":
        return False, "beneficiary is missing, blocked or outside the sending organization"
    inst = db.query(models.ReceiverInstitution).filter_by(
        org_id=org_id, receiver_id=ben.receiver_id).first()
    if not inst or inst.status != "ACTIVE" or inst.identity_assurance != "ADMIN_APPROVED":
        return False, "receiving institution has not been approved or is suspended"
    if ben.alias.strip().casefold() != merchant.strip().casefold():
        return False, "payment merchant does not match the governed beneficiary alias"
    if currency.upper() != ben.currency.upper():
        return False, "beneficiary currency does not match payment currency"
    if amount_minor_units <= 0 or amount_minor_units > ben.max_payment_minor_units:
        return False, "payment exceeds beneficiary limits"
    return True, "receiving institution and beneficiary controls passed"


def require_execution_receiver(db: Session, *, org_id: str, intent_id: str,
                               merchant: str, amount_minor_units: int, currency: str) -> None:
    if not receiver_enforced():
        return
    intent = db.query(models.PaymentIntent).filter_by(intent_id=intent_id, org_id=org_id).first()
    if not intent:
        raise HTTPException(status_code=403, detail="Original payment intent is missing")
    ok, reason = check_receiver(db, org_id=org_id, beneficiary_id=intent.beneficiary_id,
                               merchant=merchant, amount_minor_units=amount_minor_units, currency=currency)
    if not ok:
        raise HTTPException(status_code=403, detail=f"Receiver revalidation failed: {reason}")

    # Optional strict two-sided acceptance handshake. The receiver signs an
    # ACCEPTED acknowledgement for this exact intent before execution. Any
    # REJECTED acknowledgement is a hard stop for this intent; acceptance is
    # not a settlement signal and cannot move provider state to PAID.
    if receiver_precheck_required():
        # Resolve the actual registered receiver ID from the beneficiary.
        ben = db.query(models.ReceiverBeneficiary).filter_by(
            org_id=org_id, beneficiary_id=intent.beneficiary_id
        ).first()
        if not ben:
            raise HTTPException(status_code=403, detail="Receiver precheck beneficiary is unavailable")
        attestations = db.query(models.ReceiverAttestation).filter_by(
            org_id=org_id, intent_id=intent_id, receiver_id=ben.receiver_id,
            beneficiary_id=ben.beneficiary_id
        ).order_by(models.ReceiverAttestation.id.asc()).all()
        if any(a.result == "REJECTED" for a in attestations):
            raise HTTPException(status_code=403, detail="Receiver precheck rejected this payment intent")
        if not any(a.result == "ACCEPTED" for a in attestations):
            raise HTTPException(status_code=409, detail="Receiver signed acceptance is required before payment execution")
