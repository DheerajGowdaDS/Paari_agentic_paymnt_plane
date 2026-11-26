"""v4.0 signed receiver acceptance must precede payment execution."""
from datetime import datetime, timezone
import uuid

import pytest
from fastapi import HTTPException

from app import crypto_utils, models
from app.receivers.policy import require_execution_receiver
from app.receivers.router import ReceiverClaim
from tests.test_v34_receivers import _create, _approve, _beneficiary, _intent


def _signed_claim(ctx, receiver_id, beneficiary_id, intent_id, private_key, result):
    claim = {
        "event_id": f"v40-{result.lower()}-{uuid.uuid4().hex}",
        "receiver_id": receiver_id,
        "beneficiary_id": beneficiary_id,
        "intent_id": intent_id,
        "result": result,
        "provider_reference": f"receiver-ref-{uuid.uuid4().hex[:12]}",
        "amount_minor_units": 1000,
        "currency": "INR",
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }
    parsed = ReceiverClaim.model_validate(claim)
    signature = crypto_utils.sign_with_private_key(
        private_key, crypto_utils.canonical_json(parsed.model_dump(mode="json"))
    )
    response = ctx.client.post(
        "/control/v1/receivers/attestations",
        json={"claim": claim, "signature_b64": signature},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_signed_receiver_acceptance_is_required_before_execution(paari_client, monkeypatch):
    ctx = paari_client
    headers, receiver_id, private_key = _create(ctx, monkeypatch)
    _approve(ctx, receiver_id)
    beneficiary_id = _beneficiary(ctx, monkeypatch, headers, receiver_id)
    monkeypatch.setenv("PAARI_RECEIVER_ENFORCEMENT", "1")
    monkeypatch.setenv("PAARI_REQUIRE_RECEIVER_PRECHECK", "1")

    created = _intent(ctx, beneficiary_id)
    assert created.status_code == 200, created.text
    assert created.json()["decision"] == "allow", created.text
    intent_id = created.json()["intent_id"]

    db = ctx.Session()
    try:
        intent = db.query(models.PaymentIntent).filter_by(intent_id=intent_id).one()
        with pytest.raises(HTTPException) as missing:
            require_execution_receiver(
                db, org_id=intent.org_id, intent_id=intent_id,
                merchant=intent.merchant, amount_minor_units=intent.amount_minor_units,
                currency=intent.currency,
            )
        assert missing.value.status_code == 409
    finally:
        db.close()

    accepted = _signed_claim(ctx, receiver_id, beneficiary_id, intent_id, private_key, "ACCEPTED")
    assert accepted["receiver_signature_verified"] is True
    assert accepted["settlement_confirmed"] is False

    db = ctx.Session()
    try:
        intent = db.query(models.PaymentIntent).filter_by(intent_id=intent_id).one()
        require_execution_receiver(
            db, org_id=intent.org_id, intent_id=intent_id,
            merchant=intent.merchant, amount_minor_units=intent.amount_minor_units,
            currency=intent.currency,
        )
    finally:
        db.close()


def test_receiver_rejection_is_hard_stop_even_after_acceptance(paari_client, monkeypatch):
    ctx = paari_client
    headers, receiver_id, private_key = _create(ctx, monkeypatch)
    _approve(ctx, receiver_id)
    beneficiary_id = _beneficiary(ctx, monkeypatch, headers, receiver_id)
    monkeypatch.setenv("PAARI_RECEIVER_ENFORCEMENT", "1")
    monkeypatch.setenv("PAARI_REQUIRE_RECEIVER_PRECHECK", "1")

    created = _intent(ctx, beneficiary_id)
    assert created.status_code == 200 and created.json()["decision"] == "allow"
    intent_id = created.json()["intent_id"]

    _signed_claim(ctx, receiver_id, beneficiary_id, intent_id, private_key, "ACCEPTED")
    _signed_claim(ctx, receiver_id, beneficiary_id, intent_id, private_key, "REJECTED")

    db = ctx.Session()
    try:
        intent = db.query(models.PaymentIntent).filter_by(intent_id=intent_id).one()
        with pytest.raises(HTTPException) as rejected:
            require_execution_receiver(
                db, org_id=intent.org_id, intent_id=intent_id,
                merchant=intent.merchant, amount_minor_units=intent.amount_minor_units,
                currency=intent.currency,
            )
        assert rejected.value.status_code == 403
        assert "rejected" in rejected.value.detail.lower()
    finally:
        db.close()
