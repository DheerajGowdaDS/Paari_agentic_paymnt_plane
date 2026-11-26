"""Versioned SAFR Governance Envelope contract.

This module validates the submitted action contract and its sender signature. It
is deliberately not an authorization engine: callers must still resolve current
policy, authority, evidence and resource state before execution.
"""
from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from datetime import datetime, timezone
from typing import Literal, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator
from typing import Annotated

from app import crypto_utils

HEX64 = Annotated[str, StringConstraints(pattern=r"^[a-fA-F0-9]{64}$")]
Identifier = Annotated[str, StringConstraints(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:/-]+$")]
Currency = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]
MAX_ENVELOPE_TTL_SECONDS = 300
MAX_CLOCK_SKEW_SECONDS = 60


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ActionContext(StrictModel):
    """Minimal action facts; account numbers and provider credentials do not belong here."""
    resource_id: Identifier
    operation: Identifier
    amount_minor_units: int | None = Field(default=None, ge=1, le=9_000_000_000_000_000)
    currency: Currency | None = None
    # Hash an opaque beneficiary/instrument reference; do not put account numbers in envelopes.
    beneficiary_ref_digest: HEX64 | None = None
    merchant: str | None = Field(default=None, min_length=1, max_length=160)
    purpose: str | None = Field(default=None, min_length=1, max_length=240)
    provider_id: Identifier | None = None
    jurisdiction: Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")] = "AE"
    request_context_digest: HEX64


class ActionTrace(StrictModel):
    trace_id: Identifier
    source_system: Identifier
    sequence: int = Field(ge=0)
    parent_trace_id: Identifier | None = None
    trace_digest: HEX64


class EvidenceReference(StrictModel):
    evidence_id: Identifier
    evidence_type: Literal[
        "identity_attestation", "kyb_attestation", "mandate_signature",
        "consent_record", "provider_read", "transaction_trace", "screening_result",
        "resource_grant", "other",
    ]
    source: Identifier
    digest: HEX64
    observed_at: datetime | None = None

    @model_validator(mode="after")
    def observed_at_must_be_aware(self):
        if self.observed_at is not None and (self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None):
            raise ValueError("evidence observed_at must be timezone-aware")
        return self


class GovernanceEnvelope(StrictModel):
    """Agent-signed proposal envelope; it does not itself confer spending authority."""
    envelope_type: Literal["paari.safr.governance-envelope"] = "paari.safr.governance-envelope"
    schema_version: Literal["1.0"] = "1.0"
    envelope_id: str = Field(default_factory=lambda: str(uuid.uuid4()), min_length=36, max_length=36)
    tenant_id: Identifier
    agent_id: Identifier
    parent_id: Identifier
    principal_id: Identifier
    resource_id: Identifier
    mandate_id: Identifier | None = None
    action_type: Literal["payment.execute", "payment.refund", "data.read", "data.write", "api.invoke"]
    action_context: ActionContext
    trace: ActionTrace
    evidence_refs: list[EvidenceReference] = Field(default_factory=list, max_length=32)
    issued_at: datetime
    expires_at: datetime
    signing_key_fingerprint: HEX64
    action_digest: HEX64
    signature_b64: str = Field(min_length=80, max_length=256)

    @model_validator(mode="after")
    def validate_timestamps_and_payment_context(self):
        for name in ("issued_at", "expires_at"):
            value = getattr(self, name)
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{name} must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        if (self.expires_at - self.issued_at).total_seconds() > MAX_ENVELOPE_TTL_SECONDS:
            raise ValueError("envelope TTL exceeds protocol maximum")
        if (self.action_type.startswith("payment.") and
                (self.mandate_id is None or self.action_context.amount_minor_units is None
                 or self.action_context.currency is None
                 or self.action_context.beneficiary_ref_digest is None
                 or self.action_context.purpose is None)):
            raise ValueError("payment envelopes require mandate, amount, currency, beneficiary digest and purpose")
        if self.resource_id != self.action_context.resource_id:
            raise ValueError("top-level resource_id must match action_context.resource_id")
        try:
            uuid.UUID(self.envelope_id)
        except ValueError as exc:
            raise ValueError("envelope_id must be a UUID") from exc
        return self


def _utc_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def action_digest_fields(envelope: GovernanceEnvelope | dict[str, Any]) -> dict[str, Any]:
    """Select the exact authority/action scope that must be integrity bound."""
    data = envelope.model_dump(mode="json") if isinstance(envelope, GovernanceEnvelope) else envelope
    return {
        "envelope_id": data["envelope_id"],
        "tenant_id": data["tenant_id"],
        "agent_id": data["agent_id"],
        "parent_id": data["parent_id"],
        "principal_id": data["principal_id"],
        "resource_id": data["resource_id"],
        "mandate_id": data.get("mandate_id"),
        "action_type": data["action_type"],
        "action_context": data["action_context"],
    }


def compute_action_digest(envelope: GovernanceEnvelope | dict[str, Any]) -> str:
    encoded = crypto_utils.canonical_json(action_digest_fields(envelope)).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def signing_payload(envelope: GovernanceEnvelope | dict[str, Any]) -> dict[str, Any]:
    """Return canonical-signable fields including digests, excluding only signature."""
    data = envelope.model_dump(mode="json") if isinstance(envelope, GovernanceEnvelope) else dict(envelope)
    data.pop("signature_b64", None)
    return data


def envelope_digest(envelope: GovernanceEnvelope | dict[str, Any]) -> str:
    return hashlib.sha256(crypto_utils.canonical_json(signing_payload(envelope)).encode("utf-8")).hexdigest()


def beneficiary_reference_digest(beneficiary_reference: str) -> str:
    """Digest an opaque beneficiary reference without placing it on the wire.

    The current checkout-compatible PaymentIntent model only stores a merchant
    alias, so sandbox clients may use that alias as the beneficiary reference.
    Open-banking/bank adapters should pass a provider-issued opaque beneficiary
    reference instead; raw account numbers must never be put in the envelope.
    """
    reference = beneficiary_reference.strip()
    if not reference:
        raise ValueError("beneficiary reference must be non-empty")
    payload = {"scheme": "paari-beneficiary-ref-v1", "reference": reference.casefold()}
    return hashlib.sha256(crypto_utils.canonical_json(payload).encode("utf-8")).hexdigest()


def validate_envelope_time(envelope: GovernanceEnvelope, *, now_epoch: int | None = None) -> None:
    now = int(time.time()) if now_epoch is None else int(now_epoch)
    issued = int(envelope.issued_at.timestamp())
    expires = int(envelope.expires_at.timestamp())
    if issued > now + MAX_CLOCK_SKEW_SECONDS:
        raise ValueError("envelope issued_at is in the future")
    # Expiry is strict: clock-skew allowance applies to a future issued_at, not
    # to a request that has already expired. Allowing an expired envelope to pass
    # for a grace window would extend authority beyond the signed validity.
    if expires <= now:
        raise ValueError("envelope expired")
    if expires <= issued or expires - issued > MAX_ENVELOPE_TTL_SECONDS:
        raise ValueError("envelope TTL exceeds protocol maximum")


def verify_envelope_signature(envelope: GovernanceEnvelope, public_key_pem: str, *, now_epoch: int | None = None, algorithm: str = "ed25519") -> None:
    """Validate freshness, action binding, key thumbprint and signature."""
    validate_envelope_time(envelope, now_epoch=now_epoch)
    expected_digest = compute_action_digest(envelope)
    if not hmac.compare_digest(expected_digest, envelope.action_digest.lower()):
        raise ValueError("action_digest does not match the signed action context")
    expected_fingerprint = crypto_utils.public_key_fingerprint(public_key_pem, algorithm=algorithm)
    if not hmac.compare_digest(expected_fingerprint.lower(), envelope.signing_key_fingerprint.lower()):
        raise ValueError("signing key fingerprint does not match registered key")
    if not crypto_utils.verify_signature(public_key_pem, crypto_utils.canonical_json(signing_payload(envelope)), envelope.signature_b64, algorithm=algorithm):
        raise ValueError("envelope signature verification failed")
