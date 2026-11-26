"""Canonical, non-PII agreement records for federated payment governance."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class SignerRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject_type: Literal["USER", "SENDER_ORG"]
    subject_id: str = Field(min_length=1, max_length=128)
    public_key_pem: str = Field(min_length=80, max_length=4000)
    # Post-quantum Phase 5: algorithm the public key belongs to. Defaults to
    # ed25519 so existing (pre-PQC) enrolments are unchanged.
    public_key_algorithm: str = "ed25519"


class AgreementClaims(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agreement_id: str = Field(min_length=8, max_length=64)
    org_id: str = Field(min_length=1, max_length=64)
    agent_id: str = Field(min_length=1, max_length=64)
    beneficiary_id: str = Field(min_length=1, max_length=64)
    subject_type: Literal["USER", "SENDER_ORG", "RECEIVER"]
    subject_id: str = Field(min_length=1, max_length=128)
    purpose: str = Field(min_length=1, max_length=500)
    max_amount_minor_units: int = Field(gt=0, le=2_000_000_000)
    currency: str = Field(pattern=r"^[A-Z]{3,10}$")
    policy_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    document_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    issued_at: datetime
    expires_at: datetime


class SignedAgreement(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claims: AgreementClaims
    # Post-quantum Phase 2b: ML-DSA-65 base64 signatures are ~4,412 chars.
    # Ed25519 is 86 chars. Cap at 8,000 to fit any PQC signature.
    signature_b64: str = Field(min_length=40, max_length=8000)


class RevokeReason(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=8, max_length=240)
