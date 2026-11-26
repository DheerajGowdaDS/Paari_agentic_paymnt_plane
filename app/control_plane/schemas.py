"""Strict API contracts for organization, principal, resource and policy governance."""
from __future__ import annotations
from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator
from typing import Annotated

Identifier = Annotated[str, StringConstraints(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:/-]+$")]
Currency = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

class PrincipalCreate(StrictModel):
    external_subject_id: Identifier
    identity_provider: Identifier
    display_name: str = Field(min_length=1, max_length=200)

class PrincipalAttest(StrictModel):
    attestation_reference: str = Field(min_length=1, max_length=256)


class PrincipalVerifyRequest(StrictModel):
    verification_kind: Literal["INDIVIDUAL", "ORGANIZATION", "AUTHORIZED_REPRESENTATIVE", "UBO"] = "INDIVIDUAL"
    jurisdiction: str = Field(default="AE", pattern=r"^[A-Z]{2}$")


class PrincipalView(StrictModel):
    principal_id: str
    org_id: str
    external_subject_id: str
    identity_provider: str
    display_name: str
    status: str
    assurance_level: str
    identity_verification_status: str = "UNVERIFIED"
    verification_provider_id: str | None = None
    verification_expires_at: datetime | None = None
    created_at: datetime
    attested_at: datetime | None = None

class ResourceCreate(StrictModel):
    resource_type: Literal["bank_account", "open_banking_account", "stablecoin_wallet", "treasury_account", "provider_mandate", "data_set", "api"]
    provider_id: Identifier
    external_resource_ref: str = Field(min_length=1, max_length=256)
    owner_principal_id: str | None = None
    currency: Currency | None = None
    classification: Literal["public", "internal", "confidential", "restricted"] = "confidential"
    metadata: dict[str, str | int | bool | None] = Field(default_factory=dict, max_length=32)

class ResourceView(StrictModel):
    resource_id: str
    org_id: str
    resource_type: str
    provider_id: str
    external_resource_ref: str
    owner_principal_id: str | None
    currency: str | None
    classification: str
    status: str
    metadata: dict
    created_at: datetime

class ResourceGrantCreate(StrictModel):
    subject_type: Literal["agent", "principal"]
    subject_id: Identifier
    actions: list[Identifier] = Field(min_length=1, max_length=32)
    consent_reference: Identifier
    valid_from: datetime
    valid_until: datetime

class ResourceGrantView(StrictModel):
    grant_id: str
    org_id: str
    resource_id: str
    subject_type: str
    subject_id: str
    actions: list[str]
    consent_reference: str
    status: str
    valid_from: datetime
    valid_until: datetime
    created_at: datetime

class PolicyCreate(StrictModel):
    policy_name: Identifier = "payment_execution"
    version: Annotated[str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")]
    activate: bool = True
    min_evidence_quality_bps: int = Field(default=8500, ge=0, le=10000)
    observe_threshold_bps: int = Field(default=2500, ge=0, le=10000)
    escalate_threshold_bps: int = Field(default=6000, ge=0, le=10000)
    deny_threshold_bps: int = Field(default=9000, ge=0, le=10000)
    require_signed_mandate: bool = True
    # Organization opt-in for releasing an ESCALATE that is held only for
    # mandatory human review. Off by default; the org's release authority
    # is explicit, never implied by tenant provisioning.
    allow_signed_review_release: bool = False

    @model_validator(mode="after")
    def validate_threshold_order(self) -> "PolicyCreate":
        if not self.observe_threshold_bps < self.escalate_threshold_bps < self.deny_threshold_bps:
            raise ValueError("Thresholds must satisfy observe < escalate < deny")
        return self

class PolicyView(StrictModel):
    policy_id: str
    org_id: str
    policy_name: str
    version: str
    status: str
    rules: dict
    created_at: datetime
    activated_at: datetime | None = None


class OrganizationStatusUpdate(StrictModel):
    status: Literal["ACTIVE", "SUSPENDED"]
    reason: str = Field(min_length=5, max_length=256)


class ControlPlaneDecisionView(StrictModel):
    decision_id: str
    intent_id: str
    org_id: str
    principal_id: str | None
    resource_id: str | None
    policy_name: str
    policy_version: str
    disposition: Literal["DENY", "ESCALATE", "AUTO_EXECUTE", "OBSERVE"]
    reason_codes: list[str]
    reason_evidence: dict[str, Any] = Field(default_factory=dict)
    reason_catalog_version: str = "1.0"
    risk_score_bps: int | None
    evidence_quality_bps: int | None
    transaction_digest: str
    created_at: datetime


class AdminKeyCreate(StrictModel):
    org_id: Identifier
    scopes: list[Literal["control:read", "control:write"]] = Field(min_length=1)
    expires_at: datetime

    @model_validator(mode="after")
    def validate_expiry(self) -> "AdminKeyCreate":
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        if len(set(self.scopes)) != len(self.scopes):
            raise ValueError("scopes must not contain duplicates")
        return self

class AdminKeyIssued(StrictModel):
    key_id: str
    org_id: str
    key_prefix: str
    scopes: list[str]
    expires_at: datetime
    # Returned once. Never persisted by Paari.
    secret: str


class PortabilityImportValidate(StrictModel):
    """Destination-side preflight for importing agent identity metadata.

    This stages identity/provenance only. It cannot transfer active authority,
    credentials, mandates, provider tokens or bounded authorizations.
    """
    package: dict
    destination_parent_id: Identifier
    destination_principal_id: Identifier
    destination_resource_id: Identifier
    consent_reference: Identifier
