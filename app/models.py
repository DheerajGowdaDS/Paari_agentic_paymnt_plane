"""
Core data model.

Phase 1-2: Agent, Credential, AuthNonce (unchanged in shape).
  - ParentAuthority: a registered, independently-keyed trust root. An agent
    is only as trustworthy as the parent that vouches for it. Registration
    now lands in PENDING_VERIFICATION, not ACTIVE (see P0 fix note below).
  - DelegationRecord: tracks each signed delegation document a parent has
    issued, so a delegation can never be replayed to register a second
    agent or reused after registration.
  - PaymentIntent: one row per payment request evaluated by the Phase 3
    governance engine - the audit trail of what was decided and why.
  - BoundedAuthorization: the single-use, short-lived authorization Phase 4
    produces on ALLOW, which is what actually gets handed to Razorpay.
  - MFAChallenge: a server-issued, single-use nonce binding a specific
    REVIEW-ed payment intent to a step-up approval that must be signed by
    the *parent's* key (a distinct key from the agent's) before the intent
    can be promoted to ALLOW. Replaces the old client-supplied
    `mfa_verified: bool`.
  - RevocationRecord: anti-replay for parent-signed agent revocations, the
    same pattern DelegationRecord uses for delegations.

P0 fix: every timestamp column below uses `UTCDateTime` (app/database.py)
instead of a plain `DateTime(timezone=True)`, which SQLite silently stores
as naive and which caused the offset-naive/offset-aware crash in Phase 2.
"""
import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    String, Boolean, JSON, ForeignKey, Enum, Integer, Text, UniqueConstraint, Index, CheckConstraint, text
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, UTCDateTime


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AgentStatus(str, enum.Enum):
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"


class ParentStatus(str, enum.Enum):
    PENDING_VERIFICATION = "pending_verification"
    ACTIVE = "active"
    REJECTED = "rejected"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class GovernanceDecision(str, enum.Enum):
    ALLOW = "allow"
    REVIEW = "review"
    DENY = "deny"


class MandateStatus(str, enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


# ---------------------------------------------------------------------------
# Multi-tenancy (Phase 6 Task 8): every tenant-scoped row carries org_id.
# Python-side default "default" keeps old seeds/tests working; migration
# 0008 backfills existing rows and flips the columns to NOT NULL.
# ---------------------------------------------------------------------------

class Organization(Base):
    """A tenant. Suspended tenants cannot authorize payments in strict mode."""
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


class ProviderAccount(Base):
    """Marker row selecting an organization's provider; secrets stay in env."""
    __tablename__ = "provider_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[str] = mapped_column(String(64), unique=True)
    provider_name: Mapped[str] = mapped_column(String(32), default="razorpay", server_default="razorpay")
    key_id_label: Mapped[str] = mapped_column(String(200), default="default")
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


# ---------------------------------------------------------------------------
# Parent / Authority
# ---------------------------------------------------------------------------

class ParentAuthority(Base):
    """
    A trust root: a company, developer, platform, another agent, or an IdP
    that can vouch for and delegate authority to agents. Parents hold their
    own Ed25519 key pair (private key never given to Paari) and sign
    delegation documents with it.

    P0 fix: registration no longer grants ParentStatus.ACTIVE immediately.
    Every new parent starts PENDING_VERIFICATION and cannot delegate to any
    agent (agent registration and payment governance both hard-require
    ACTIVE) until an administrator approves it via POST
    /parents/{parent_id}/approve. This is where real identity-proofing
    (KYB, business-registry lookup, domain verification, IdP federation)
    plugs in - the admin-approval gate is the minimum viable version of
    that step, not a replacement for it.
    """
    __tablename__ = "parent_authorities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    parent_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), default="default")

    name: Mapped[str] = mapped_column(String(200))
    parent_type: Mapped[str] = mapped_column(String(50))  # company | developer | platform | agent | idp
    contact: Mapped[str] = mapped_column(String(200))

    public_key_pem: Mapped[str] = mapped_column(String(8000))
    # Post-quantum migration: track which signature algorithm this key uses.
    # Default ed25519 preserves backward compatibility with existing keys.
    public_key_algorithm: Mapped[str] = mapped_column(String(20), default="ed25519")
    status: Mapped[ParentStatus] = mapped_column(Enum(ParentStatus), default=ParentStatus.PENDING_VERIFICATION)
    # Production trust tier: how this parent was verified.
    # self_asserted (registered, nothing checked) -> admin_approved (human
    # gate) -> kyb_verified (KYB vendor reference recorded, no vendor call).
    trust_tier: Mapped[str] = mapped_column(String(20), default="self_asserted")
    kyb_provider_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    agents: Mapped[list["Agent"]] = relationship(back_populates="parent")


class DelegationRecord(Base):
    """
    Tracks a signed delegation document once it has been consumed by an
    agent registration, so the exact same delegation can never be replayed
    to bind a second agent or re-register the same one.
    """
    __tablename__ = "delegation_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    delegation_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    org_id: Mapped[str] = mapped_column(String(64), default="default")
    parent_pk: Mapped[int] = mapped_column(ForeignKey("parent_authorities.id"))

    agent_public_key_fingerprint: Mapped[str] = mapped_column(String(64))
    # Preserve the exact parent-signed artifact for offline verification/portability.
    # Nullable for legacy delegations created before v2.7; those cannot be exported as verifiable packages.
    delegation_signature_b64: Mapped[str | None] = mapped_column(String(8000), nullable=True)
    delegation_algorithm: Mapped[str | None] = mapped_column(String(20), nullable=True)
    granted_capabilities: Mapped[list] = mapped_column(JSON)
    payment_limit_minor_units: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(10))

    issued_at: Mapped[datetime] = mapped_column(UTCDateTime)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class RevocationRecord(Base):
    """
    Anti-replay for parent-signed agent revocations (see routers/agents.py).
    A given revocation_id can only ever be consumed once, exactly like a
    DelegationRecord - otherwise a captured signed revocation could be
    replayed, or (worse) a stale one could be replayed to knock out an
    agent's *new* credential after re-registration.
    """
    __tablename__ = "revocation_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    revocation_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    org_id: Mapped[str] = mapped_column(String(64), default="default")
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    consumed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


# ---------------------------------------------------------------------------
# Agent / Credential / Auth (Phase 1-2)
# ---------------------------------------------------------------------------

class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), default="default")

    name: Mapped[str] = mapped_column(String(200))
    agent_type: Mapped[str] = mapped_column(String(100))
    purpose: Mapped[str] = mapped_column(String(500))

    parent_pk: Mapped[int] = mapped_column(ForeignKey("parent_authorities.id"))
    parent: Mapped["ParentAuthority"] = relationship(back_populates="agents")
    delegation_id: Mapped[str] = mapped_column(String(64))  # which delegation bound this agent

    public_key_pem: Mapped[str] = mapped_column(String(8000))
    # Post-quantum migration: track which signature algorithm this key uses.
    public_key_algorithm: Mapped[str] = mapped_column(String(20), default="ed25519")
    # Rotation: previous key stays verifiable until key_sunset_at (24h
    # grace for in-flight clients), then fails closed.
    old_public_key_pem: Mapped[str | None] = mapped_column(String(8000), nullable=True)
    old_public_key_algorithm: Mapped[str | None] = mapped_column(String(20), nullable=True)
    key_sunset_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    # Granted by the parent's delegation - never self-requested by the agent.
    granted_capabilities: Mapped[list] = mapped_column(JSON, default=list)
    payment_limit_minor_units: Mapped[int] = mapped_column(Integer, default=0)
    currency: Mapped[str] = mapped_column(String(10), default="INR")

    status: Mapped[AgentStatus] = mapped_column(Enum(AgentStatus), default=AgentStatus.PENDING)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    valid_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # Protocol version this agent onboarded with ("1.0" for v1; NULL = legacy).
    protocol_version: Mapped[str | None] = mapped_column(String(10), nullable=True)

    credentials: Mapped[list["Credential"]] = relationship(back_populates="agent")


class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    credential_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), default="default")

    agent_pk: Mapped[int] = mapped_column(ForeignKey("agents.id"))
    agent: Mapped["Agent"] = relationship(back_populates="credentials")

    signed_jwt: Mapped[str] = mapped_column(String(4000))
    issued_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    # Rotation chain: superseded_by points at the replacing credential.
    superseded_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rotates_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class AuthNonce(Base):
    __tablename__ = "auth_nonces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    nonce: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), default="default")
    agent_id: Mapped[str] = mapped_column(String(64), index=True)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


# ---------------------------------------------------------------------------
# User payment authority (Paari v2)
# ---------------------------------------------------------------------------

class UserPaymentMandate(Base):
    """Bounded user/trusted-surface authority for autonomous agent payments.

    This is intentionally separate from parent delegation. Delegation answers
    what an agent is allowed to do; the mandate answers what the user allows
    the agent to spend. Provider credentials are not stored here.
    """
    __tablename__ = "user_payment_mandates"
    __table_args__ = (
        # Created by hand in migration d0e1f2a3b4c5 for the active-mandate
        # lookup. Declaring it here keeps the model and the database describing
        # the same object, so `alembic check` stops reporting it as an extra
        # index in the schema that the model knows nothing about.
        Index(
            "ix_user_payment_mandates_active_lookup",
            "agent_id", "org_id", "status", "expires_at",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mandate_id: Mapped[str] = mapped_column(String(64), unique=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    user_id: Mapped[str] = mapped_column(String(128), index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.agent_id"), index=True)

    max_per_transaction: Mapped[int] = mapped_column(Integer)
    max_daily_amount: Mapped[int] = mapped_column(Integer)
    # Paari v2 Sprint 6: finer-grained spending windows. NULL = limit not set
    # and therefore not enforced for that dimension.
    max_per_hour: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_per_merchant_per_day: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_category_per_day: Mapped[int | None] = mapped_column(Integer, nullable=True)
    currency: Mapped[str] = mapped_column(String(10))
    allowed_merchants: Mapped[list | None] = mapped_column(JSON, nullable=True)
    allowed_categories: Mapped[list | None] = mapped_column(JSON, nullable=True)
    require_review_above: Mapped[int | None] = mapped_column(Integer, nullable=True)

    valid_from: Mapped[datetime] = mapped_column(UTCDateTime)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    status: Mapped[MandateStatus] = mapped_column(Enum(MandateStatus), default=MandateStatus.ACTIVE)
    approval_reference: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    # Paari v2 Sprint 5: cryptographic mandate signing. The signature is over
    # canonical_json(mandate_payload(mandate)) - never over the signature
    # itself - made by the user's (or trusted surface's) Ed25519 key. Paari
    # stores the user public key at creation time so verification stays
    # possible even if the trusted surface rotates keys later.
    signing_key_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    signing_algorithm: Mapped[str | None] = mapped_column(String(20), nullable=True)
    signature_b64: Mapped[str | None] = mapped_column(String(8000), nullable=True)
    user_public_key_pem: Mapped[str | None] = mapped_column(String(8000), nullable=True)
    signed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class SetuConsent(Base):
    """Tenant-bound Setu AA consent metadata; never payment authority."""
    __tablename__ = "setu_consents"
    __table_args__ = (
        UniqueConstraint("org_id", "provider_consent_id", name="uq_setu_consent_org_provider"),
        Index("ix_setu_consents_org_subject_status", "org_id", "subject_user_id", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    setu_consent_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    subject_user_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    provider_consent_id: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    purpose_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    consent_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, nullable=False)


class SetuConsentMandateBinding(Base):
    """Explicit user-scoped permission to use Setu context with one mandate."""
    __tablename__ = "setu_consent_mandate_bindings"
    __table_args__ = (
        UniqueConstraint("org_id", "setu_consent_id", "mandate_id", name="uq_setu_binding_org_consent_mandate"),
        Index("ix_setu_binding_org_subject_status", "org_id", "subject_user_id", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    binding_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    setu_consent_id: Mapped[str] = mapped_column(ForeignKey("setu_consents.setu_consent_id"), nullable=False, index=True)
    mandate_id: Mapped[str] = mapped_column(ForeignKey("user_payment_mandates.mandate_id"), nullable=False, index=True)
    subject_user_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    purpose_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class SetuDataSession(Base):
    """Tenant-bound lifecycle state for one provider Setu data session."""
    __tablename__ = "setu_data_sessions"
    __table_args__ = (
        UniqueConstraint("org_id", "provider_session_id", name="uq_setu_session_org_provider"),
        Index("ix_setu_sessions_org_consent_status", "org_id", "setu_consent_id", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    data_session_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    setu_consent_id: Mapped[str] = mapped_column(
        ForeignKey("setu_consents.setu_consent_id"), nullable=False, index=True
    )
    provider_session_id: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, nullable=False)


class FinancialContextSnapshot(Base):
    """Encrypted Setu source data plus the minimal normalized policy context."""
    __tablename__ = "financial_context_snapshots"
    __table_args__ = (
        Index(
            "ix_financial_context_snapshots_org_consent_status",
            "org_id", "setu_consent_id", "status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    snapshot_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    setu_consent_id: Mapped[str] = mapped_column(
        ForeignKey("setu_consents.setu_consent_id"), nullable=False, index=True
    )
    data_session_id: Mapped[str] = mapped_column(
        ForeignKey("setu_data_sessions.data_session_id"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    raw_payload_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_payload_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    normalized_context: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    normalized_context_version: Mapped[str] = mapped_column(String(64), nullable=False, default="1.0")
    source_freshness_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    completeness: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, nullable=False)


class PaymentInstrumentBinding(Base):
    """Provider-issued reference for a user-authorized payment mandate.

    Paari stores only references/tokens issued by the provider; never raw
    card numbers, CVV, UPI PINs, or bank passwords. The current Razorpay
    adapter does not implement autonomous settlement yet; this table is the
    provider-neutral bridge for that future capability.
    """
    __tablename__ = "payment_instrument_bindings"
    __table_args__ = (
        Index("uq_provider_mandate_ref", "provider", "provider_mandate_ref", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    binding_id: Mapped[str] = mapped_column(String(64), unique=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    mandate_id: Mapped[str] = mapped_column(ForeignKey("user_payment_mandates.mandate_id"), index=True)
    # Explicit source-resource link for institutional control-plane enforcement.
    # NULL is retained only for legacy/sandbox compatibility; production mode
    # requires this value before an authorization can be issued.
    source_resource_id: Mapped[str | None] = mapped_column(ForeignKey("governed_resources.resource_id"), nullable=True, index=True)
    provider: Mapped[str] = mapped_column(String(50))
    provider_customer_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    provider_mandate_ref: Mapped[str] = mapped_column(String(200))
    provider_instrument_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    currency: Mapped[str] = mapped_column(String(10))
    max_amount_minor_units: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), default="active")
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


# ---------------------------------------------------------------------------
# Payment Governance (Phase 3) / Bounded Authorization (Phase 4)
# ---------------------------------------------------------------------------

class PaymentIntent(Base):
    """
    One row per payment request evaluated - the governance audit trail.

    P1 fix: idempotency is now scoped to (agent_id, idempotency_key), with
    a real unique constraint, instead of a bare idempotency_key that any
    caller could collide with (or race) regardless of which agent it
    belonged to.
    """
    __tablename__ = "payment_intents"
    __table_args__ = (
        UniqueConstraint("agent_id", "idempotency_key", name="uq_payment_intents_agent_idem"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    intent_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), default="default")

    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.agent_id"), index=True)
    transaction_id: Mapped[str] = mapped_column(String(100), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(100), index=True)
    mandate_id: Mapped[str | None] = mapped_column(ForeignKey("user_payment_mandates.mandate_id"), nullable=True, index=True)
    beneficiary_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    v36_provider_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    v36_provider_policy_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    merchant: Mapped[str] = mapped_column(String(200))
    amount_minor_units: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(10))
    action: Mapped[str] = mapped_column(String(50))
    purpose: Mapped[str] = mapped_column(String(500), default="")
    merchant_category: Mapped[str | None] = mapped_column(String(80), nullable=True)

    # Paari v2 Sprint 7: minimum LLM causal identifiers. Never store the
    # conversation or any secret - just the trace identifiers that connect a
    # model tool invocation to this governed payment request.
    #
    # These are CLIENT-ASSERTED trace labels. Paari proves that the
    # authenticated agent submitted them (they ride on a sender-constrained
    # Paari-Proof-JWT); it does NOT and cannot prove a model produced them,
    # because the ids originate from the LLM. `llm_attributed` records
    # whether attribution was even claimed, so an auditor can tell a real
    # LLM-attributed payment from a plain protocol client.
    llm_run_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    llm_model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    llm_tool_call_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    llm_tool_name: Mapped[str | None] = mapped_column(String(80), nullable=True)
    llm_attributed: Mapped[bool] = mapped_column(Boolean, default=False)

    decision: Mapped[GovernanceDecision] = mapped_column(Enum(GovernanceDecision))
    reasons: Mapped[list] = mapped_column(JSON, default=list)  # every check result, for audit
    reason_codes: Mapped[list] = mapped_column(JSON, default=list)
    reason_evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    reason_catalog_version: Mapped[str] = mapped_column(String(24), default="1.0")
    mfa_required: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    # Task 2: velocity REVIEWs park for REVIEW_TTL instead of forever. A
    # resubmission is accepted once this passes; NULL means "not a
    # velocity-parked intent" (ALLOW/DENY rows and MFA-step-up REVIEWs).
    review_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


class MFAChallenge(Base):
    """
    Phase 3 step-up MFA - P0 fix for the `mfa_verified: bool` trust
    problem.

    A payment intent that lands on REVIEW because it needs step-up MFA is
    NOT allowed to self-certify. Instead:

      1. The caller requests a challenge for that specific intent_id.
      2. Paari mints a single-use nonce bound to that intent's exact
         context (agent, transaction, merchant, amount, currency) and
         returns the canonical string that must be signed.
      3. The *parent authority* (a different key than the agent's) signs
         that exact string with its private key - out-of-band, e.g. a
         human approver at the parent org - and the signature is submitted
         back to Paari.
      4. Paari verifies the signature against the parent's registered
         public key, burns the challenge, and only then promotes the
         intent to ALLOW and mints a BoundedAuthorization.

    This is a genuine second factor (a distinct key holder, not the agent
    re-proving the same key) and it is bound to the specific transaction,
    so a captured approval can't be replayed against a different amount.
    """
    __tablename__ = "mfa_challenges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    challenge_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)

    # Not unique: an expired-but-unused challenge for an intent is
    # invalidated (marked used) before a fresh one is issued, so retries
    # after a lost response don't get stuck behind a DB uniqueness error.
    intent_id: Mapped[str] = mapped_column(ForeignKey("payment_intents.intent_id"), index=True)
    org_id: Mapped[str] = mapped_column(String(64), default="default")
    nonce: Mapped[str] = mapped_column(String(64), default=_uuid)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class BoundedAuthorization(Base):
    """
    The Phase 4 artifact: a single-use, short-lived authorization handed to
    the payment provider layer. Never gives the agent standing/reusable
    payment authority.
    """
    __tablename__ = "bounded_authorizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    authorization_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), default="default")

    intent_id: Mapped[str] = mapped_column(ForeignKey("payment_intents.intent_id"), index=True)
    mandate_id: Mapped[str | None] = mapped_column(ForeignKey("user_payment_mandates.mandate_id"), nullable=True, index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.agent_id"), index=True)
    transaction_id: Mapped[str] = mapped_column(String(100))
    merchant: Mapped[str] = mapped_column(String(200))
    amount_minor_units: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(10))

    token: Mapped[str] = mapped_column(Text)  # signed JWT encoding the same bounds, for the provider layer
    issued_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    max_usage: Mapped[int] = mapped_column(Integer, default=1)
    usage_count: Mapped[int] = mapped_column(Integer, default=0)


class ProviderTransaction(Base):
    """
    Phase 5 execution state for one bounded authorization.

    States: AUTHORIZED -> PROVIDER_SUBMITTED -> PROVIDER_AUTHORIZED -> CAPTURED
           -> PAID, with FAILED / DECLINED / EXPIRED / CANCELLED / PROVIDER_UNKNOWN
           off the happy path and REFUNDED / REVERSED after it. The single source of
           truth is app/transitions.py; PAYMENT_PENDING is the retired spelling of
           PROVIDER_AUTHORIZED.
    (REFUNDED reserved for a later refund path; never set here).
    One row per authorization_id; provider order/event ids are unique so
    retries and webhook replays stay idempotent.
    """
    __tablename__ = "provider_transactions"
    __table_args__ = (
        Index("uq_provider_transactions_provider_order_id", "provider_name", "provider_order_id", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    authorization_id: Mapped[str] = mapped_column(ForeignKey("bounded_authorizations.authorization_id"), unique=True, index=True)
    intent_id: Mapped[str] = mapped_column(ForeignKey("payment_intents.intent_id"), index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.agent_id"), index=True)
    org_id: Mapped[str] = mapped_column(String(64), default="default")
    provider_name: Mapped[str] = mapped_column(String(32), default="razorpay", server_default="razorpay")

    state: Mapped[str] = mapped_column(String(30), default="AUTHORIZED")
    provider_order_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    provider_payment_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    razorpay_order_id: Mapped[str | None] = mapped_column(String(100), unique=True, nullable=True)
    razorpay_payment_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    webhook_event_id: Mapped[str | None] = mapped_column(String(100), unique=True, nullable=True)

    # PROVENANCE OF THE PROVIDER OBJECT. Recorded at submit time from the
    # credentials the adapter actually used - never from a client claim and
    # never inferred later. Without it, a settlement produced by the local
    # simulator mints exactly the same durable evidence as a settlement the
    # provider reported: `final_state=PAID`, `webhook_verified=true`,
    # `provider=razorpay`. That is the one distinction an auditor cannot be
    # asked to reconstruct from a console banner, so it lives on the row.
    #   test      -> rzp_test_* key against the production API base
    #   live      -> rzp_live_* key against the production API base (real money)
    #   simulated -> the API base is not Razorpay's (e.g. scripts/stub_razorpay.py)
    #   unknown   -> could not be classified; must never be reported as real
    provider_environment: Mapped[str] = mapped_column(String(16), default="unknown")
    provider_key_id_prefix: Mapped[str | None] = mapped_column(String(24), nullable=True)
    provider_api_base: Mapped[str | None] = mapped_column(String(200), nullable=True)

    attempts: Mapped[int] = mapped_column(Integer, default=0)
    # Durable reconciliation scheduling. attempts above is provider-submit usage;
    # reconciliation_attempts is deliberately separate.
    reconciliation_attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_reconcile_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_reconcile_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    dead_lettered_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    provider_idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    reconciled_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class AuditEvent(Base):
    """
    Phase 6 Task 4: append-only, hash-chained audit log. One row per
    security-relevant fact (intent decided, authorization minted/consumed,
    order submitted, webhook applied, reconciled, delegation consumed,
    credential issued, challenge verified). Rows are keyed by a trace id
    (payment transaction_id for money flows) and linked via
    prev_hash/event_hash so tampering with any row breaks verification.
    Rows are never updated or deleted - only appended.
    """
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[str] = mapped_column(String(64), default="default")
    transaction_id: Mapped[str] = mapped_column(String(100), index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    parent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    kind: Mapped[str] = mapped_column(String(40))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    hash_version: Mapped[int] = mapped_column(Integer, default=2)


class RequestProof(Base):
    """Consumed per-request proof JTIs. Durable replay protection for
    sender-constrained Paari-Proof-JWT requests across workers/restarts."""
    __tablename__ = "request_proofs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    jti: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.agent_id"))
    org_id: Mapped[str] = mapped_column(String(64), default="default")
    issued_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


class RateBucket(Base):
    """
    Phase 6 Task 7: shared rate-limit counters. Table-backed (not in-memory)
    so N uvicorn workers share one counter; one row per (scope, window).
    Rows for dead windows are pruned lazily inside check_rate.
    """
    __tablename__ = "rate_buckets"
    __table_args__ = (
        UniqueConstraint("scope", "window_start", name="uq_rate_buckets_scope_window"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[str] = mapped_column(String(64), default="default")
    scope: Mapped[str] = mapped_column(String(100), index=True)
    window_start: Mapped[datetime] = mapped_column(UTCDateTime)
    count: Mapped[int] = mapped_column(Integer, default=0)


# ---------------------------------------------------------------------------
# Paari institutional control plane (organization -> principal -> resource ->
# versioned policy -> disposition). Provider credentials are never stored here.
# ---------------------------------------------------------------------------



# Paari v4.0: atomic, tenant/currency/period-scoped treasury reservations.
class TreasuryBudgetPolicy(Base):
    __tablename__ = "treasury_budget_policies"
    __table_args__ = (
        UniqueConstraint("org_id", "currency", name="uq_treasury_policy_org_currency"),
        CheckConstraint("limit_minor_units > 0", name="ck_treasury_policy_limit_positive"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    policy_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    currency: Mapped[str] = mapped_column(String(10), nullable=False)
    limit_minor_units: Mapped[int] = mapped_column(Integer, nullable=False)
    period: Mapped[str] = mapped_column(String(16), nullable=False, default="DAILY")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


class TreasuryBudgetBucket(Base):
    __tablename__ = "treasury_budget_buckets"
    __table_args__ = (
        UniqueConstraint("org_id", "currency", "period_key", name="uq_treasury_bucket_org_currency_period"),
        CheckConstraint("limit_minor_units > 0", name="ck_treasury_bucket_limit_positive"),
        CheckConstraint("reserved_minor_units >= 0", name="ck_treasury_bucket_reserved_nonnegative"),
        CheckConstraint("spent_minor_units >= 0", name="ck_treasury_bucket_spent_nonnegative"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    bucket_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    policy_id: Mapped[str] = mapped_column(ForeignKey("treasury_budget_policies.policy_id"), nullable=False, index=True)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    currency: Mapped[str] = mapped_column(String(10), nullable=False)
    period_key: Mapped[str] = mapped_column(String(24), nullable=False)
    limit_minor_units: Mapped[int] = mapped_column(Integer, nullable=False)
    reserved_minor_units: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    spent_minor_units: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


class TreasuryReservation(Base):
    __tablename__ = "treasury_reservations"
    __table_args__ = (
        UniqueConstraint("authorization_id", name="uq_treasury_reservation_authorization"),
        UniqueConstraint("intent_id", name="uq_treasury_reservation_intent"),
        CheckConstraint("amount_minor_units > 0", name="ck_treasury_reservation_amount_positive"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    reservation_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    bucket_id: Mapped[str] = mapped_column(ForeignKey("treasury_budget_buckets.bucket_id"), nullable=False, index=True)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    intent_id: Mapped[str] = mapped_column(ForeignKey("payment_intents.intent_id"), nullable=False, index=True)
    authorization_id: Mapped[str] = mapped_column(ForeignKey("bounded_authorizations.authorization_id"), nullable=False, index=True)
    currency: Mapped[str] = mapped_column(String(10), nullable=False)
    period_key: Mapped[str] = mapped_column(String(24), nullable=False)
    amount_minor_units: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="RESERVED")
    provider_state: Mapped[str] = mapped_column(String(30), nullable=False, default="AUTHORIZED")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    finalized_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class PrincipalIdentity(Base):
    """Organization-scoped end-user/principal identity reference.

    `external_subject_id` is an issuer-scoped subject identifier, not proof of
    identity by itself. PENDING identities cannot authorize payments until a
    trusted identity/KYB/IdP verifier or authorized reviewer activates them.
    """
    __tablename__ = "principal_identities"
    __table_args__ = (
        UniqueConstraint("org_id", "identity_provider", "external_subject_id", name="uq_principal_external_subject"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    principal_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), index=True)
    external_subject_id: Mapped[str] = mapped_column(String(128), index=True)
    identity_provider: Mapped[str] = mapped_column(String(128))
    display_name: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), default="PENDING")
    assurance_level: Mapped[str] = mapped_column(String(20), default="low")
    attestation_reference: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # Authoritative KYC/KYB evidence is distinct from a local reviewer/parent
    # attestation. The provider case is refreshed before production payment
    # authorization and execution; no raw identity documents are stored here.
    identity_verification_status: Mapped[str] = mapped_column(String(24), default="UNVERIFIED", server_default="UNVERIFIED")
    verification_provider_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    verification_case_reference: Mapped[str | None] = mapped_column(String(256), nullable=True)
    verification_kind: Mapped[str | None] = mapped_column(String(40), nullable=True)
    verification_subject_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_evidence_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_retrieved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    verification_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    attested_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class GovernedResource(Base):
    """A source account, wallet, treasury account, provider mandate, data set or API.

    Only opaque provider references are allowed here: no account credentials,
    card data, private keys, UPI PINs, bank passwords or bearer tokens.
    """
    __tablename__ = "governed_resources"
    __table_args__ = (
        UniqueConstraint("org_id", "provider_id", "external_resource_ref", name="uq_resource_external_ref"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    resource_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), index=True)
    resource_type: Mapped[str] = mapped_column(String(40))
    provider_id: Mapped[str] = mapped_column(String(128))
    external_resource_ref: Mapped[str] = mapped_column(String(256))
    owner_principal_id: Mapped[str | None] = mapped_column(ForeignKey("principal_identities.principal_id"), nullable=True, index=True)
    currency: Mapped[str | None] = mapped_column(String(3), nullable=True)
    classification: Mapped[str] = mapped_column(String(20), default="confidential")
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")
    resource_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


class ResourceAccessGrant(Base):
    """Time-bounded, explicitly scoped access to a governed resource."""
    __tablename__ = "resource_access_grants"
    __table_args__ = (
        Index("ix_resource_grants_active_lookup", "org_id", "resource_id", "subject_type", "subject_id", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    grant_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), index=True)
    resource_id: Mapped[str] = mapped_column(ForeignKey("governed_resources.resource_id"), index=True)
    subject_type: Mapped[str] = mapped_column(String(16))
    subject_id: Mapped[str] = mapped_column(String(128), index=True)
    actions: Mapped[list] = mapped_column(JSON, default=list)
    consent_reference: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")
    valid_from: Mapped[datetime] = mapped_column(UTCDateTime)
    valid_until: Mapped[datetime] = mapped_column(UTCDateTime)
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class PolicyBundle(Base):
    """Versioned tenant-owned policy; only one ACTIVE version per policy name."""
    __tablename__ = "policy_bundles"
    __table_args__ = (
        UniqueConstraint("org_id", "policy_name", "version", name="uq_policy_bundle_version"),
        Index("uq_policy_bundle_one_active", "org_id", "policy_name", unique=True,
              postgresql_where=text("status = 'ACTIVE'"), sqlite_where=text("status = 'ACTIVE'")),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    policy_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), index=True)
    policy_name: Mapped[str] = mapped_column(String(128))
    version: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="DRAFT")
    rules: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    activated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class ControlPlaneDecision(Base):
    """Immutable per-intent disposition and the versions/evidence that drove it."""
    __tablename__ = "control_plane_decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    decision_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    intent_id: Mapped[str] = mapped_column(ForeignKey("payment_intents.intent_id"), unique=True, index=True)
    org_id: Mapped[str] = mapped_column(String(64), index=True)
    principal_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    policy_name: Mapped[str] = mapped_column(String(128))
    policy_version: Mapped[str] = mapped_column(String(64))
    disposition: Mapped[str] = mapped_column(String(20))
    reason_codes: Mapped[list] = mapped_column(JSON, default=list)
    reason_evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    reason_catalog_version: Mapped[str] = mapped_column(String(20), default="1.0", server_default="1.0")
    risk_score_bps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence_quality_bps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    transaction_digest: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


class GovernanceEnvelopeReceipt(Base):
    """Tenant-scoped replay receipt for validated SAFR envelope ingress.

    A receipt proves structural/signature ingress validation only. It does not
    represent a disposition or confer execution authority; the runtime policy
    and bounded-authorization path must still run independently.
    """
    __tablename__ = "governance_envelope_receipts"
    __table_args__ = (
        UniqueConstraint("org_id", "envelope_id", name="uq_governance_envelope_org_id"),
        Index("ix_governance_envelope_receipts_org_agent", "org_id", "agent_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    receipt_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    envelope_id: Mapped[str] = mapped_column(String(36), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    action_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    envelope_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    validation_status: Mapped[str] = mapped_column(String(32), nullable=False, default="VALIDATED_ONLY")
    # Populated only by /process after exact persisted-intent/context matching.
    # Production consume requires one unexpired, unconsumed bound receipt.
    bound_intent_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    bound_transaction_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    bound_decision_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    bound_authorization_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    bound_request_context_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    execution_consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, nullable=False)


class AgentPortabilityImport(Base):
    """Auditable destination-side staging record for a verified portability package.

    Staging never creates an active agent or transfers payment authority. The
    destination must independently register the agent under a local parent,
    issue fresh credentials, create local grants/mandates and re-authorize each
    transaction.
    """
    __tablename__ = "agent_portability_imports"
    __table_args__ = (
        UniqueConstraint("org_id", "package_digest", name="uq_portability_import_org_digest"),
        Index("ix_portability_imports_org_state", "org_id", "state"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    import_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    package_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    source_org_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    source_parent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    destination_parent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    destination_principal_id: Mapped[str] = mapped_column(String(64), nullable=False)
    destination_resource_id: Mapped[str] = mapped_column(String(64), nullable=False)
    consent_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="STAGED")
    verification_evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, nullable=False)


class OrganizationAdminKey(Base):
    """Hashed, revocable organization-scoped administrative credential.

    Raw key material is returned once at issuance and never persisted. The
    organization boundary is checked against this row, not an untrusted body.
    """
    __tablename__ = "organization_admin_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    key_prefix: Mapped[str] = mapped_column(String(20))
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


# Paari v3.4: receiving-side control plane. Payment settlement state remains
# owned by ProviderTransaction; a signed receiving acknowledgement is separate.
class ReceiverInstitution(Base):
    __tablename__ = "receiver_institutions"
    __table_args__ = (UniqueConstraint("org_id", "external_id", name="uq_receiver_org_external"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    receiver_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    rail: Mapped[str] = mapped_column(String(32), nullable=False)
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    public_key_algorithm: Mapped[str] = mapped_column(String(20), nullable=False, default="ed25519")
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING")
    identity_assurance: Mapped[str] = mapped_column(String(24), nullable=False, default="UNVERIFIED")
    verification_reference: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=_now)
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class ReceiverBeneficiary(Base):
    __tablename__ = "receiver_beneficiaries"
    __table_args__ = (UniqueConstraint("org_id", "receiver_id", "account_fingerprint", name="uq_beneficiary_account"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    beneficiary_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    receiver_id: Mapped[str] = mapped_column(ForeignKey("receiver_institutions.receiver_id"), nullable=False, index=True)
    alias: Mapped[str] = mapped_column(String(200), nullable=False)
    # Only a one-way, salted digest is persisted; do not persist raw bank details.
    account_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    currency: Mapped[str] = mapped_column(String(10), nullable=False)
    max_payment_minor_units: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=_now)


class ReceiverAttestation(Base):
    __tablename__ = "receiver_attestations"
    __table_args__ = (UniqueConstraint("receiver_id", "event_id", name="uq_receiver_event_replay"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    attestation_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    receiver_id: Mapped[str] = mapped_column(ForeignKey("receiver_institutions.receiver_id"), nullable=False, index=True)
    beneficiary_id: Mapped[str] = mapped_column(ForeignKey("receiver_beneficiaries.beneficiary_id"), nullable=False)
    intent_id: Mapped[str] = mapped_column(ForeignKey("payment_intents.intent_id"), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    result: Mapped[str] = mapped_column(String(30), nullable=False)
    provider_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    amount_minor_units: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(10), nullable=False)
    signed_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    signature_b64: Mapped[str] = mapped_column(String(8000), nullable=False)
    signature_algorithm: Mapped[str] = mapped_column(String(20), nullable=False, default="ed25519")
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=_now)


# v3.5: federated control-plane evidence, separate from agent/mandate authority.
class FederationSigner(Base):
    __tablename__ = "federation_signers"
    __table_args__ = (UniqueConstraint("org_id", "subject_type", "subject_id", name="uq_fed_signer_subject"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    signer_id: Mapped[str] = mapped_column(String(64), unique=True, default=_uuid, index=True)
    org_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    subject_type: Mapped[str] = mapped_column(String(24), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False)
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    # Post-quantum Phase 2b: algorithm tracking (default ed25519 for backward compat).
    public_key_algorithm: Mapped[str] = mapped_column(String(20), default="ed25519", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE", nullable=False)
    registered_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class FederationAgreement(Base):
    __tablename__ = "federation_agreements"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agreement_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    beneficiary_id: Mapped[str] = mapped_column(String(64), nullable=False)
    subject_type: Mapped[str] = mapped_column(String(24), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    # Post-quantum Phase 2b: PQC signatures are ~4,412 base64 chars for ML-DSA-65.
    signature_b64: Mapped[str] = mapped_column(String(8000), nullable=False)
    # PQC fingerprints are algorithm-prefixed (e.g. "ml-dsa-65:<sha256hex>").
    signer_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    # Algorithm used for the signature (ed25519 default for backward compat).
    signature_algorithm: Mapped[str] = mapped_column(String(20), default="ed25519", nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="ACTIVE", nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class PaymentContextEnvelope(Base):
    __tablename__ = "payment_context_envelopes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    context_id: Mapped[str] = mapped_column(String(64), unique=True, default=_uuid, index=True)
    intent_id: Mapped[str] = mapped_column(ForeignKey("payment_intents.intent_id"), unique=True, index=True, nullable=False)
    org_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    # Post-quantum Phase 2b: Paari-signed context envelopes under an ML-DSA
    # backend produce ~4,412 base64-char signatures; 256 chars would truncate.
    signature_b64: Mapped[str] = mapped_column(String(8000), nullable=False)
    # Algorithm used to sign this envelope (ed25519 default for backward compat).
    signature_algorithm: Mapped[str] = mapped_column(String(20), default="ed25519", nullable=False)
    issuer_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, nullable=False)

# V3.6 additive mapping: imported by migrations and legacy test metadata reset.
from app.v36 import models as v36_models  # noqa: E402,F401


class AgentClientCertificate(Base):
    """mTLS client certificate pinned to one registered Paari Agent Card."""
    __tablename__ = "agent_client_certificates"
    __table_args__ = (
        UniqueConstraint("fingerprint_sha256", name="uq_agent_client_cert_fingerprint"),
        Index("ix_agent_client_cert_agent_status", "agent_id", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    certificate_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.agent_id"), nullable=False, index=True)
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    # Snapshot of the Agent Card signing key that authorized this transport
    # certificate. A later Agent Card key rotation invalidates the binding
    # unless that key remains inside its explicitly configured grace period.
    agent_card_key_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, default="", server_default="")
    subject_cn: Mapped[str] = mapped_column(String(128), nullable=False)
    not_before: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    not_after: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE", server_default="ACTIVE")
    issued_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
