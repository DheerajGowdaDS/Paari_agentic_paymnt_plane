"""Additive v3.6 onboarding and provider data; all legacy rows remain intact."""
from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import String, Integer, ForeignKey, Boolean, JSON, UniqueConstraint, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base, UTCDateTime


def now(): return datetime.now(timezone.utc)
def uid(): return str(uuid4())

class ParentAccount(Base):
    __tablename__ = 'v36_parent_accounts'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    parent_pk: Mapped[int] = mapped_column(ForeignKey('parent_authorities.id'), unique=True)
    kind: Mapped[str] = mapped_column(String(20))
    registration_ref: Mapped[str] = mapped_column(String(64), unique=True, default=uid)
    identifier_last4: Mapped[str] = mapped_column(String(4))
    identifier_hmac: Mapped[str] = mapped_column(String(64))
    representative_name: Mapped[str] = mapped_column(String(200))
    representative_email: Mapped[str] = mapped_column(String(200))
    representative_phone: Mapped[str] = mapped_column(String(30))
    address: Mapped[str] = mapped_column(String(500), default='')
    password_hash: Mapped[str] = mapped_column(String(255))
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    encrypted_signing_key: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)

class PolicyAcceptance(Base):
    __tablename__ = 'v36_policy_acceptances'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject_type: Mapped[str] = mapped_column(String(20))
    subject_id: Mapped[str] = mapped_column(String(64), index=True)
    policy_code: Mapped[str] = mapped_column(String(60))
    version: Mapped[str] = mapped_column(String(20))
    document_sha256: Mapped[str] = mapped_column(String(64))
    accepted_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    __table_args__ = (UniqueConstraint('subject_type','subject_id','policy_code','version'),)

class ManualApproval(Base):
    __tablename__ = 'v36_manual_approvals'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject_type: Mapped[str] = mapped_column(String(20))
    subject_id: Mapped[str] = mapped_column(String(64), index=True)
    decision: Mapped[str] = mapped_column(String(20))
    checks: Mapped[dict] = mapped_column(JSON)
    reviewer_note: Mapped[str] = mapped_column(String(1000))
    reviewed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)

class AgentRegistration(Base):
    __tablename__ = 'v36_agent_registrations'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey('agents.agent_id'), unique=True)
    parent_id: Mapped[str] = mapped_column(String(64))
    agent_description: Mapped[str] = mapped_column(String(500), default='')
    software_operator: Mapped[str] = mapped_column(String(200), default='')
    approver_name: Mapped[str] = mapped_column(String(200))
    approver_email: Mapped[str] = mapped_column(String(200))
    approver_phone: Mapped[str] = mapped_column(String(30))
    alternate_email: Mapped[str | None] = mapped_column(String(200), nullable=True)
    registration_status: Mapped[str] = mapped_column(String(20), default='approved')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)

class ProviderApplication(Base):
    __tablename__ = 'v36_provider_applications'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider_id: Mapped[str] = mapped_column(String(64), unique=True, default=uid)
    legal_name: Mapped[str] = mapped_column(String(200))
    registration_number: Mapped[str] = mapped_column(String(80))
    contact_email: Mapped[str] = mapped_column(String(200))
    representative_name: Mapped[str] = mapped_column(String(200))
    payment_rail: Mapped[str] = mapped_column(String(50))
    currencies: Mapped[list] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default='pending_approval')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)

class ProviderRequirements(Base):
    __tablename__ = 'v36_provider_requirements'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider_id: Mapped[str] = mapped_column(String(64), ForeignKey('v36_provider_applications.provider_id'))
    version: Mapped[int] = mapped_column(Integer, default=1)
    required_context_fields: Mapped[list] = mapped_column(JSON)
    max_amount_minor_units: Mapped[int] = mapped_column(Integer)
    required_currency: Mapped[str] = mapped_column(String(10))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    __table_args__ = (UniqueConstraint('provider_id','version'),)


class KybSimulationCase(Base):
    """Synthetic KYB workflow evidence for local demonstrations only."""
    __tablename__ = "v36_kyb_simulation_cases"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=uid)
    parent_id: Mapped[str] = mapped_column(String(64), index=True)
    registration_ref: Mapped[str] = mapped_column(String(64), index=True)
    provider_id: Mapped[str] = mapped_column(String(80), default="paari-sandbox-kyb")
    scenario: Mapped[str] = mapped_column(String(30))
    outcome: Mapped[str] = mapped_column(String(30))
    reason_codes: Mapped[list] = mapped_column(JSON, default=list)
    evidence_digest: Mapped[str] = mapped_column(String(64))
    sandbox_only: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
