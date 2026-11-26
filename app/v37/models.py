"""Additive enterprise treasury security and portability records (v3.7)."""
from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import String, Integer, BigInteger, ForeignKey, Boolean, JSON, UniqueConstraint, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base, UTCDateTime


def now(): return datetime.now(timezone.utc)
def uid(): return str(uuid4())


class TreasuryPolicy(Base):
    __tablename__ = 'v37_treasury_policies'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    parent_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    currency: Mapped[str] = mapped_column(String(3))
    daily_limit_minor_units: Mapped[int] = mapped_column(BigInteger)
    state: Mapped[str] = mapped_column(String(16), default='ACTIVE')
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class AgentRiskRule(Base):
    __tablename__ = 'v37_agent_risk_rules'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey('agents.agent_id'), unique=True)
    parent_id: Mapped[str] = mapped_column(String(64), index=True)
    daily_limit_minor_units: Mapped[int] = mapped_column(BigInteger)
    suspended: Mapped[bool] = mapped_column(Boolean, default=False)
    hourly_request_limit: Mapped[int] = mapped_column(Integer, default=20)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class DataSet(Base):
    __tablename__ = 'v37_data_sets'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dataset_id: Mapped[str] = mapped_column(String(64), default=uid, unique=True)
    parent_id: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(40))
    fields: Mapped[list] = mapped_column(JSON)
    encrypted_content: Mapped[str] = mapped_column(Text)
    content_sha256: Mapped[str] = mapped_column(String(64))
    deleted_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class DataGrant(Base):
    __tablename__ = 'v37_data_grants'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    grant_id: Mapped[str] = mapped_column(String(64), unique=True, default=uid)
    parent_id: Mapped[str] = mapped_column(String(64), index=True)
    dataset_id: Mapped[str] = mapped_column(String(64), ForeignKey('v37_data_sets.dataset_id'))
    agent_id: Mapped[str] = mapped_column(String(64), ForeignKey('agents.agent_id'))
    allowed_fields: Mapped[list] = mapped_column(JSON)
    purpose: Mapped[str] = mapped_column(String(200))
    destination: Mapped[str] = mapped_column(String(200))
    # Captured at consent time; the agent cannot substitute a destination key at export.
    destination_public_key_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    destination_key_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class DataExportLog(Base):
    __tablename__ = 'v37_data_exports'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    export_id: Mapped[str] = mapped_column(String(64), default=uid, unique=True)
    grant_id: Mapped[str] = mapped_column(String(64))
    agent_id: Mapped[str] = mapped_column(String(64))
    destination: Mapped[str] = mapped_column(String(200))
    fields: Mapped[list] = mapped_column(JSON)
    payload_sha256: Mapped[str] = mapped_column(String(64))
    exported_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class AgentMigration(Base):
    __tablename__ = 'v37_agent_migrations'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    migration_id: Mapped[str] = mapped_column(String(64), default=uid, unique=True)
    package_digest: Mapped[str] = mapped_column(String(64), unique=True)
    source_agent_id: Mapped[str] = mapped_column(String(64))
    source_parent_id: Mapped[str] = mapped_column(String(64))
    source_key_fingerprint: Mapped[str] = mapped_column(String(64))
    destination_parent_id: Mapped[str] = mapped_column(String(64), index=True)
    destination_agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state: Mapped[str] = mapped_column(String(24), default='STAGED')
    verified_evidence: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    activated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)



class RailSimulation(Base):
    """Non-settlement route preview tied to an already-authorized payment intent."""
    __tablename__ = 'v37_rail_simulations'
    __table_args__ = (UniqueConstraint('intent_id', 'rail', name='uq_v37_rail_simulation_intent_rail'),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    simulation_id: Mapped[str] = mapped_column(String(64), default=uid, unique=True)
    parent_id: Mapped[str] = mapped_column(String(64), index=True)
    org_id: Mapped[str] = mapped_column(String(64), index=True)
    intent_id: Mapped[str] = mapped_column(ForeignKey('payment_intents.intent_id'), index=True)
    rail: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(40), default='ROUTE_PREVIEW_ONLY')
    request_digest: Mapped[str] = mapped_column(String(64))
    safe_context: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
