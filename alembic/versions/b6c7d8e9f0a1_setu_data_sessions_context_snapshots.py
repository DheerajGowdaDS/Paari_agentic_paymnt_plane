"""Persist tenant-bound Setu data sessions and normalized context snapshots.

Revision ID: b6c7d8e9f0a1
Revises: a5b6c7d8e9f0
"""
from alembic import op
import sqlalchemy as sa

from app.database import UTCDateTime


revision = "b6c7d8e9f0a1"
down_revision = "a5b6c7d8e9f0"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "setu_data_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("data_session_id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("setu_consent_id", sa.String(length=64), nullable=False),
        sa.Column("provider_session_id", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(["setu_consent_id"], ["setu_consents.setu_consent_id"]),
        sa.UniqueConstraint("data_session_id"),
        sa.UniqueConstraint("org_id", "provider_session_id", name="uq_setu_session_org_provider"),
    )
    op.create_index(
        "ix_setu_data_sessions_data_session_id",
        "setu_data_sessions",
        ["data_session_id"],
        unique=True,
    )
    op.create_index(
        "ix_setu_sessions_org_consent_status",
        "setu_data_sessions",
        ["org_id", "setu_consent_id", "status"],
    )
    op.create_index("ix_setu_data_sessions_org_id", "setu_data_sessions", ["org_id"])
    op.create_index("ix_setu_data_sessions_setu_consent_id", "setu_data_sessions", ["setu_consent_id"])

    op.create_table(
        "financial_context_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("setu_consent_id", sa.String(length=64), nullable=False),
        sa.Column("data_session_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("raw_payload_ciphertext", sa.Text(), nullable=True),
        sa.Column("raw_payload_digest", sa.String(length=64), nullable=True),
        sa.Column("normalized_context", sa.JSON(), nullable=False),
        sa.Column("normalized_context_version", sa.String(length=64), nullable=False),
        sa.Column("source_freshness_at", UTCDateTime(), nullable=True),
        sa.Column("completeness", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(["setu_consent_id"], ["setu_consents.setu_consent_id"]),
        sa.ForeignKeyConstraint(["data_session_id"], ["setu_data_sessions.data_session_id"]),
        sa.UniqueConstraint("snapshot_id"),
    )
    op.create_index(
        "ix_financial_context_snapshots_snapshot_id",
        "financial_context_snapshots",
        ["snapshot_id"],
        unique=True,
    )
    op.create_index(
        "ix_financial_context_snapshots_org_consent_status",
        "financial_context_snapshots",
        ["org_id", "setu_consent_id", "status"],
    )
    op.create_index(
        "ix_financial_context_snapshots_org_id",
        "financial_context_snapshots",
        ["org_id"],
    )
    op.create_index(
        "ix_financial_context_snapshots_setu_consent_id",
        "financial_context_snapshots",
        ["setu_consent_id"],
    )
    op.create_index(
        "ix_financial_context_snapshots_data_session_id",
        "financial_context_snapshots",
        ["data_session_id"],
    )


def downgrade():
    op.drop_table("financial_context_snapshots")
    op.drop_table("setu_data_sessions")
