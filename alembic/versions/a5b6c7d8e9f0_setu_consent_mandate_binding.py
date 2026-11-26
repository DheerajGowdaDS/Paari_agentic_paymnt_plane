"""Persist tenant-bound Setu consent and payment-mandate binding.

Revision ID: a5b6c7d8e9f0
Revises: f4c5d6e7f8a9
"""
from alembic import op
import sqlalchemy as sa

from app.database import UTCDateTime

revision = "a5b6c7d8e9f0"
down_revision = "f4c5d6e7f8a9"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "setu_consents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("setu_consent_id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("subject_user_id", sa.String(length=128), nullable=False),
        sa.Column("provider_consent_id", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("purpose_digest", sa.String(length=64), nullable=False),
        sa.Column("consent_expires_at", UTCDateTime(), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.UniqueConstraint("setu_consent_id"),
        sa.UniqueConstraint("org_id", "provider_consent_id", name="uq_setu_consent_org_provider"),
    )
    op.create_index("ix_setu_consents_setu_consent_id", "setu_consents", ["setu_consent_id"], unique=True)
    op.create_index("ix_setu_consents_org_subject_status", "setu_consents", ["org_id", "subject_user_id", "status"])
    op.create_index("ix_setu_consents_org_id", "setu_consents", ["org_id"])
    op.create_index("ix_setu_consents_subject_user_id", "setu_consents", ["subject_user_id"])
    op.create_table(
        "setu_consent_mandate_bindings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("binding_id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("setu_consent_id", sa.String(length=64), nullable=False),
        sa.Column("mandate_id", sa.String(length=64), nullable=False),
        sa.Column("subject_user_id", sa.String(length=128), nullable=False),
        sa.Column("purpose_digest", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="ACTIVE"),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("revoked_at", UTCDateTime(), nullable=True),
        sa.ForeignKeyConstraint(["setu_consent_id"], ["setu_consents.setu_consent_id"]),
        sa.ForeignKeyConstraint(["mandate_id"], ["user_payment_mandates.mandate_id"]),
        sa.UniqueConstraint("binding_id"),
        sa.UniqueConstraint("org_id", "setu_consent_id", "mandate_id", name="uq_setu_binding_org_consent_mandate"),
    )
    op.create_index("ix_setu_consent_mandate_bindings_binding_id", "setu_consent_mandate_bindings", ["binding_id"], unique=True)
    op.create_index("ix_setu_binding_org_subject_status", "setu_consent_mandate_bindings", ["org_id", "subject_user_id", "status"])
    op.create_index("ix_setu_consent_mandate_bindings_org_id", "setu_consent_mandate_bindings", ["org_id"])
    op.create_index("ix_setu_consent_mandate_bindings_setu_consent_id", "setu_consent_mandate_bindings", ["setu_consent_id"])
    op.create_index("ix_setu_consent_mandate_bindings_mandate_id", "setu_consent_mandate_bindings", ["mandate_id"])
    op.create_index("ix_setu_consent_mandate_bindings_subject_user_id", "setu_consent_mandate_bindings", ["subject_user_id"])


def downgrade():
    op.drop_table("setu_consent_mandate_bindings")
    op.drop_table("setu_consents")
