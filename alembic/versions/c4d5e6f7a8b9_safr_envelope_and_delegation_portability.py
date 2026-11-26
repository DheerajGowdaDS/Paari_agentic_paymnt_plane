"""SAFR envelope receipts and preserved parent-signed delegation artifacts.

Revision ID: c4d5e6f7a8b9
Revises: b3c4d5e6f7a8
"""
from __future__ import annotations

from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "c4d5e6f7a8b9"
down_revision: Union[str, None] = "b3c4d5e6f7a8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "delegation_records" in inspector.get_table_names() and "delegation_signature_b64" not in {
        c["name"] for c in inspector.get_columns("delegation_records")
    }:
        op.add_column("delegation_records", sa.Column("delegation_signature_b64", sa.String(length=256), nullable=True))

    if "governance_envelope_receipts" not in sa.inspect(bind).get_table_names():
        op.create_table(
            "governance_envelope_receipts",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("receipt_id", sa.String(length=64), nullable=False),
            sa.Column("org_id", sa.String(length=64), nullable=False),
            sa.Column("envelope_id", sa.String(length=36), nullable=False),
            sa.Column("agent_id", sa.String(length=64), nullable=False),
            sa.Column("action_type", sa.String(length=64), nullable=False),
            sa.Column("action_digest", sa.String(length=64), nullable=False),
            sa.Column("envelope_digest", sa.String(length=64), nullable=False),
            sa.Column("validation_status", sa.String(length=32), nullable=False, server_default="VALIDATED_ONLY"),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("org_id", "envelope_id", name="uq_governance_envelope_org_id"),
        )
        op.create_index("ix_governance_envelope_receipts_receipt_id", "governance_envelope_receipts", ["receipt_id"], unique=True)
        op.create_index("ix_governance_envelope_receipts_org_id", "governance_envelope_receipts", ["org_id"], unique=False)
        op.create_index("ix_governance_envelope_receipts_org_agent", "governance_envelope_receipts", ["org_id", "agent_id"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    if "governance_envelope_receipts" in sa.inspect(bind).get_table_names():
        op.drop_table("governance_envelope_receipts")
    if "delegation_records" in sa.inspect(bind).get_table_names() and "delegation_signature_b64" in {
        c["name"] for c in sa.inspect(bind).get_columns("delegation_records")
    }:
        op.drop_column("delegation_records", "delegation_signature_b64")
