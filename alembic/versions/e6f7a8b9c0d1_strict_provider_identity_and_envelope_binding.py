"""Persist trusted identity evidence and transaction-bound SAFR consume receipts.

Revision ID: e6f7a8b9c0d1
Revises: d5e6f7a8b9c0
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "e6f7a8b9c0d1"
down_revision: Union[str, None] = "d5e6f7a8b9c0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _add_columns(table: str, columns: list[sa.Column]) -> None:
    bind = op.get_bind()
    existing_tables = set(sa.inspect(bind).get_table_names())
    if table not in existing_tables:
        return
    existing = {c["name"] for c in sa.inspect(bind).get_columns(table)}
    for column in columns:
        if column.name not in existing:
            op.add_column(table, column)


def upgrade() -> None:
    _add_columns("principal_identities", [
        sa.Column("identity_verification_status", sa.String(length=24), nullable=False, server_default="UNVERIFIED"),
        sa.Column("verification_provider_id", sa.String(length=128), nullable=True),
        sa.Column("verification_case_reference", sa.String(length=256), nullable=True),
        sa.Column("verification_kind", sa.String(length=40), nullable=True),
        sa.Column("verification_subject_digest", sa.String(length=64), nullable=True),
        sa.Column("verification_evidence_digest", sa.String(length=64), nullable=True),
        sa.Column("verification_retrieved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verification_expires_at", sa.DateTime(timezone=True), nullable=True),
    ])
    _add_columns("governance_envelope_receipts", [
        sa.Column("bound_intent_id", sa.String(length=64), nullable=True),
        sa.Column("bound_transaction_id", sa.String(length=100), nullable=True),
        sa.Column("bound_decision_id", sa.String(length=64), nullable=True),
        sa.Column("bound_authorization_id", sa.String(length=64), nullable=True),
        sa.Column("bound_request_context_digest", sa.String(length=64), nullable=True),
        sa.Column("execution_consumed_at", sa.DateTime(timezone=True), nullable=True),
    ])
    bind = op.get_bind()
    if "governance_envelope_receipts" in set(sa.inspect(bind).get_table_names()):
        indexes = {i["name"] for i in sa.inspect(bind).get_indexes("governance_envelope_receipts")}
        if "ix_governance_envelope_receipts_bound_intent_id" not in indexes:
            op.create_index("ix_governance_envelope_receipts_bound_intent_id", "governance_envelope_receipts", ["bound_intent_id"], unique=False)
        if "ix_governance_envelope_receipts_bound_authorization_id" not in indexes:
            op.create_index("ix_governance_envelope_receipts_bound_authorization_id", "governance_envelope_receipts", ["bound_authorization_id"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "governance_envelope_receipts" in tables:
        indexes = {i["name"] for i in sa.inspect(bind).get_indexes("governance_envelope_receipts")}
        for index in ("ix_governance_envelope_receipts_bound_intent_id", "ix_governance_envelope_receipts_bound_authorization_id"):
            if index in indexes:
                op.drop_index(index, table_name="governance_envelope_receipts")
        columns = {c["name"] for c in sa.inspect(bind).get_columns("governance_envelope_receipts")}
        for name in ("execution_consumed_at", "bound_request_context_digest", "bound_authorization_id", "bound_decision_id", "bound_transaction_id", "bound_intent_id"):
            if name in columns:
                op.drop_column("governance_envelope_receipts", name)
    if "principal_identities" in tables:
        columns = {c["name"] for c in sa.inspect(bind).get_columns("principal_identities")}
        for name in ("verification_expires_at", "verification_retrieved_at", "verification_evidence_digest", "verification_subject_digest", "verification_kind", "verification_case_reference", "verification_provider_id", "identity_verification_status"):
            if name in columns:
                op.drop_column("principal_identities", name)
