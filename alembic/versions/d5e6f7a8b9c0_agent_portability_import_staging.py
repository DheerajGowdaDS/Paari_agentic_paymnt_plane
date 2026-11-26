"""Persist destination-side verified portability staging records.

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
"""
from __future__ import annotations

from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "d5e6f7a8b9c0"
down_revision: Union[str, None] = "c4d5e6f7a8b9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "agent_portability_imports" in sa.inspect(bind).get_table_names():
        return
    op.create_table(
        "agent_portability_imports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("import_id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("package_digest", sa.String(length=64), nullable=False),
        sa.Column("source_org_id", sa.String(length=64), nullable=True),
        sa.Column("source_agent_id", sa.String(length=64), nullable=False),
        sa.Column("source_parent_id", sa.String(length=64), nullable=False),
        sa.Column("destination_parent_id", sa.String(length=64), nullable=False),
        sa.Column("destination_principal_id", sa.String(length=64), nullable=False),
        sa.Column("destination_resource_id", sa.String(length=64), nullable=False),
        sa.Column("consent_reference", sa.String(length=128), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False, server_default="STAGED"),
        sa.Column("verification_evidence", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "package_digest", name="uq_portability_import_org_digest"),
    )
    op.create_index("ix_agent_portability_imports_import_id", "agent_portability_imports", ["import_id"], unique=True)
    op.create_index("ix_agent_portability_imports_org_id", "agent_portability_imports", ["org_id"], unique=False)
    op.create_index("ix_portability_imports_org_state", "agent_portability_imports", ["org_id", "state"], unique=False)


def downgrade() -> None:
    if "agent_portability_imports" in sa.inspect(op.get_bind()).get_table_names():
        op.drop_table("agent_portability_imports")
