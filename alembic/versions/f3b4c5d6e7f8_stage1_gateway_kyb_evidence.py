"""Stage 1: agent mTLS certificate binding and sandbox KYB simulation evidence.

Revision ID: f3b4c5d6e7f8
Revises: f2a3b4c5d6e7
"""
from alembic import op
import sqlalchemy as sa
from app.database import Base
import app.models  # noqa: F401
from app.v36 import models as v36_models  # noqa: F401

revision = "f3b4c5d6e7f8"
down_revision = "f2a3b4c5d6e7"
branch_labels = None
depends_on = None


def upgrade():
    Base.metadata.tables["agent_client_certificates"].create(bind=op.get_bind(), checkfirst=True)
    Base.metadata.tables["v36_kyb_simulation_cases"].create(bind=op.get_bind(), checkfirst=True)
    with op.batch_alter_table("control_plane_decisions") as batch:
        batch.add_column(sa.Column("reason_evidence", sa.JSON(), nullable=False, server_default=sa.text("'{}'")))
        batch.add_column(sa.Column("reason_catalog_version", sa.String(length=20), nullable=False, server_default="1.0"))
    with op.batch_alter_table("payment_intents") as batch:
        batch.add_column(sa.Column("reason_codes", sa.JSON(), nullable=False, server_default=sa.text("'[]'")))
        batch.add_column(sa.Column("reason_evidence", sa.JSON(), nullable=False, server_default=sa.text("'{}'")))
        batch.add_column(sa.Column("reason_catalog_version", sa.String(length=24), nullable=False, server_default="1.0"))


def downgrade():
    with op.batch_alter_table("payment_intents") as batch:
        batch.drop_column("reason_catalog_version")
        batch.drop_column("reason_evidence")
        batch.drop_column("reason_codes")
    with op.batch_alter_table("control_plane_decisions") as batch:
        batch.drop_column("reason_catalog_version")
        batch.drop_column("reason_evidence")
    Base.metadata.tables["v36_kyb_simulation_cases"].drop(bind=op.get_bind(), checkfirst=True)
    Base.metadata.tables["agent_client_certificates"].drop(bind=op.get_bind(), checkfirst=True)
