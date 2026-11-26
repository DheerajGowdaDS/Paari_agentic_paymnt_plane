"""Bind every mTLS certificate to the Agent Card signing-key version.

Revision ID: f4c5d6e7f8a9
Revises: f3b4c5d6e7f8
"""
from alembic import op
import sqlalchemy as sa

revision = "f4c5d6e7f8a9"
down_revision = "f3b4c5d6e7f8"
branch_labels = None
depends_on = None


def upgrade():
    # The previous Stage 1 revision creates its certificate table from current
    # SQLAlchemy metadata on a fresh install. In that case this column may
    # already exist. Existing deployed v3.8.0 tables will not have it. Handle
    # both states without trying to add the same column twice.
    columns = {column["name"]: column for column in sa.inspect(op.get_bind()).get_columns("agent_client_certificates")}
    if "agent_card_key_fingerprint" not in columns:
        with op.batch_alter_table("agent_client_certificates") as batch:
            batch.add_column(sa.Column("agent_card_key_fingerprint", sa.String(length=128), nullable=True))
    # Existing certificate bindings have no Agent Card proof snapshot. Keep
    # their sentinel blank so the gateway fails closed until re-registration.
    op.execute("UPDATE agent_client_certificates SET agent_card_key_fingerprint = '' WHERE agent_card_key_fingerprint IS NULL")
    # Enforce a non-null column for both newly-added and metadata-created cases.
    column = {item["name"]: item for item in sa.inspect(op.get_bind()).get_columns("agent_client_certificates")}[
        "agent_card_key_fingerprint"]
    if column.get("nullable", True) or column.get("default") is None:
        with op.batch_alter_table("agent_client_certificates") as batch:
            batch.alter_column(
                "agent_card_key_fingerprint",
                existing_type=sa.String(length=128),
                nullable=False,
                server_default="",
            )


def downgrade():
    with op.batch_alter_table("agent_client_certificates") as batch:
        batch.drop_column("agent_card_key_fingerprint")
