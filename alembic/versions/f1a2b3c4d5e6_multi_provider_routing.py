"""Persist provider selection and provider-neutral execution identifiers.

Revision ID: f1a2b3c4d5e6
Revises: e8f901234567
"""
from alembic import op
import sqlalchemy as sa


revision = "f1a2b3c4d5e6"
down_revision = "e8f901234567"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("provider_accounts", recreate="auto") as batch_op:
        batch_op.add_column(sa.Column(
            "provider_name", sa.String(length=32), nullable=False, server_default="razorpay",
        ))

    with op.batch_alter_table("provider_transactions", recreate="auto") as batch_op:
        batch_op.add_column(sa.Column(
            "provider_name", sa.String(length=32), nullable=False, server_default="razorpay",
        ))
        batch_op.add_column(sa.Column("provider_order_id", sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column("provider_payment_id", sa.String(length=100), nullable=True))
    op.create_index(
        "uq_provider_transactions_provider_order_id",
        "provider_transactions",
        ["provider_name", "provider_order_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_provider_transactions_provider_order_id",
        table_name="provider_transactions",
    )
    with op.batch_alter_table("provider_transactions", recreate="auto") as batch_op:
        batch_op.drop_column("provider_payment_id")
        batch_op.drop_column("provider_order_id")
        batch_op.drop_column("provider_name")
    with op.batch_alter_table("provider_accounts", recreate="auto") as batch_op:
        batch_op.drop_column("provider_name")