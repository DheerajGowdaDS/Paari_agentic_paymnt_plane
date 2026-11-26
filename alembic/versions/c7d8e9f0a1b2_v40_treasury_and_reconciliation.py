"""Paari v4.0 treasury reservations and provider reconciliation scheduling."""
from alembic import op
import sqlalchemy as sa
from app.database import UTCDateTime

revision = "c7d8e9f0a1b2"
down_revision = "b6c7d8e9f0a1"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "treasury_budget_policies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("policy_id", sa.String(64), nullable=False),
        sa.Column("org_id", sa.String(64), nullable=False),
        sa.Column("currency", sa.String(10), nullable=False),
        sa.Column("limit_minor_units", sa.Integer(), nullable=False),
        sa.Column("period", sa.String(16), nullable=False, server_default="DAILY"),
        sa.Column("status", sa.String(16), nullable=False, server_default="ACTIVE"),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.UniqueConstraint("org_id", "currency", name="uq_treasury_policy_org_currency"),
        sa.CheckConstraint("limit_minor_units > 0", name="ck_treasury_policy_limit_positive"),
    )
    op.create_index("ix_treasury_budget_policies_policy_id", "treasury_budget_policies", ["policy_id"], unique=True)
    op.create_index("ix_treasury_budget_policies_org_id", "treasury_budget_policies", ["org_id"])

    op.create_table(
        "treasury_budget_buckets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("bucket_id", sa.String(64), nullable=False),
        sa.Column("policy_id", sa.String(64), sa.ForeignKey("treasury_budget_policies.policy_id"), nullable=False),
        sa.Column("org_id", sa.String(64), nullable=False),
        sa.Column("currency", sa.String(10), nullable=False),
        sa.Column("period_key", sa.String(24), nullable=False),
        sa.Column("limit_minor_units", sa.Integer(), nullable=False),
        sa.Column("reserved_minor_units", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("spent_minor_units", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.UniqueConstraint("org_id", "currency", "period_key", name="uq_treasury_bucket_org_currency_period"),
        sa.CheckConstraint("limit_minor_units > 0", name="ck_treasury_bucket_limit_positive"),
        sa.CheckConstraint("reserved_minor_units >= 0", name="ck_treasury_bucket_reserved_nonnegative"),
        sa.CheckConstraint("spent_minor_units >= 0", name="ck_treasury_bucket_spent_nonnegative"),
    )
    op.create_index("ix_treasury_budget_buckets_bucket_id", "treasury_budget_buckets", ["bucket_id"], unique=True)
    op.create_index("ix_treasury_budget_buckets_policy_id", "treasury_budget_buckets", ["policy_id"])
    op.create_index("ix_treasury_budget_buckets_org_id", "treasury_budget_buckets", ["org_id"])

    op.create_table(
        "treasury_reservations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("reservation_id", sa.String(64), nullable=False),
        sa.Column("bucket_id", sa.String(64), sa.ForeignKey("treasury_budget_buckets.bucket_id"), nullable=False),
        sa.Column("org_id", sa.String(64), nullable=False),
        sa.Column("intent_id", sa.String(64), sa.ForeignKey("payment_intents.intent_id"), nullable=False),
        sa.Column("authorization_id", sa.String(64), sa.ForeignKey("bounded_authorizations.authorization_id"), nullable=False),
        sa.Column("currency", sa.String(10), nullable=False),
        sa.Column("period_key", sa.String(24), nullable=False),
        sa.Column("amount_minor_units", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="RESERVED"),
        sa.Column("provider_state", sa.String(30), nullable=False, server_default="AUTHORIZED"),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("finalized_at", UTCDateTime(), nullable=True),
        sa.UniqueConstraint("authorization_id", name="uq_treasury_reservation_authorization"),
        sa.UniqueConstraint("intent_id", name="uq_treasury_reservation_intent"),
        sa.CheckConstraint("amount_minor_units > 0", name="ck_treasury_reservation_amount_positive"),
    )
    op.create_index("ix_treasury_reservations_reservation_id", "treasury_reservations", ["reservation_id"], unique=True)
    op.create_index("ix_treasury_reservations_bucket_id", "treasury_reservations", ["bucket_id"])
    op.create_index("ix_treasury_reservations_org_id", "treasury_reservations", ["org_id"])
    op.create_index("ix_treasury_reservations_intent_id", "treasury_reservations", ["intent_id"])
    op.create_index("ix_treasury_reservations_authorization_id", "treasury_reservations", ["authorization_id"])

    with op.batch_alter_table("provider_transactions") as batch:
        batch.add_column(sa.Column("reconciliation_attempts", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("next_reconcile_at", UTCDateTime(), nullable=True))
        batch.add_column(sa.Column("last_reconcile_at", UTCDateTime(), nullable=True))
        batch.add_column(sa.Column("dead_lettered_at", UTCDateTime(), nullable=True))
        batch.add_column(sa.Column("provider_idempotency_key", sa.String(128), nullable=True))


def downgrade():
    with op.batch_alter_table("provider_transactions") as batch:
        batch.drop_column("provider_idempotency_key")
        batch.drop_column("dead_lettered_at")
        batch.drop_column("last_reconcile_at")
        batch.drop_column("next_reconcile_at")
        batch.drop_column("reconciliation_attempts")
    op.drop_table("treasury_reservations")
    op.drop_table("treasury_budget_buckets")
    op.drop_table("treasury_budget_policies")
