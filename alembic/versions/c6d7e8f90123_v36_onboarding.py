"""v3.6 additive onboarding, policy acceptance and provider requirements.

Revision ID: c6d7e8f90123
Revises: b9c0d1e2f3a4b
"""
from alembic import op
import sqlalchemy as sa
from app.database import Base
from app.v36 import models as v36_models  # noqa: F401
revision = 'c6d7e8f90123'
down_revision = 'b9c0d1e2f3a4b'
branch_labels = None
depends_on = None

TABLES = ['v36_parent_accounts','v36_policy_acceptances','v36_manual_approvals',
          'v36_agent_registrations','v36_provider_applications','v36_provider_requirements']

def upgrade():
    for name in TABLES:
        Base.metadata.tables[name].create(bind=op.get_bind(), checkfirst=True)
    with op.batch_alter_table("payment_intents") as batch:
        batch.add_column(sa.Column("v36_provider_id", sa.String(64), nullable=True))
        batch.add_column(sa.Column("v36_provider_policy_version", sa.Integer(), nullable=True))

def downgrade():
    with op.batch_alter_table("payment_intents") as batch:
        batch.drop_column("v36_provider_policy_version")
        batch.drop_column("v36_provider_id")
    for name in reversed(TABLES):
        Base.metadata.tables[name].drop(bind=op.get_bind(), checkfirst=True)
