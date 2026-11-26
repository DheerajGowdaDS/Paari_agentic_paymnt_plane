"""Paari v3.7 enterprise treasury, data consent and identity migration.

Revision ID: d7e8f9012345
Revises: c6d7e8f90123
"""
from alembic import op
import sqlalchemy as sa
from app.database import Base
from app.v37 import models  # noqa: F401
revision='d7e8f9012345'
down_revision='c6d7e8f90123'
branch_labels=None
depends_on=None
TABLES=['v37_treasury_policies','v37_agent_risk_rules','v37_data_sets','v37_data_grants','v37_data_exports','v37_agent_migrations']

def upgrade():
    for name in TABLES: Base.metadata.tables[name].create(bind=op.get_bind(),checkfirst=True)
    existing={column['name'] for column in sa.inspect(op.get_bind()).get_columns('v36_parent_accounts')}
    if 'failed_login_attempts' not in existing or 'locked_until' not in existing:
        with op.batch_alter_table('v36_parent_accounts') as batch:
            if 'failed_login_attempts' not in existing:
                batch.add_column(sa.Column('failed_login_attempts',sa.Integer(),nullable=False,server_default='0'))
            if 'locked_until' not in existing:
                batch.add_column(sa.Column('locked_until',sa.DateTime(timezone=True),nullable=True))

def downgrade():
    with op.batch_alter_table('v36_parent_accounts') as batch:
        batch.drop_column('locked_until')
        batch.drop_column('failed_login_attempts')
    for name in reversed(TABLES): Base.metadata.tables[name].drop(bind=op.get_bind(),checkfirst=True)
