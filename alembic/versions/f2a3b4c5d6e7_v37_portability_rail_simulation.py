"""Pinned recipient keys and auditable payment-rail route previews.

Revision ID: f2a3b4c5d6e7
Revises: f1a2b3c4d5e6
"""
from alembic import op
import sqlalchemy as sa
from app.database import Base
from app.v37 import models  # noqa: F401

revision = 'f2a3b4c5d6e7'
down_revision = 'f1a2b3c4d5e6'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    existing = {c['name'] for c in sa.inspect(bind).get_columns('v37_data_grants')}
    with op.batch_alter_table('v37_data_grants') as batch:
        if 'destination_public_key_pem' not in existing:
            batch.add_column(sa.Column('destination_public_key_pem', sa.Text(), nullable=True))
        if 'destination_key_fingerprint' not in existing:
            batch.add_column(sa.Column('destination_key_fingerprint', sa.String(length=64), nullable=True))
    Base.metadata.tables['v37_rail_simulations'].create(bind=bind, checkfirst=True)


def downgrade():
    Base.metadata.tables['v37_rail_simulations'].drop(bind=op.get_bind(), checkfirst=True)
    with op.batch_alter_table('v37_data_grants') as batch:
        batch.drop_column('destination_key_fingerprint')
        batch.drop_column('destination_public_key_pem')
