"""Paari v3.5 signed institutional agreements and payment context.

Revision ID: f8a9b0c1d2e3
Revises: e7f8a9b0c1d2
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
revision: str = "f8a9b0c1d2e3"
down_revision: Union[str, None] = "e7f8a9b0c1d2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade():
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "federation_signers" not in tables:
        op.create_table("federation_signers",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("signer_id",sa.String(64),unique=True,nullable=False),
            sa.Column("org_id",sa.String(64),nullable=False),
            sa.Column("subject_type",sa.String(24),nullable=False),
            sa.Column("subject_id",sa.String(128),nullable=False),
            sa.Column("public_key_pem",sa.Text(),nullable=False),
            sa.Column("status",sa.String(20),nullable=False),
            sa.Column("registered_at",sa.DateTime(timezone=True),nullable=False),
            sa.Column("revoked_at",sa.DateTime(timezone=True),nullable=True),
            sa.UniqueConstraint("org_id","subject_type","subject_id",name="uq_fed_signer_subject"))
        op.create_index("ix_federation_signers_org_id","federation_signers",["org_id"])
        op.create_index("ix_federation_signers_signer_id","federation_signers",["signer_id"],unique=True)
    if "federation_agreements" not in tables:
        op.create_table("federation_agreements",
            sa.Column("id",sa.Integer(),primary_key=True),
            sa.Column("agreement_id",sa.String(64),unique=True,nullable=False),
            sa.Column("org_id",sa.String(64),nullable=False),
            sa.Column("agent_id",sa.String(64),nullable=False),
            sa.Column("beneficiary_id",sa.String(64),nullable=False),
            sa.Column("subject_type",sa.String(24),nullable=False),
            sa.Column("subject_id",sa.String(128),nullable=False),
            sa.Column("payload",sa.JSON(),nullable=False),
            sa.Column("payload_digest",sa.String(64),nullable=False),
            sa.Column("signature_b64",sa.String(256),nullable=False),
            sa.Column("signer_fingerprint",sa.String(64),nullable=False),
            sa.Column("status",sa.String(24),nullable=False),
            sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),
            sa.Column("revoked_at",sa.DateTime(timezone=True),nullable=True))
        op.create_index("ix_federation_agreements_agreement_id","federation_agreements",["agreement_id"],unique=True)
        op.create_index("ix_federation_agreements_org_id","federation_agreements",["org_id"])
        op.create_index("ix_federation_agreements_agent_id","federation_agreements",["agent_id"])
    if "payment_context_envelopes" not in tables:
        op.create_table("payment_context_envelopes",
            sa.Column("id",sa.Integer(),primary_key=True),
            sa.Column("context_id",sa.String(64),unique=True,nullable=False),
            sa.Column("intent_id",sa.String(64),sa.ForeignKey("payment_intents.intent_id"),unique=True,nullable=False),
            sa.Column("org_id",sa.String(64),nullable=False),
            sa.Column("payload",sa.JSON(),nullable=False),
            sa.Column("payload_digest",sa.String(64),nullable=False),
            sa.Column("signature_b64",sa.String(256),nullable=False),
            sa.Column("issuer_key_id",sa.String(128),nullable=False),
            sa.Column("created_at",sa.DateTime(timezone=True),nullable=False))
        op.create_index("ix_payment_context_envelopes_context_id","payment_context_envelopes",["context_id"],unique=True)
        op.create_index("ix_payment_context_envelopes_intent_id","payment_context_envelopes",["intent_id"],unique=True)
        op.create_index("ix_payment_context_envelopes_org_id","payment_context_envelopes",["org_id"])

def downgrade():
    for table in ("payment_context_envelopes", "federation_agreements", "federation_signers"):
        if table in set(sa.inspect(op.get_bind()).get_table_names()):
            op.drop_table(table)
