"""Paari v3.4: receiver control plane registry, beneficiary and attestations.

Revision ID: e7f8a9b0c1d2
Revises: e6f7a8b9c0d1
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
revision: str = "e7f8a9b0c1d2"
down_revision: Union[str,None] = "e6f7a8b9c0d1"
branch_labels: Union[str,Sequence[str],None] = None
depends_on: Union[str,Sequence[str],None] = None

def upgrade():
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    if "receiver_institutions" not in existing:
        op.create_table("receiver_institutions",
          sa.Column("id",sa.Integer(),primary_key=True),
          sa.Column("receiver_id",sa.String(64),nullable=False,unique=True),
          sa.Column("org_id",sa.String(64),nullable=False),
          sa.Column("external_id",sa.String(128),nullable=False),
          sa.Column("name",sa.String(200),nullable=False),
          sa.Column("rail",sa.String(32),nullable=False),
          sa.Column("public_key_pem",sa.Text(),nullable=False),
          sa.Column("status",sa.String(24),nullable=False),
          sa.Column("identity_assurance",sa.String(24),nullable=False),
          sa.Column("verification_reference",sa.String(200),nullable=True),
          sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),
          sa.Column("verified_at",sa.DateTime(timezone=True),nullable=True),
          sa.UniqueConstraint("org_id","external_id",name="uq_receiver_org_external"))
        op.create_index("ix_receiver_institutions_org_id","receiver_institutions",["org_id"])
        op.create_index("ix_receiver_institutions_receiver_id","receiver_institutions",["receiver_id"],unique=True)
    if "receiver_beneficiaries" not in existing:
        op.create_table("receiver_beneficiaries",
          sa.Column("id",sa.Integer(),primary_key=True),
          sa.Column("beneficiary_id",sa.String(64),nullable=False,unique=True),
          sa.Column("org_id",sa.String(64),nullable=False),
          sa.Column("receiver_id",sa.String(64),sa.ForeignKey("receiver_institutions.receiver_id"),nullable=False),
          sa.Column("alias",sa.String(200),nullable=False),
          sa.Column("account_fingerprint",sa.String(64),nullable=False),
          sa.Column("currency",sa.String(10),nullable=False),
          sa.Column("max_payment_minor_units",sa.Integer(),nullable=False),
          sa.Column("status",sa.String(24),nullable=False),
          sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),
          sa.UniqueConstraint("org_id","receiver_id","account_fingerprint",name="uq_beneficiary_account"))
        op.create_index("ix_receiver_beneficiaries_org_id","receiver_beneficiaries",["org_id"])
        op.create_index("ix_receiver_beneficiaries_receiver_id","receiver_beneficiaries",["receiver_id"])
        op.create_index("ix_receiver_beneficiaries_beneficiary_id","receiver_beneficiaries",["beneficiary_id"],unique=True)
    if "receiver_attestations" not in existing:
        op.create_table("receiver_attestations",
          sa.Column("id",sa.Integer(),primary_key=True),
          sa.Column("attestation_id",sa.String(64),nullable=False,unique=True),
          sa.Column("org_id",sa.String(64),nullable=False),
          sa.Column("receiver_id",sa.String(64),sa.ForeignKey("receiver_institutions.receiver_id"),nullable=False),
          sa.Column("beneficiary_id",sa.String(64),sa.ForeignKey("receiver_beneficiaries.beneficiary_id"),nullable=False),
          sa.Column("intent_id",sa.String(64),sa.ForeignKey("payment_intents.intent_id"),nullable=False),
          sa.Column("event_id",sa.String(64),nullable=False),
          sa.Column("result",sa.String(30),nullable=False),
          sa.Column("provider_reference",sa.String(128),nullable=False),
          sa.Column("amount_minor_units",sa.Integer(),nullable=False),
          sa.Column("currency",sa.String(10),nullable=False),
          sa.Column("signed_at",sa.DateTime(timezone=True),nullable=False),
          sa.Column("signature_b64",sa.String(256),nullable=False),
          sa.Column("payload_digest",sa.String(64),nullable=False),
          sa.Column("received_at",sa.DateTime(timezone=True),nullable=False),
          sa.UniqueConstraint("receiver_id","event_id",name="uq_receiver_event_replay"))
        for name in ("org_id","receiver_id","intent_id"):
          op.create_index(f"ix_receiver_attestations_{name}","receiver_attestations",[name])
        op.create_index("ix_receiver_attestations_attestation_id","receiver_attestations",["attestation_id"],unique=True)
    cols = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("payment_intents")}
    if "beneficiary_id" not in cols:
        with op.batch_alter_table("payment_intents") as batch:
            batch.add_column(sa.Column("beneficiary_id",sa.String(64),nullable=True))
            batch.create_index("ix_payment_intents_beneficiary_id",["beneficiary_id"])

def downgrade():
    with op.batch_alter_table("payment_intents") as batch:
      batch.drop_index("ix_payment_intents_beneficiary_id")
      batch.drop_column("beneficiary_id")
    op.drop_table("receiver_attestations")
    op.drop_table("receiver_beneficiaries")
    op.drop_table("receiver_institutions")
