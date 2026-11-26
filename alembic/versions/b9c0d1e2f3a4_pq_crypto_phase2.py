"""Post-quantum migration Phase 2: algorithm tracking columns and column resizing.

Revision ID: b9c0d1e2f3a4
Revises: f8a9b0c1d2e3
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = "b9c0d1e2f3a4"
down_revision: Union[str, None] = "f8a9b0c1d2e3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns(table: str) -> dict:
    return {c["name"]: c for c in sa.inspect(op.get_bind()).get_columns(table)}


def _add_column_if_missing(table: str, column: sa.Column) -> None:
    if column.name not in _columns(table):
        op.add_column(table, column)


def _alter_if_needed(table: str, column: str, *, new_type, nullable=None) -> None:
    cols = _columns(table)
    if column not in cols:
        return
    # Only alter when the live type differs (avoid pointless table rebuilds).
    existing_type = cols[column].get("type")
    existing_nullable = cols[column].get("nullable")
    needs_type = existing_type is not None and str(existing_type) != str(new_type)
    needs_null = nullable is not None and existing_nullable != nullable
    if not (needs_type or needs_null):
        return
    with op.batch_alter_table(table) as batch:
        kwargs = {}
        if needs_type:
            kwargs["type_"] = new_type
        if needs_null:
            kwargs["nullable"] = nullable
        batch.alter_column(column, existing_type=existing_type, **kwargs)


def upgrade() -> None:
    # Algorithm tracking columns (default ed25519 for backward compatibility).
    _add_column_if_missing("parent_authorities", sa.Column("public_key_algorithm", sa.String(20), nullable=True, server_default="ed25519"))
    _add_column_if_missing("agents", sa.Column("public_key_algorithm", sa.String(20), nullable=True, server_default="ed25519"))
    _add_column_if_missing("agents", sa.Column("old_public_key_algorithm", sa.String(20), nullable=True))
    _add_column_if_missing("user_payment_mandates", sa.Column("signing_algorithm", sa.String(20), nullable=True))
    _add_column_if_missing("delegation_records", sa.Column("delegation_algorithm", sa.String(20), nullable=True))
    _add_column_if_missing("receiver_institutions", sa.Column("public_key_algorithm", sa.String(20), nullable=True, server_default="ed25519"))
    _add_column_if_missing("receiver_attestations", sa.Column("signature_algorithm", sa.String(20), nullable=True, server_default="ed25519"))

    # Backfill NULLs for safety.
    op.execute("UPDATE parent_authorities SET public_key_algorithm='ed25519' WHERE public_key_algorithm IS NULL")
    op.execute("UPDATE agents SET public_key_algorithm='ed25519' WHERE public_key_algorithm IS NULL")
    op.execute("UPDATE receiver_institutions SET public_key_algorithm='ed25519' WHERE public_key_algorithm IS NULL")
    op.execute("UPDATE receiver_attestations SET signature_algorithm='ed25519' WHERE signature_algorithm IS NULL")

    # Make algorithm columns non-nullable after backfill.
    _alter_if_needed("parent_authorities", "public_key_algorithm", new_type=sa.String(20), nullable=False)
    _alter_if_needed("agents", "public_key_algorithm", new_type=sa.String(20), nullable=False)
    _alter_if_needed("receiver_institutions", "public_key_algorithm", new_type=sa.String(20), nullable=False)
    _alter_if_needed("receiver_attestations", "signature_algorithm", new_type=sa.String(20), nullable=False)

    # Increase column sizes to accommodate PQC keys/signatures.
    _alter_if_needed("parent_authorities", "public_key_pem", new_type=sa.String(8000))
    _alter_if_needed("agents", "public_key_pem", new_type=sa.String(8000))
    _alter_if_needed("agents", "old_public_key_pem", new_type=sa.String(8000))
    _alter_if_needed("user_payment_mandates", "signature_b64", new_type=sa.String(8000))
    _alter_if_needed("user_payment_mandates", "user_public_key_pem", new_type=sa.String(8000))
    _alter_if_needed("delegation_records", "delegation_signature_b64", new_type=sa.String(8000))
    _alter_if_needed("receiver_attestations", "signature_b64", new_type=sa.String(8000))


def downgrade() -> None:
    _alter_if_needed("receiver_attestations", "signature_b64", new_type=sa.String(256))
    _alter_if_needed("receiver_attestations", "signature_algorithm", new_type=sa.String(20), nullable=True)
    _alter_if_needed("delegation_records", "delegation_signature_b64", new_type=sa.String(256))
    _alter_if_needed("user_payment_mandates", "user_public_key_pem", new_type=sa.String(2000))
    _alter_if_needed("user_payment_mandates", "signature_b64", new_type=sa.String(500))
    _alter_if_needed("agents", "old_public_key_pem", new_type=sa.String(2000))
    _alter_if_needed("agents", "public_key_pem", new_type=sa.String(2000))
    _alter_if_needed("parent_authorities", "public_key_pem", new_type=sa.String(2000))

    for table, col in [
        ("receiver_attestations", "signature_algorithm"),
        ("receiver_institutions", "public_key_algorithm"),
        ("delegation_records", "delegation_algorithm"),
        ("user_payment_mandates", "signing_algorithm"),
        ("agents", "old_public_key_algorithm"),
        ("agents", "public_key_algorithm"),
        ("parent_authorities", "public_key_algorithm"),
    ]:
        if col in _columns(table):
            op.drop_column(table, col)
