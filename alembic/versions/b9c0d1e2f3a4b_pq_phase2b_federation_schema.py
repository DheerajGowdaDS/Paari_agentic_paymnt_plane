"""Post-quantum migration Phase 2b: PQC-sized federation schema.

The Phase 2 migration (b9c0d1e2f3a4) resized the agent/mandate/receiver
key & signature columns, but left federation_agreements.signature_b64 and
payment_context_envelopes.signature_b64 at VARCHAR(256) -- far too small for
an ML-DSA-65 signature (~4,412 base64 chars) -- and federation_agreements.
signer_fingerprint at VARCHAR(64), which clips the algorithm-prefixed PQC
fingerprint ("ml-dsa-65:<sha256hex>" = 79 chars).

This additive migration:
  * federation_signers       : add public_key_algorithm   (default ed25519)
  * federation_agreements    : resize signature_b64 -> 8000,
                               signer_fingerprint -> 128,
                               add signature_algorithm   (default ed25519)
  * payment_context_envelopes: resize signature_b64 -> 8000,
                               add signature_algorithm   (default ed25519)

Idempotent: every step is guarded against re-run (column-exists and type
drift checks). Downgrade is best-effort; PQC data must not be truncated, so
resize-backs are omitted.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = "b9c0d1e2f3a4b"
down_revision: Union[str, None] = "b9c0d1e2f3a4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns(table: str) -> dict:
    return {c["name"]: c for c in sa.inspect(op.get_bind()).get_columns(table)}


def _add_column_if_missing(table: str, column: sa.Column) -> None:
    if column.name not in _columns(table):
        op.add_column(table, column)


def _alter_if_needed(table: str, column: str, *, new_type) -> None:
    cols = _columns(table)
    if column not in cols:
        return
    existing_type = cols[column].get("type")
    if existing_type is None or str(existing_type) == str(new_type):
        return
    with op.batch_alter_table(table) as batch:
        batch.alter_column(column, existing_type=existing_type, type_=new_type)


def upgrade() -> None:
    # federation_signers: algorithm tracking for enrolled signers.
    _add_column_if_missing("federation_signers",
        sa.Column("public_key_algorithm", sa.String(20), nullable=True, server_default="ed25519"))
    op.execute("UPDATE federation_signers SET public_key_algorithm='ed25519' "
               "WHERE public_key_algorithm IS NULL")
    _alter_if_needed("federation_signers", "public_key_algorithm",
                     new_type=sa.String(20))
    # Make non-nullable only if already present and backfilled.
    cols = _columns("federation_signers")
    if cols.get("public_key_algorithm", {}).get("nullable") is False:
        pass
    elif "public_key_algorithm" in cols:
        with op.batch_alter_table("federation_signers") as batch:
            batch.alter_column("public_key_algorithm", existing_type=sa.String(20), nullable=False)

    # federation_agreements: PQC-sized signature + algorithm-prefixed fingerprint.
    _add_column_if_missing("federation_agreements",
        sa.Column("signature_algorithm", sa.String(20), nullable=True, server_default="ed25519"))
    op.execute("UPDATE federation_agreements SET signature_algorithm='ed25519' "
               "WHERE signature_algorithm IS NULL")
    _alter_if_needed("federation_agreements", "signature_b64", new_type=sa.String(8000))
    _alter_if_needed("federation_agreements", "signer_fingerprint", new_type=sa.String(128))
    _alter_if_needed("federation_agreements", "signature_algorithm", new_type=sa.String(20))
    cols = _columns("federation_agreements")
    if "signature_algorithm" in cols:
        with op.batch_alter_table("federation_agreements") as batch:
            batch.alter_column("signature_algorithm", existing_type=sa.String(20), nullable=False)

    # payment_context_envelopes: PQC-sized signature + algorithm tracking.
    _add_column_if_missing("payment_context_envelopes",
        sa.Column("signature_algorithm", sa.String(20), nullable=True, server_default="ed25519"))
    op.execute("UPDATE payment_context_envelopes SET signature_algorithm='ed25519' "
               "WHERE signature_algorithm IS NULL")
    _alter_if_needed("payment_context_envelopes", "signature_b64", new_type=sa.String(8000))
    _alter_if_needed("payment_context_envelopes", "signature_algorithm", new_type=sa.String(20))
    cols = _columns("payment_context_envelopes")
    if "signature_algorithm" in cols:
        with op.batch_alter_table("payment_context_envelopes") as batch:
            batch.alter_column("signature_algorithm", existing_type=sa.String(20), nullable=False)


def downgrade() -> None:
    # Drop the new algorithm columns. Do NOT resize signature columns back to
    # 256 / 64: that would truncate any PQC signatures or fingerprints stored.
    for table, col in [
        ("federation_agreements", "signature_algorithm"),
        ("payment_context_envelopes", "signature_algorithm"),
        ("federation_signers", "public_key_algorithm"),
    ]:
        if col in _columns(table):
            with op.batch_alter_table(table) as batch:
                batch.drop_column(col)
