"""Remove duplicate PostgreSQL UNIQUE constraints where unique indexes remain.

Revision ID: e8f901234567
Revises: d7e8f9012345

The v3.4/v3.5 migrations created some identifier columns as both inline UNIQUE
constraints and separately named unique indexes. Current SQLAlchemy metadata
models these as unique indexes (``unique=True, index=True``). SQLite reflection
hid the discrepancy, while PostgreSQL's ``alembic check`` reported seven
removed constraints. This migration removes only a duplicate constraint when
an independent, non-partial unique index on the same single column remains.
Any inbound foreign keys that currently depend on a constraint are dropped and
recreated around the DDL change. Uniqueness continues to be enforced by the
surviving unique index.

The downgrade is intentionally a no-op: recreating redundant constraints would
reinstate the metadata drift without restoring any lost uniqueness guarantee.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "e8f901234567"
down_revision: Union[str, None] = "d7e8f9012345"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TARGETS: dict[str, set[str]] = {
    "federation_agreements": {"agreement_id"},
    "federation_signers": {"signer_id"},
    "payment_context_envelopes": {"context_id", "intent_id"},
    "receiver_attestations": {"attestation_id"},
    "receiver_beneficiaries": {"beneficiary_id"},
    "receiver_institutions": {"receiver_id"},
}


def _independent_unique_index_columns(inspector, table: str) -> set[tuple[str, ...]]:
    """Return column tuples protected by a standalone unique index.

    PostgreSQL can also expose the implicit index backing a UNIQUE constraint.
    SQLAlchemy tags such entries with ``duplicates_constraint``; they are not
    considered independent here, because dropping that constraint would remove
    that very index.
    """
    result: set[tuple[str, ...]] = set()
    for index in inspector.get_indexes(table):
        if not index.get("unique") or index.get("duplicates_constraint"):
            continue
        columns = tuple(index.get("column_names") or ())
        if not columns or any(column is None for column in columns):
            continue
        dialect_options = index.get("dialect_options") or {}
        if dialect_options.get("postgresql_where"):
            continue
        result.add(columns)
    return result


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # SQLite metadata already treats these as unique indexes and its
        # reflection did not show the extra constraints. No DDL is required.
        return

    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    drop_constraints: list[tuple[str, str, str]] = []

    for table, columns in _TARGETS.items():
        if table not in tables:
            continue
        independent_indexes = _independent_unique_index_columns(inspector, table)
        for constraint in inspector.get_unique_constraints(table):
            column_names = tuple(constraint.get("column_names") or ())
            name = constraint.get("name")
            if (name and len(column_names) == 1 and column_names[0] in columns
                    and column_names in independent_indexes):
                drop_constraints.append((table, name, column_names[0]))

    if not drop_constraints:
        return

    # A PostgreSQL FK may be attached to the UNIQUE constraint being removed.
    # Preserve all inbound FK definitions and restore them after the surviving
    # standalone unique index is available to back the referenced key.
    target_columns = {(table, column) for table, _name, column in drop_constraints}
    inbound: list[dict] = []
    for source_table in sorted(tables):
        for fk in inspector.get_foreign_keys(source_table):
            target_table = fk.get("referred_table")
            referred_columns = tuple(fk.get("referred_columns") or ())
            constrained_columns = tuple(fk.get("constrained_columns") or ())
            if (not fk.get("name") or not target_table or len(referred_columns) != 1
                    or len(constrained_columns) != 1):
                continue
            if (target_table, referred_columns[0]) in target_columns:
                inbound.append({"source_table": source_table, **fk})

    for fk in inbound:
        op.drop_constraint(fk["name"], fk["source_table"], type_="foreignkey")

    for table, constraint_name, _column in drop_constraints:
        op.drop_constraint(constraint_name, table, type_="unique")

    for fk in inbound:
        options = fk.get("options") or {}
        kwargs = {}
        for option in ("onupdate", "ondelete", "deferrable", "initially", "match"):
            if options.get(option) is not None:
                kwargs[option] = options[option]
        op.create_foreign_key(
            fk["name"], fk["source_table"], fk["referred_table"],
            fk.get("constrained_columns") or [], fk.get("referred_columns") or [],
            **kwargs,
        )


def downgrade() -> None:
    pass
