"""Normalize duplicate inline UNIQUE constraints and matching unique indexes.

Revision ID: b3c4d5e6f7a8
Revises: da7e4a2b91c0

The control-plane revision created unique=True columns as both inline UNIQUE
constraints and named unique indexes, while the SQLAlchemy models describe the
unique indexes only. PostgreSQL's Alembic autogenerate therefore reported drift
that SQLite reflection did not show. This migration removes only duplicate
single-column constraints when an equivalent unique index already exists,
rebuilding inbound foreign keys with their names/actions intact. Uniqueness is
still enforced by the surviving index. SQLite intentionally needs no DDL here.
"""
from __future__ import annotations

from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "b3c4d5e6f7a8"
down_revision: Union[str, None] = "da7e4a2b91c0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TARGETS = {
    "control_plane_decisions": {"decision_id", "intent_id"},
    "governed_resources": {"resource_id"},
    "organization_admin_keys": {"key_hash", "key_id"},
    "policy_bundles": {"policy_id"},
    "principal_identities": {"principal_id"},
    "resource_access_grants": {"grant_id"},
}


def _inspector():
    return sa.inspect(op.get_bind())


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    inspector = _inspector()
    tables = inspector.get_table_names()
    drop_constraints: list[tuple[str, str, str]] = []
    for table, columns in _TARGETS.items():
        if table not in tables:
            continue
        unique_indexes = {
            tuple(index.get("column_names") or [])
            for index in inspector.get_indexes(table)
            if index.get("unique") is True
        }
        for constraint in inspector.get_unique_constraints(table):
            constrained = tuple(constraint.get("column_names") or [])
            name = constraint.get("name")
            if name and len(constrained) == 1 and constrained[0] in columns and constrained in unique_indexes:
                drop_constraints.append((table, name, constrained[0]))

    if not drop_constraints:
        return

    # Lift foreign keys pointing at a redundant constraint before dropping it.
    # PostgreSQL permits the FK to reference the surviving non-partial unique
    # index. We preserve FK names, source/target columns and referential actions.
    targets = {(table, column) for table, _, column in drop_constraints}
    inbound: list[dict] = []
    for source in tables:
        for fk in inspector.get_foreign_keys(source):
            target_table = fk.get("referred_table")
            referred = tuple(fk.get("referred_columns") or [])
            constrained = tuple(fk.get("constrained_columns") or [])
            if not fk.get("name") or not target_table or len(referred) != 1 or len(constrained) != 1:
                continue
            if (target_table, referred[0]) in targets:
                inbound.append({"source": source, **fk})

    for fk in inbound:
        op.drop_constraint(fk["name"], fk["source"], type_="foreignkey")

    for table, name, _column in drop_constraints:
        op.drop_constraint(name, table, type_="unique")

    for fk in inbound:
        options = fk.get("options") or {}
        kwargs = {}
        for option in ("onupdate", "ondelete", "deferrable", "initially", "match"):
            if options.get(option) is not None:
                kwargs[option] = options[option]
        op.create_foreign_key(
            fk["name"], fk["source"], fk["referred_table"],
            fk.get("constrained_columns") or [], fk.get("referred_columns") or [],
            **kwargs,
        )


def downgrade() -> None:
    # Intentionally no-op: removing a duplicate constraint did not remove the
    # uniqueness guarantee; the named unique index remains in force. Recreating
    # redundant constraints would reintroduce schema drift against current models.
    pass
