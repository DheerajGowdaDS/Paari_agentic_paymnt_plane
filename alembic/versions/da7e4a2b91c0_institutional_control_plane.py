"""Add institutional control-plane identities, resources, grants and decisions.

Revision ID: da7e4a2b91c0
Revises: c3d4e5f6a7b8
Create Date: 2026-10-16
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
import app.database

revision: str = "da7e4a2b91c0"
down_revision: Union[str, None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _inspector():
    return sa.inspect(op.get_bind())


def _has_table(name: str) -> bool:
    return name in _inspector().get_table_names()


def _has_column(table: str, column: str) -> bool:
    return _has_table(table) and column in {item["name"] for item in _inspector().get_columns(table)}


def _has_index(table: str, index: str) -> bool:
    return _has_table(table) and index in {item["name"] for item in _inspector().get_indexes(table)}


def _create_index_if_missing(name: str, table: str, columns: list[str], **kwargs) -> None:
    if not _has_index(table, name):
        op.create_index(name, table, columns, **kwargs)


def upgrade() -> None:
    # This revision is safe to re-enter if an operator restores a revision marker
    # while the schema already contains the new structures. Normal Alembic usage
    # still runs it exactly once; checks also make recovery from partial SQLite
    # DDL failures practical.
    if not _has_column("organizations", "status"):
        op.add_column("organizations", sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"))

    if not _has_table("organization_admin_keys"):
        op.create_table(
            "organization_admin_keys",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("key_id", sa.String(64), nullable=False, unique=True),
            sa.Column("org_id", sa.String(64), nullable=False),
            sa.Column("key_hash", sa.String(64), nullable=False, unique=True),
            sa.Column("key_prefix", sa.String(20), nullable=False),
            sa.Column("scopes", sa.JSON(), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"),
            sa.Column("expires_at", app.database.UTCDateTime(timezone=True), nullable=False),
            sa.Column("created_by", sa.String(128), nullable=False),
            sa.Column("created_at", app.database.UTCDateTime(timezone=True), nullable=False),
            sa.Column("last_used_at", app.database.UTCDateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", app.database.UTCDateTime(timezone=True), nullable=True),
        )
    _create_index_if_missing("ix_organization_admin_keys_key_id", "organization_admin_keys", ["key_id"], unique=True)
    _create_index_if_missing("ix_organization_admin_keys_org_id", "organization_admin_keys", ["org_id"])
    _create_index_if_missing("ix_organization_admin_keys_key_hash", "organization_admin_keys", ["key_hash"], unique=True)

    if not _has_table("principal_identities"):
        op.create_table(
            "principal_identities",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("principal_id", sa.String(64), nullable=False, unique=True),
            sa.Column("org_id", sa.String(64), nullable=False),
            sa.Column("external_subject_id", sa.String(128), nullable=False),
            sa.Column("identity_provider", sa.String(128), nullable=False),
            sa.Column("display_name", sa.String(200), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="PENDING"),
            sa.Column("assurance_level", sa.String(20), nullable=False, server_default="low"),
            sa.Column("attestation_reference", sa.String(256), nullable=True),
            sa.Column("created_at", app.database.UTCDateTime(timezone=True), nullable=False),
            sa.Column("attested_at", app.database.UTCDateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("org_id", "identity_provider", "external_subject_id", name="uq_principal_external_subject"),
        )
    _create_index_if_missing("ix_principal_identities_principal_id", "principal_identities", ["principal_id"], unique=True)
    _create_index_if_missing("ix_principal_identities_org_id", "principal_identities", ["org_id"])
    _create_index_if_missing("ix_principal_identities_external_subject_id", "principal_identities", ["external_subject_id"])

    if not _has_table("governed_resources"):
        op.create_table(
            "governed_resources",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("resource_id", sa.String(64), nullable=False, unique=True),
            sa.Column("org_id", sa.String(64), nullable=False),
            sa.Column("resource_type", sa.String(40), nullable=False),
            sa.Column("provider_id", sa.String(128), nullable=False),
            sa.Column("external_resource_ref", sa.String(256), nullable=False),
            sa.Column("owner_principal_id", sa.String(64), sa.ForeignKey("principal_identities.principal_id"), nullable=True),
            sa.Column("currency", sa.String(3), nullable=True),
            sa.Column("classification", sa.String(20), nullable=False, server_default="confidential"),
            sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"),
            sa.Column("resource_metadata", sa.JSON(), nullable=False),
            sa.Column("created_at", app.database.UTCDateTime(timezone=True), nullable=False),
            sa.Column("updated_at", app.database.UTCDateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("org_id", "provider_id", "external_resource_ref", name="uq_resource_external_ref"),
        )
    _create_index_if_missing("ix_governed_resources_resource_id", "governed_resources", ["resource_id"], unique=True)
    _create_index_if_missing("ix_governed_resources_org_id", "governed_resources", ["org_id"])
    _create_index_if_missing("ix_governed_resources_owner_principal_id", "governed_resources", ["owner_principal_id"])

    if not _has_column("payment_instrument_bindings", "source_resource_id"):
        with op.batch_alter_table("payment_instrument_bindings") as batch:
            batch.add_column(sa.Column("source_resource_id", sa.String(64), nullable=True))
            batch.create_foreign_key("fk_payment_instrument_source_resource", "governed_resources", ["source_resource_id"], ["resource_id"])
    else:
        fks = _inspector().get_foreign_keys("payment_instrument_bindings")
        if not any(fk.get("constrained_columns") == ["source_resource_id"] for fk in fks):
            with op.batch_alter_table("payment_instrument_bindings") as batch:
                batch.create_foreign_key("fk_payment_instrument_source_resource", "governed_resources", ["source_resource_id"], ["resource_id"])
    _create_index_if_missing("ix_payment_instrument_bindings_source_resource_id", "payment_instrument_bindings", ["source_resource_id"])

    if not _has_table("resource_access_grants"):
        op.create_table(
            "resource_access_grants",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("grant_id", sa.String(64), nullable=False, unique=True),
            sa.Column("org_id", sa.String(64), nullable=False),
            sa.Column("resource_id", sa.String(64), sa.ForeignKey("governed_resources.resource_id"), nullable=False),
            sa.Column("subject_type", sa.String(16), nullable=False),
            sa.Column("subject_id", sa.String(128), nullable=False),
            sa.Column("actions", sa.JSON(), nullable=False),
            sa.Column("consent_reference", sa.String(128), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"),
            sa.Column("valid_from", app.database.UTCDateTime(timezone=True), nullable=False),
            sa.Column("valid_until", app.database.UTCDateTime(timezone=True), nullable=False),
            sa.Column("created_by", sa.String(128), nullable=False),
            sa.Column("created_at", app.database.UTCDateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", app.database.UTCDateTime(timezone=True), nullable=True),
        )
    _create_index_if_missing("ix_resource_access_grants_grant_id", "resource_access_grants", ["grant_id"], unique=True)
    _create_index_if_missing("ix_resource_access_grants_org_id", "resource_access_grants", ["org_id"])
    _create_index_if_missing("ix_resource_access_grants_resource_id", "resource_access_grants", ["resource_id"])
    _create_index_if_missing("ix_resource_access_grants_subject_id", "resource_access_grants", ["subject_id"])
    _create_index_if_missing("ix_resource_grants_active_lookup", "resource_access_grants", ["org_id", "resource_id", "subject_type", "subject_id", "status"])

    if not _has_table("policy_bundles"):
        op.create_table(
            "policy_bundles",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("policy_id", sa.String(64), nullable=False, unique=True),
            sa.Column("org_id", sa.String(64), nullable=False),
            sa.Column("policy_name", sa.String(128), nullable=False),
            sa.Column("version", sa.String(64), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="DRAFT"),
            sa.Column("rules", sa.JSON(), nullable=False),
            sa.Column("created_by", sa.String(128), nullable=False),
            sa.Column("created_at", app.database.UTCDateTime(timezone=True), nullable=False),
            sa.Column("activated_at", app.database.UTCDateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("org_id", "policy_name", "version", name="uq_policy_bundle_version"),
        )
    _create_index_if_missing("ix_policy_bundles_policy_id", "policy_bundles", ["policy_id"], unique=True)
    _create_index_if_missing("ix_policy_bundles_org_id", "policy_bundles", ["org_id"])
    _create_index_if_missing(
        "uq_policy_bundle_one_active", "policy_bundles", ["org_id", "policy_name"], unique=True,
        sqlite_where=sa.text("status = 'ACTIVE'"), postgresql_where=sa.text("status = 'ACTIVE'"),
    )

    if not _has_table("control_plane_decisions"):
        op.create_table(
            "control_plane_decisions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("decision_id", sa.String(64), nullable=False, unique=True),
            sa.Column("intent_id", sa.String(64), sa.ForeignKey("payment_intents.intent_id"), nullable=False, unique=True),
            sa.Column("org_id", sa.String(64), nullable=False),
            sa.Column("principal_id", sa.String(64), nullable=True),
            sa.Column("resource_id", sa.String(64), nullable=True),
            sa.Column("policy_name", sa.String(128), nullable=False),
            sa.Column("policy_version", sa.String(64), nullable=False),
            sa.Column("disposition", sa.String(20), nullable=False),
            sa.Column("reason_codes", sa.JSON(), nullable=False),
            sa.Column("risk_score_bps", sa.Integer(), nullable=True),
            sa.Column("evidence_quality_bps", sa.Integer(), nullable=True),
            sa.Column("transaction_digest", sa.String(64), nullable=False),
            sa.Column("created_at", app.database.UTCDateTime(timezone=True), nullable=False),
        )
    _create_index_if_missing("ix_control_plane_decisions_decision_id", "control_plane_decisions", ["decision_id"], unique=True)
    _create_index_if_missing("ix_control_plane_decisions_intent_id", "control_plane_decisions", ["intent_id"], unique=True)
    _create_index_if_missing("ix_control_plane_decisions_org_id", "control_plane_decisions", ["org_id"])
    _create_index_if_missing("ix_control_plane_decisions_principal_id", "control_plane_decisions", ["principal_id"])
    _create_index_if_missing("ix_control_plane_decisions_resource_id", "control_plane_decisions", ["resource_id"])


def downgrade() -> None:
    for table in ("control_plane_decisions", "policy_bundles", "resource_access_grants"):
        if _has_table(table):
            op.drop_table(table)

    if _has_table("payment_instrument_bindings") and _has_column("payment_instrument_bindings", "source_resource_id"):
        if _has_index("payment_instrument_bindings", "ix_payment_instrument_bindings_source_resource_id"):
            op.drop_index("ix_payment_instrument_bindings_source_resource_id", table_name="payment_instrument_bindings")
        fks = _inspector().get_foreign_keys("payment_instrument_bindings")
        fk = next((item for item in fks if item.get("constrained_columns") == ["source_resource_id"]), None)
        with op.batch_alter_table("payment_instrument_bindings") as batch:
            if fk and fk.get("name"):
                batch.drop_constraint(fk["name"], type_="foreignkey")
            batch.drop_column("source_resource_id")

    for table in ("governed_resources", "principal_identities", "organization_admin_keys"):
        if _has_table(table):
            op.drop_table(table)
    if _has_column("organizations", "status"):
        op.drop_column("organizations", "status")
