from typing import cast

from sqlalchemy import JSON, Table, Text

from app import models


PLAINTEXT_PII_COLUMNS = {
    "account_number",
    "address",
    "email",
    "full_name",
    "pan",
    "phone_number",
    "vua",
}


def _foreign_key_targets(model):
    return {
        foreign_key.target_fullname
        for column in model.__table__.columns
        for foreign_key in column.foreign_keys
    }


def test_setu_sessions_and_context_snapshots_are_tenant_bound_and_pii_safe():
    """Fails if Setu context loses its tenant/consent provenance or stores raw PII."""
    session_table = cast(Table, models.SetuDataSession.__table__)
    session_columns = session_table.c
    snapshot_columns = models.FinancialContextSnapshot.__table__.c

    assert {
        "data_session_id",
        "org_id",
        "setu_consent_id",
        "provider_session_id",
        "status",
        "created_at",
        "updated_at",
    } <= set(session_columns.keys())
    assert "setu_consents.setu_consent_id" in _foreign_key_targets(models.SetuDataSession)
    assert any(
        constraint.name == "uq_setu_session_org_provider"
        for constraint in session_table.constraints
    )

    assert {
        "snapshot_id",
        "org_id",
        "setu_consent_id",
        "data_session_id",
        "status",
        "raw_payload_ciphertext",
        "raw_payload_digest",
        "normalized_context",
        "normalized_context_version",
        "source_freshness_at",
        "completeness",
        "created_at",
    } <= set(snapshot_columns.keys())
    assert {
        "setu_consents.setu_consent_id",
        "setu_data_sessions.data_session_id",
    } <= _foreign_key_targets(models.FinancialContextSnapshot)
    assert isinstance(snapshot_columns.normalized_context.type, JSON)
    assert isinstance(snapshot_columns.raw_payload_ciphertext.type, Text)

    persisted_columns = set(session_columns.keys()) | set(snapshot_columns.keys())
    assert not persisted_columns & PLAINTEXT_PII_COLUMNS


def test_setu_snapshot_persists_encrypted_source_and_normalized_context(paari_client):
    """Fails if the Alembic schema cannot persist the tenant-bound context record."""
    db = paari_client.Session()
    try:
        consent = models.SetuConsent(
            org_id="tenant-setu-persistence",
            subject_user_id="subject-opaque-1",
            provider_consent_id="provider-consent-1",
            purpose_digest="a" * 64,
        )
        db.add(consent)
        db.flush()

        data_session = models.SetuDataSession(
            org_id=consent.org_id,
            setu_consent_id=consent.setu_consent_id,
            provider_session_id="provider-session-1",
            status="COMPLETED",
        )
        db.add(data_session)
        db.flush()

        snapshot = models.FinancialContextSnapshot(
            org_id=consent.org_id,
            setu_consent_id=consent.setu_consent_id,
            data_session_id=data_session.data_session_id,
            status="AVAILABLE",
            raw_payload_ciphertext="v1:encrypted-fi-payload",
            raw_payload_digest="b" * 64,
            normalized_context={
                "source": "setu_account_aggregator",
                "accounts": [{"masked_reference": "XXXX1234", "currency": "INR"}],
            },
            normalized_context_version="1.0",
            completeness="COMPLETE",
        )
        db.add(snapshot)
        db.commit()

        stored = db.get(models.FinancialContextSnapshot, snapshot.id)
        assert stored is not None
        assert stored.org_id == "tenant-setu-persistence"
        assert stored.raw_payload_ciphertext == "v1:encrypted-fi-payload"
        assert stored.normalized_context == {
            "source": "setu_account_aggregator",
            "accounts": [{"masked_reference": "XXXX1234", "currency": "INR"}],
        }
        assert stored.completeness == "COMPLETE"
    finally:
        db.close()
