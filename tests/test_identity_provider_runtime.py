from datetime import datetime, timedelta, timezone

from app.identity_providers.contracts import VerificationKind, VerificationRequest, VerificationStatus, subject_reference_digest
from app.identity_providers.runtime import identity_provider_status, require_identity_provider, validate_verification_result


def test_no_identity_adapter_is_not_reported_as_trusted(monkeypatch):
    monkeypatch.delenv("PAARI_IDENTITY_PROVIDER_ADAPTER", raising=False)
    monkeypatch.delenv("PAARI_TRUSTED_IDENTITY_PROVIDER_IDS", raising=False)
    status = identity_provider_status()
    assert status["configured"] is False
    assert status["trusted_evidence"] is False
    assert status["status"] == "not_configured"


def test_provider_must_be_explicitly_pinned(monkeypatch):
    monkeypatch.setenv("PAARI_IDENTITY_PROVIDER_ADAPTER", "tests.fake_trusted_identity_adapter:create_provider")
    monkeypatch.setenv("PAARI_TRUSTED_IDENTITY_PROVIDER_IDS", "different-provider")
    status = identity_provider_status()
    assert status["configured"] is True
    assert status["trusted_evidence"] is False
    try:
        require_identity_provider()
    except RuntimeError as exc:
        assert "not included" in str(exc)
    else:  # pragma: no cover - assertion describes the trust boundary
        raise AssertionError("un-pinned provider must not be loaded as trusted")


def test_pinned_provider_returns_subject_and_purpose_bound_verified_evidence(monkeypatch):
    monkeypatch.setenv("PAARI_IDENTITY_PROVIDER_ADAPTER", "tests.fake_trusted_identity_adapter:create_provider")
    monkeypatch.setenv("PAARI_TRUSTED_IDENTITY_PROVIDER_IDS", "test-reviewed-idp")
    status = identity_provider_status()
    assert status["trusted_evidence"] is True
    provider = require_identity_provider()
    request = VerificationRequest(
        verification_id="verification-unit-1", organization_id="org-1",
        subject_reference="subject-1", kind=VerificationKind.INDIVIDUAL, jurisdiction="AE",
    )
    result = provider.verify(request)
    accepted, reason = validate_verification_result(
        result, provider_id=provider.provider_id, organization_id=request.organization_id,
        subject_reference=request.subject_reference, kind=request.kind,
        jurisdiction=request.jurisdiction, now=datetime.now(timezone.utc),
    )
    assert accepted is True
    assert reason == "IDENTITY_EVIDENCE_VERIFIED"
    assert result.status is VerificationStatus.VERIFIED


def test_wrong_subject_evidence_is_rejected(monkeypatch):
    monkeypatch.setenv("PAARI_IDENTITY_PROVIDER_ADAPTER", "tests.fake_trusted_identity_adapter:create_provider")
    monkeypatch.setenv("PAARI_TRUSTED_IDENTITY_PROVIDER_IDS", "test-reviewed-idp")
    provider = require_identity_provider()
    request = VerificationRequest(
        verification_id="verification-unit-2", organization_id="org-1",
        subject_reference="subject-1", kind=VerificationKind.INDIVIDUAL, jurisdiction="AE",
    )
    result = provider.verify(request)
    accepted, reason = validate_verification_result(
        result, provider_id=provider.provider_id, organization_id=request.organization_id,
        subject_reference="other-subject", kind=request.kind, jurisdiction="AE",
        now=datetime.now(timezone.utc),
    )
    assert accepted is False
    assert reason == "IDENTITY_SUBJECT_BINDING_MISMATCH"


def test_expired_identity_evidence_is_rejected(monkeypatch):
    monkeypatch.setenv("PAARI_IDENTITY_PROVIDER_ADAPTER", "tests.fake_trusted_identity_adapter:create_provider")
    monkeypatch.setenv("PAARI_TRUSTED_IDENTITY_PROVIDER_IDS", "test-reviewed-idp")
    provider = require_identity_provider()
    request = VerificationRequest(
        verification_id="verification-unit-3", organization_id="org-1",
        subject_reference="subject-1", kind=VerificationKind.INDIVIDUAL, jurisdiction="AE",
    )
    result = provider.verify(request)
    accepted, reason = validate_verification_result(
        result, provider_id=provider.provider_id, organization_id=request.organization_id,
        subject_reference=request.subject_reference, kind=request.kind, jurisdiction="AE",
        now=result.expires_at + timedelta(seconds=1),
    )
    assert accepted is False
    assert reason == "IDENTITY_EVIDENCE_EXPIRED_OR_NO_EXPIRY"


def test_control_plane_verify_endpoint_records_provider_evidence(paari_client, monkeypatch):
    from tests.test_control_plane_api import _issue_org_key

    ctx = paari_client
    key = _issue_org_key(ctx, monkeypatch)
    headers = {"X-Paari-Control-Key": key, "X-Paari-Org": "default"}
    monkeypatch.setenv("PAARI_IDENTITY_PROVIDER_ADAPTER", "tests.fake_trusted_identity_adapter:create_provider")
    monkeypatch.setenv("PAARI_TRUSTED_IDENTITY_PROVIDER_IDS", "test-reviewed-idp")

    created = ctx.client.post("/control/v1/principals", headers=headers, json={
        "external_subject_id": "provider-subject-42", "identity_provider": "oidc:bank-example",
        "display_name": "Provider-backed principal",
    })
    assert created.status_code == 201, created.text
    principal_id = created.json()["principal_id"]

    verified = ctx.client.post(f"/control/v1/principals/{principal_id}/verify", headers=headers, json={
        "verification_kind": "INDIVIDUAL", "jurisdiction": "AE",
    })
    assert verified.status_code == 200, verified.text
    body = verified.json()
    assert body["status"] == "ACTIVE"
    assert body["assurance_level"] == "substantial"
    assert body["identity_verification_status"] == "VERIFIED"
    assert body["verification_provider_id"] == "test-reviewed-idp"
    assert body["verification_expires_at"] is not None


def test_control_plane_verify_fails_closed_without_trusted_provider(paari_client, monkeypatch):
    from tests.test_control_plane_api import _issue_org_key

    ctx = paari_client
    key = _issue_org_key(ctx, monkeypatch)
    headers = {"X-Paari-Control-Key": key, "X-Paari-Org": "default"}
    monkeypatch.delenv("PAARI_IDENTITY_PROVIDER_ADAPTER", raising=False)
    monkeypatch.delenv("PAARI_TRUSTED_IDENTITY_PROVIDER_IDS", raising=False)
    created = ctx.client.post("/control/v1/principals", headers=headers, json={
        "external_subject_id": "provider-subject-absent", "identity_provider": "oidc:bank-example",
        "display_name": "Unverified principal",
    })
    assert created.status_code == 201, created.text
    result = ctx.client.post(f"/control/v1/principals/{created.json()['principal_id']}/verify",
                             headers=headers, json={"verification_kind": "INDIVIDUAL", "jurisdiction": "AE"})
    assert result.status_code == 503
    assert "identity verification adapter" in result.text.lower()
    assert "provider-subject-absent" not in result.text
    from app import models
    with ctx.Session() as db:
        row = db.query(models.PrincipalIdentity).filter_by(
            principal_id=created.json()["principal_id"]
        ).one()
        assert row.status == "PENDING"
        assert row.identity_verification_status == "UNVERIFIED"
