from __future__ import annotations

import copy
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app import crypto_utils, security, models
from app.safr.envelope import (
    ActionContext, ActionTrace, GovernanceEnvelope, compute_action_digest,
    signing_payload, verify_envelope_signature,
)
from app.portability import (
    PortabilityValidationError, build_agent_portability_package,
    validate_agent_portability_package,
)


def _hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _signed_envelope(private_key: str, public_key: str, *, tenant="default", action_type="data.read",
                     principal_id="prn-1", resource_id="res-1", mandate_id=None):
    now = datetime.now(timezone.utc)
    raw = {
        "envelope_type": "paari.safr.governance-envelope",
        "schema_version": "1.0",
        "envelope_id": str(uuid.uuid4()),
        "tenant_id": tenant,
        "agent_id": "agt-1",
        "parent_id": "par-1",
        "principal_id": principal_id,
        "resource_id": resource_id,
        "mandate_id": mandate_id,
        "action_type": action_type,
        "action_context": {
            "resource_id": resource_id,
            "operation": action_type,
            "amount_minor_units": 100 if action_type.startswith("payment.") else None,
            "currency": "AED" if action_type.startswith("payment.") else None,
            "beneficiary_ref_digest": _hex("beneficiary") if action_type.startswith("payment.") else None,
            "merchant": "Test Merchant" if action_type.startswith("payment.") else None,
            "purpose": "Test purchase" if action_type.startswith("payment.") else None,
            "provider_id": "test-provider" if action_type.startswith("payment.") else None,
            "jurisdiction": "AE",
            "request_context_digest": _hex("request-context"),
        },
        "trace": {
            "trace_id": "trace-1",
            "source_system": "treasury-agent-test",
            "sequence": 1,
            "parent_trace_id": None,
            "trace_digest": _hex("agent-asserted-trace"),
        },
        "evidence_refs": [{
            "evidence_id": "evidence-1", "evidence_type": "transaction_trace",
            "source": "test-fixture", "digest": _hex("evidence"),
            "observed_at": now.isoformat(),
        }],
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=2)).isoformat(),
        "signing_key_fingerprint": crypto_utils.public_key_fingerprint(public_key),
        "action_digest": "0" * 64,
        "signature_b64": "A" * 88,
    }
    env = GovernanceEnvelope.model_validate(raw)
    raw["action_digest"] = compute_action_digest(env)
    env = GovernanceEnvelope.model_validate(raw)
    raw["signature_b64"] = crypto_utils.sign_with_private_key(
        private_key, crypto_utils.canonical_json(signing_payload(env))
    )
    return GovernanceEnvelope.model_validate(raw)


def test_governance_envelope_signature_and_digest_are_valid():
    private_key, public_key = crypto_utils.generate_agent_keypair()
    envelope = _signed_envelope(private_key, public_key)
    verify_envelope_signature(envelope, public_key)
    assert envelope.action_digest == compute_action_digest(envelope)
    assert envelope.action_context.jurisdiction == "AE"


def test_governance_envelope_rejects_changed_transaction_context():
    private_key, public_key = crypto_utils.generate_agent_keypair()
    envelope = _signed_envelope(private_key, public_key)
    changed = envelope.model_dump(mode="json")
    changed["action_context"]["request_context_digest"] = _hex("attacker-changed-context")
    tampered = GovernanceEnvelope.model_validate(changed)
    with pytest.raises(ValueError, match="action_digest"):
        verify_envelope_signature(tampered, public_key)


def test_governance_envelope_rejects_expired_or_long_lived_envelopes():
    private_key, public_key = crypto_utils.generate_agent_keypair()
    envelope = _signed_envelope(private_key, public_key)
    with pytest.raises(ValueError, match="expired"):
        verify_envelope_signature(envelope, public_key, now_epoch=int(envelope.expires_at.timestamp()) + 1)
    too_long = envelope.model_dump(mode="json")
    too_long["expires_at"] = (envelope.issued_at + timedelta(hours=1)).isoformat()
    with pytest.raises(ValidationError):
        GovernanceEnvelope.model_validate(too_long)


def test_payment_envelope_requires_transaction_bound_payment_fields():
    with pytest.raises(ValidationError, match="payment envelopes require"):
        GovernanceEnvelope.model_validate({
            "envelope_type": "paari.safr.governance-envelope", "schema_version": "1.0",
            "envelope_id": str(uuid.uuid4()), "tenant_id": "default", "agent_id": "agt-1",
            "parent_id": "par-1", "principal_id": "prn-1", "resource_id": "res-1",
            "action_type": "payment.execute", "action_context": {
                "resource_id": "res-1", "operation": "payment.execute", "request_context_digest": _hex("ctx")
            },
            "trace": {"trace_id": "t1", "source_system": "agent", "sequence": 1,
                      "trace_digest": _hex("trace")},
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            "signing_key_fingerprint": _hex("fp"), "action_digest": _hex("action"), "signature_b64": "A" * 88,
        })


def _portability_fixture():
    parent_private, parent_public = crypto_utils.generate_agent_keypair()
    agent_private, agent_public = crypto_utils.generate_agent_keypair()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    parent_id = "parent-portability"
    delegation_claims = {
        "delegation_id": "delegation-portability-1",
        "parent_id": parent_id,
        "agent_public_key_fingerprint": crypto_utils.public_key_fingerprint(agent_public),
        "granted_capabilities": ["make_payment"],
        "payment_limit_minor_units": 50000,
        "currency": "AED",
        "issued_at": int(now.timestamp()),
        "expires_at": int((now + timedelta(days=30)).timestamp()),
    }
    delegation_sig = crypto_utils.sign_with_private_key(parent_private, crypto_utils.canonical_json(delegation_claims))
    parent = SimpleNamespace(
        parent_id=parent_id, parent_type="company", status=models.ParentStatus.ACTIVE,
        trust_tier="admin_approved", verified_at=now, public_key_pem=parent_public,
    )
    agent = SimpleNamespace(
        agent_id="agent-portability-1", org_id="org-uae-1", name="Treasury agent",
        agent_type="treasury", status=models.AgentStatus.ACTIVE, public_key_pem=agent_public,
        granted_capabilities=["make_payment"], payment_limit_minor_units=50000, currency="AED",
        valid_until=now + timedelta(days=30),
    )
    delegation_record = SimpleNamespace(
        delegation_id=delegation_claims["delegation_id"],
        agent_public_key_fingerprint=delegation_claims["agent_public_key_fingerprint"],
        granted_capabilities=delegation_claims["granted_capabilities"],
        payment_limit_minor_units=delegation_claims["payment_limit_minor_units"],
        currency=delegation_claims["currency"],
        issued_at=now, expires_at=now + timedelta(days=30),
        delegation_signature_b64=delegation_sig,
    )
    card_fields = {
        "agent_id": agent.agent_id, "name": agent.name, "agent_type": agent.agent_type,
        "parent_id": parent_id, "parent_name": "Treasury Parent", "identity_status": "active",
        "public_key_reference": agent_public, "granted_capabilities": ["make_payment"],
        "payment_limit_minor_units": 50000, "currency": "AED", "valid_until": agent.valid_until.isoformat(),
        "credential_id": "credential-1", "paari_endpoint": "/agents",
    }
    card = {
        **card_fields,
        "card_signature_b64": security.sign_agent_card(card_fields),
        "paari_public_key_pem": security.paari_public_key_pem(),
    }
    return agent, parent, delegation_record, card


def test_portability_package_verifies_issuer_card_and_parent_delegation():
    agent, parent, delegation, card = _portability_fixture()
    package = build_agent_portability_package(agent=agent, parent=parent, delegation_record=delegation, agent_card=card)
    key_id = security.signing_backend_status()["key_id"]
    result = validate_agent_portability_package(package, trusted_issuer_keys={key_id: security.paari_public_key_pem()})
    assert result["valid"] is True
    assert result["signatures_verified"] == ["paari_package", "paari_agent_card", "parent_delegation"]
    assert result["authority_transferred"] is False
    assert "private_keys" in package["portability_policy"]["never_exported"]


def test_portability_package_rejects_tampering_and_untrusted_issuer():
    agent, parent, delegation, card = _portability_fixture()
    package = build_agent_portability_package(agent=agent, parent=parent, delegation_record=delegation, agent_card=card)
    key_id = security.signing_backend_status()["key_id"]
    trusted = {key_id: security.paari_public_key_pem()}
    tampered = copy.deepcopy(package)
    tampered["agent_card"]["name"] = "Changed by importer"
    with pytest.raises(PortabilityValidationError, match="package signature"):
        validate_agent_portability_package(tampered, trusted_issuer_keys=trusted)
    with pytest.raises(PortabilityValidationError, match="trust store"):
        validate_agent_portability_package(package, trusted_issuer_keys={"untrusted-key": security.paari_public_key_pem()})


def _root_headers(monkeypatch, key="test-root-control-key"):
    monkeypatch.setattr(security, "_ADMIN_API_KEY", key)
    return {"X-Admin-Api-Key": key}


def _issue_org_key(ctx, monkeypatch, org_id="default"):
    with ctx.Session() as db:
        if not db.query(models.Organization).filter_by(org_id=org_id).first():
            db.add(models.Organization(org_id=org_id, name="Test Organization"))
            db.commit()
    response = ctx.client.post("/control/v1/admin-keys", headers=_root_headers(monkeypatch), json={
        "org_id": org_id, "scopes": ["control:read", "control:write"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    })
    assert response.status_code == 201, response.text
    return response.json()["secret"]


def test_fleet_risk_summary_handles_one_hundred_agents(paari_client, monkeypatch):
    """Functional 100-agent inventory check; not a production load/soak test."""
    ctx = paari_client
    secret = _issue_org_key(ctx, monkeypatch)
    headers = {"X-Paari-Control-Key": secret, "X-Paari-Org": "default"}
    now = datetime.now(timezone.utc)
    with ctx.Session() as db:
        existing = db.query(models.Agent).filter_by(agent_id=ctx.agent_id).one()
        parent_pk = existing.parent_pk
        public_key = existing.public_key_pem
        existing_agents = db.query(models.Agent).filter_by(org_id="default").all()
        existing_ids = {row.agent_id for row in existing_agents}
        for row in existing_agents:
            row.status = models.AgentStatus.ACTIVE
        needed = max(0, 100 - len(existing_ids))
        for idx in range(needed):
            db.add(models.Agent(
                agent_id=f"fleet-acceptance-{uuid.uuid4().hex}",
                org_id="default",
                name=f"Treasury fleet agent {idx + 1}",
                agent_type="treasury-acceptance",
                purpose="100-agent fleet acceptance fixture",
                parent_pk=parent_pk,
                delegation_id=f"fleet-delegation-{uuid.uuid4().hex}",
                public_key_pem=public_key,
                granted_capabilities=["payment:execute"],
                payment_limit_minor_units=10000,
                currency="AED",
                status=models.AgentStatus.ACTIVE,
                created_at=now,
                valid_until=now + timedelta(days=30),
            ))
        db.commit()

    response = ctx.client.get("/control/v1/organizations/default/fleet/risk-summary", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["fleet"]["total_agents"] == 100
    assert len(body["agents"]) == 100
    assert len({item["agent_id"] for item in body["agents"]}) == 100
    assert body["fleet"]["active_agents"] == 100
    assert body["exposure_semantics"].startswith("Unconsumed, unexpired authorizations")


def test_agent_portability_export_is_signed_and_excludes_authority(paari_client, monkeypatch):
    ctx = paari_client
    secret = _issue_org_key(ctx, monkeypatch)
    headers = {"X-Paari-Control-Key": secret, "X-Paari-Org": "default"}
    response = ctx.client.get(f"/control/v1/organizations/default/agents/{ctx.agent_id}/portability-export", headers=headers)
    assert response.status_code == 200, response.text
    package = response.json()
    key_id = package["issuer"]["key_id"]
    trusted_key = package["issuer"]["public_key_pem"]
    result = validate_agent_portability_package(package, trusted_issuer_keys={key_id: trusted_key})
    assert result["valid"] is True
    assert package["portability_policy"]["authority_transferred"] is False
    assert package["portability_policy"]["destination_consent_and_grants_required"] is True
    assert "user_mandates" in package["portability_policy"]["never_exported"]


def test_governance_envelope_ingress_records_one_receipt_and_rejects_replay(paari_client, monkeypatch):
    ctx = paari_client
    secret = _issue_org_key(ctx, monkeypatch)
    headers = {"X-Paari-Control-Key": secret, "X-Paari-Org": "default"}
    now = datetime.now(timezone.utc)
    with ctx.Session() as db:
        agent = db.query(models.Agent).filter_by(agent_id=ctx.agent_id).one()
        parent = db.query(models.ParentAuthority).filter_by(id=agent.parent_pk).one()
        # This represents a fresh, explicitly parent-signed delegation that adds the data.read capability.
        delegated = {
            "delegation_id": str(uuid.uuid4()), "parent_id": parent.parent_id,
            "agent_public_key_fingerprint": crypto_utils.public_key_fingerprint(agent.public_key_pem),
            "granted_capabilities": ["data.read"], "payment_limit_minor_units": int(agent.payment_limit_minor_units),
            "currency": agent.currency, "issued_at": int(now.timestamp()),
            "expires_at": int((now + timedelta(days=30)).timestamp()),
        }
        delegated_signature = crypto_utils.sign_with_private_key(ctx.parent_private, crypto_utils.canonical_json(delegated))
        db.add(models.DelegationRecord(
            delegation_id=delegated["delegation_id"], org_id=agent.org_id, parent_pk=parent.id,
            agent_public_key_fingerprint=delegated["agent_public_key_fingerprint"],
            delegation_signature_b64=delegated_signature, granted_capabilities=["data.read"],
            payment_limit_minor_units=delegated["payment_limit_minor_units"], currency=delegated["currency"],
            issued_at=now, expires_at=now + timedelta(days=30), consumed=True, consumed_at=now,
        ))
        agent.delegation_id = delegated["delegation_id"]
        agent.granted_capabilities = ["data.read"]
        db.commit()

    principal = ctx.client.post("/control/v1/principals", headers=headers, json={
        "external_subject_id": "data-reader-1", "identity_provider": "test-idp", "display_name": "Data Reader",
    })
    assert principal.status_code == 201, principal.text
    principal_id = principal.json()["principal_id"]
    assert ctx.client.post(f"/control/v1/principals/{principal_id}/attest", headers=headers,
                           json={"attestation_reference": "test-attestation-1"}).status_code == 200
    resource = ctx.client.post("/control/v1/resources", headers=headers, json={
        "resource_type": "data_set", "provider_id": "treasury-test", "external_resource_ref": "treasury-summary-1",
        "owner_principal_id": principal_id, "classification": "confidential", "metadata": {"schema": "summary-v1"},
    })
    assert resource.status_code == 201, resource.text
    resource_id = resource.json()["resource_id"]
    valid_from = (now - timedelta(seconds=2)).isoformat()
    valid_until = (now + timedelta(days=1)).isoformat()
    for subject_type, subject_id in (("agent", ctx.agent_id), ("principal", principal_id)):
        grant = ctx.client.post(f"/control/v1/resources/{resource_id}/grants", headers=headers, json={
            "subject_type": subject_type, "subject_id": subject_id, "actions": ["data:read"],
            "consent_reference": f"consent-{subject_type}-1", "valid_from": valid_from, "valid_until": valid_until,
        })
        assert grant.status_code == 201, grant.text

    private_key = ctx.agent_private
    with ctx.Session() as db:
        agent = db.query(models.Agent).filter_by(agent_id=ctx.agent_id).one()
        public_key = agent.public_key_pem
        parent_id = db.query(models.ParentAuthority).filter_by(id=agent.parent_pk).one().parent_id
    now = datetime.now(timezone.utc)
    envelope_id = str(uuid.uuid4())
    raw = {
        "envelope_type": "paari.safr.governance-envelope", "schema_version": "1.0",
        "envelope_id": envelope_id, "tenant_id": "default", "agent_id": ctx.agent_id,
        "parent_id": parent_id, "principal_id": principal_id, "resource_id": resource_id,
        "action_type": "data.read", "action_context": {
            "resource_id": resource_id, "operation": "data.read", "jurisdiction": "AE",
            "request_context_digest": _hex("data-read-request"),
        },
        "trace": {"trace_id": "trace-data-read-1", "source_system": "treasury-test", "sequence": 1,
                  "trace_digest": _hex("trace-data-read")},
        "evidence_refs": [], "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=2)).isoformat(),
        "signing_key_fingerprint": crypto_utils.public_key_fingerprint(public_key),
        "action_digest": "0" * 64, "signature_b64": "A" * 88,
    }
    env = GovernanceEnvelope.model_validate(raw)
    raw["action_digest"] = compute_action_digest(env)
    env = GovernanceEnvelope.model_validate(raw)
    raw["signature_b64"] = crypto_utils.sign_with_private_key(private_key, crypto_utils.canonical_json(signing_payload(env)))
    signed = GovernanceEnvelope.model_validate(raw).model_dump(mode="json")

    first = ctx.client.post("/control/v1/governance/envelopes/validate", headers=headers, json=signed)
    assert first.status_code == 200, first.text
    assert first.json()["validation_status"] == "VALIDATED_ONLY"
    assert first.json()["policy_evaluated"] is False
    assert first.json()["authorization_issued"] is False
    replay = ctx.client.post("/control/v1/governance/envelopes/validate", headers=headers, json=signed)
    assert replay.status_code == 409, replay.text

    # A valid signature and even a valid data grant are not enough to create
    # authority while this build has no registered data/API executor.
    process_raw = copy.deepcopy(signed)
    process_raw["envelope_id"] = str(uuid.uuid4())
    process_raw["trace"]["trace_id"] = "trace-data-read-process-2"
    process_raw["trace"]["sequence"] = 2
    process_raw["action_digest"] = "0" * 64
    process_raw["signature_b64"] = "A" * 88
    process_env = GovernanceEnvelope.model_validate(process_raw)
    process_raw["action_digest"] = compute_action_digest(process_env)
    process_env = GovernanceEnvelope.model_validate(process_raw)
    process_raw["signature_b64"] = crypto_utils.sign_with_private_key(
        private_key, crypto_utils.canonical_json(signing_payload(process_env))
    )
    process_signed = GovernanceEnvelope.model_validate(process_raw).model_dump(mode="json")
    processed = ctx.client.post("/control/v1/governance/envelopes/process", headers=headers, json=process_signed)
    assert processed.status_code == 200, processed.text
    assert processed.json()["disposition"] == "DENY"
    assert processed.json()["reason_codes"] == ["GOVERNED_EXECUTOR_NOT_REGISTERED"]
    assert processed.json()["authorization_issued"] is False
    assert processed.json()["execution_permitted"] is False


def test_fleet_risk_summary_and_emergency_revoke_are_tenant_scoped(paari_client, monkeypatch):
    ctx = paari_client
    secret = _issue_org_key(ctx, monkeypatch)
    headers = {"X-Paari-Control-Key": secret, "X-Paari-Org": "default"}

    before = ctx.client.get("/control/v1/organizations/default/fleet/risk-summary", headers=headers)
    assert before.status_code == 200, before.text
    before_json = before.json()
    assert before_json["fleet"]["total_agents"] >= 1
    agent_row = next(item for item in before_json["agents"] if item["agent_id"] == ctx.agent_id)
    assert agent_row["risk_status"] == "UNASSESSED"
    assert agent_row["outstanding_exposure_by_currency_minor_units"] == {}

    revoked = ctx.client.post(
        f"/control/v1/organizations/default/agents/{ctx.agent_id}/revoke?reason=treasury-emergency-stop",
        headers=headers,
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"
    assert revoked.json()["credentials_revoked"] is True
    assert revoked.json()["active_agent_grants_revoked"] is True

    after = ctx.client.get("/control/v1/organizations/default/fleet/risk-summary", headers=headers)
    assert after.status_code == 200, after.text
    after_row = next(item for item in after.json()["agents"] if item["agent_id"] == ctx.agent_id)
    assert after_row["status"] == "revoked"
    assert after_row["risk_status"] == "BLOCKED"


def test_portability_import_requires_local_trust_and_stages_without_authority_transfer(
    paari_client, monkeypatch,
):
    ctx = paari_client
    secret = _issue_org_key(ctx, monkeypatch)
    headers = {"X-Paari-Control-Key": secret, "X-Paari-Org": "default"}
    agent, source_parent, delegation, card = _portability_fixture()
    package = build_agent_portability_package(
        agent=agent, parent=source_parent, delegation_record=delegation, agent_card=card,
    )
    key_id = package["issuer"]["key_id"]
    # Test-only out-of-band trust pin. The endpoint does not trust a key merely
    # because it appears in an imported package.
    monkeypatch.setenv("PAARI_PORTABILITY_TRUSTED_ISSUERS_JSON", json.dumps({
        key_id: security.paari_public_key_pem(),
    }))

    now = datetime.now(timezone.utc)
    dest_parent_private, dest_parent_public = crypto_utils.generate_agent_keypair()
    del dest_parent_private  # The sandbox stores only the destination public trust root.
    with ctx.Session() as db:
        dest_parent = models.ParentAuthority(
            org_id="default", name="Destination Treasury", parent_type="company",
            contact="destination-treasury@example.invalid", public_key_pem=dest_parent_public,
            status=models.ParentStatus.ACTIVE, trust_tier="admin_approved", verified_at=now,
        )
        db.add(dest_parent)
        db.flush()
        dest_principal = models.PrincipalIdentity(
            org_id="default", external_subject_id="destination-principal-001",
            identity_provider="uae-pass-production-adapter", display_name="Destination Principal",
            status="ACTIVE", assurance_level="high", attestation_reference="uae-pass-case-001",
            attested_at=now,
        )
        db.add(dest_principal)
        db.flush()
        dest_resource = models.GovernedResource(
            org_id="default", resource_type="treasury_account", provider_id="test-provider",
            external_resource_ref="destination-account-ref-001", owner_principal_id=dest_principal.principal_id,
            currency="AED", classification="restricted", status="ACTIVE", resource_metadata={},
        )
        db.add(dest_resource)
        db.flush()
        db.add(models.ResourceAccessGrant(
            org_id="default", resource_id=dest_resource.resource_id, subject_type="principal",
            subject_id=dest_principal.principal_id, actions=["payment:execute"],
            consent_reference="destination-consent-001", status="ACTIVE",
            valid_from=now - timedelta(seconds=2), valid_until=now + timedelta(days=1),
            created_by="test-destination-reviewer",
        ))
        db.commit()
        destination_parent_id = dest_parent.parent_id
        destination_principal_id = dest_principal.principal_id
        destination_resource_id = dest_resource.resource_id

    payload = {
        "package": package,
        "destination_parent_id": destination_parent_id,
        "destination_principal_id": destination_principal_id,
        "destination_resource_id": destination_resource_id,
        "consent_reference": "destination-consent-001",
    }
    staged = ctx.client.post("/control/v1/portability/import/validate", headers=headers, json=payload)
    assert staged.status_code == 200, staged.text
    staged_json = staged.json()
    assert staged_json["state"] == "STAGED"
    assert staged_json["authority_transferred"] is False
    assert staged_json["credentials_imported"] is False
    assert staged_json["mandate_imported"] is False
    assert staged_json["destination_checks"]["destination_consent_grant_verified"] is True

    readback = ctx.client.get(f"/control/v1/portability/imports/{staged_json['import_id']}", headers=headers)
    assert readback.status_code == 200, readback.text
    assert readback.json()["state"] == "STAGED"
    assert readback.json()["authority_transferred"] is False

    duplicate = ctx.client.post("/control/v1/portability/import/validate", headers=headers, json=payload)
    assert duplicate.status_code == 409, duplicate.text


def test_governance_envelope_does_not_accept_unknown_secret_fields():
    raw = {
        "envelope_type": "paari.safr.governance-envelope", "schema_version": "1.0",
        "envelope_id": str(uuid.uuid4()), "tenant_id": "default", "agent_id": "agt-1",
        "parent_id": "par-1", "principal_id": "prn-1", "resource_id": "res-1",
        "action_type": "data.read", "action_context": {
            "resource_id": "res-1", "operation": "data.read", "request_context_digest": _hex("ctx"),
            "api_key": "should-be-rejected",
        },
        "trace": {"trace_id": "t1", "source_system": "agent", "sequence": 1, "trace_digest": _hex("trace")},
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
        "signing_key_fingerprint": _hex("fingerprint"), "action_digest": _hex("action"), "signature_b64": "A" * 88,
    }
    with pytest.raises(ValidationError):
        GovernanceEnvelope.model_validate(raw)


def test_sandbox_identity_provider_never_manufactures_verification():
    from app.identity_providers.contracts import (
        SandboxIdentityVerificationProvider, VerificationKind, VerificationRequest, VerificationStatus,
    )
    provider = SandboxIdentityVerificationProvider("test")
    request = VerificationRequest(
        verification_id="verify-test-1", organization_id="org-test",
        subject_reference="synthetic-subject", kind=VerificationKind.ORGANIZATION,
        jurisdiction="AE",
    )
    result = provider.verify(request)
    assert result.status is VerificationStatus.REVIEW_REQUIRED
    assert result.assurance_level == "low"
    assert provider.healthcheck() is True
    with pytest.raises(RuntimeError, match="forbidden"):
        SandboxIdentityVerificationProvider("prod")
