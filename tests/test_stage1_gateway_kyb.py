import asyncio
from datetime import datetime, timedelta, timezone
import pytest
from urllib.parse import quote

from app import models, security
from app.mtls_gateway import GatewayMTLSMiddleware, resolve_certificate_binding
from app.v36 import models as v36_models


def _onboard_parent(client, monkeypatch, identifier="ABCDE1234F"):
    monkeypatch.setenv("PAARI_V36_KEY_ENCRYPTION_SECRET", "local-test-parent-key-encryption-0123456789")
    monkeypatch.setenv("PAARI_V36_PII_HMAC_SECRET", "local-test-parent-pii-hmac-secret-0123456789")
    monkeypatch.setenv("PAARI_V36_AUTH_SECRET", "local-test-parent-auth-secret-0123456789")
    return client.post("/v36/parents/register", json={
        "parent_type": "person", "name": "Sandbox Parent", "identifier": identifier,
        "representative_name": "Sandbox Parent", "representative_email": "parent@local.invalid",
        "representative_phone": "9999999999", "password": "correct-horse-battery-staple",
        "accept_terms": True, "accept_privacy": True, "accept_agent_security": True,
    })


def test_mtls_certificate_binding_allows_only_active_agent_parent(paari_client):
    ctx = paari_client
    now = datetime.now(timezone.utc)
    with ctx.Session() as db:
        agent = db.query(models.Agent).filter_by(agent_id=ctx.agent_id).one()
        from app import crypto_utils
        db.add(models.AgentClientCertificate(
            agent_id=ctx.agent_id, org_id=agent.org_id,
            fingerprint_sha256="a" * 64,
            agent_card_key_fingerprint=crypto_utils.public_key_fingerprint(
                agent.public_key_pem, crypto_utils.Algorithm(agent.public_key_algorithm or "ed25519")),
            subject_cn=ctx.agent_id,
            not_before=now - timedelta(minutes=1), not_after=now + timedelta(days=1),
            status="ACTIVE",
        ))
        db.commit()
        assert resolve_certificate_binding("a" * 64, db) == (True, "MTLS_AGENT_CARD_BOUND", ctx.agent_id, agent.org_id)
        row = db.query(models.AgentClientCertificate).filter_by(fingerprint_sha256="a" * 64).one()
        row.agent_card_key_fingerprint = ""
        db.commit()
        legacy_allowed, legacy_reason, _agent, _org = resolve_certificate_binding("a" * 64, db)
        assert not legacy_allowed and legacy_reason == "AGENT_CARD_KEY_BINDING_MISSING_REENROLL_REQUIRED"
        row.agent_card_key_fingerprint = crypto_utils.public_key_fingerprint(
            agent.public_key_pem, crypto_utils.Algorithm(agent.public_key_algorithm or "ed25519"))
        row.status = "REVOKED"
        row.revoked_at = now
        db.commit()
        allowed, reason, resolved_agent, _org = resolve_certificate_binding("a" * 64, db)
        assert allowed is False
        assert reason == "AGENT_CERTIFICATE_REVOKED"
        assert resolved_agent == ctx.agent_id


def test_payment_intent_is_blocked_at_gateway_without_mtls(paari_client, monkeypatch):
    ctx = paari_client
    monkeypatch.setenv("PAARI_REQUIRE_MTLS_INGRESS", "1")
    monkeypatch.setenv("PAARI_MTLS_TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
    before = ctx.client.get("/health").status_code
    assert before == 200
    response = ctx.client.post("/v1/payments/intent", json={"agent_id": ctx.agent_id})
    assert response.status_code == 403
    assert response.json()["reason_code"] == "AGENT_INGRESS_REJECTED"
    assert response.json()["payment_intent_created"] is False
    with ctx.Session() as db:
        assert db.query(models.PaymentIntent).count() == 0
        audit = db.query(models.AuditEvent).filter_by(kind="gateway_ingress_denied").first()
        assert audit is not None
        assert audit.detail["payment_intent_created"] is False
        assert audit.detail["authorization_issued"] is False


def test_local_pki_certificate_registration_and_revocation(paari_client, monkeypatch, tmp_path):
    from scripts.mtls_pki import init_pki, issue_client
    ctx = paari_client
    pki = tmp_path / "pki"
    init_pki(pki)
    with ctx.Session() as db:
        registered_agent = db.query(models.Agent).filter_by(agent_id=ctx.agent_id).one()
        org_id = registered_agent.org_id
        agent_public = registered_agent.public_key_pem
        agent_algorithm = registered_agent.public_key_algorithm or "ed25519"
    agent_private_path = tmp_path / "agent-card-private.pem"
    agent_public_path = tmp_path / "agent-card-public.pem"
    agent_private_path.write_text(ctx.agent_private, encoding="utf-8")
    agent_public_path.write_text(agent_public, encoding="utf-8")
    issue_client(pki, ctx.agent_id, org_id=org_id,
                 agent_card_private_key=agent_private_path,
                 agent_card_public_key=agent_public_path,
                 agent_card_algorithm=agent_algorithm)
    cert_path = pki / "clients" / f"{ctx.agent_id}.crt"
    registration_payload = __import__("json").loads(
        (pki / "clients" / f"{ctx.agent_id}.register.json").read_text(encoding="utf-8"))
    monkeypatch.setenv("PAARI_MTLS_CA_CERT", str(pki / "ca.crt"))
    from app.mtls_gateway import mtls_ca_certificate_valid
    assert mtls_ca_certificate_valid() is True
    response = ctx.client.post(
        f"/control/v1/agents/{ctx.agent_id}/mtls-certificates",
        headers={"X-Admin-Api-Key": security._ADMIN_API_KEY},
        json=registration_payload,
    )
    assert response.status_code == 201, response.text
    fingerprint = response.json()["fingerprint_sha256"]
    certificate_pem = cert_path.read_text(encoding="utf-8")
    with ctx.Session() as db:
        allowed, reason, agent_id, _org = resolve_certificate_binding(fingerprint, db)
        assert allowed and reason == "MTLS_AGENT_CARD_BOUND" and agent_id == ctx.agent_id

    # Exercise the proxy contract using the URL-escaped certificate PEM that
    # Nginx $ssl_client_escaped_cert supplies. Paari must derive SHA-256 itself.
    monkeypatch.setenv("PAARI_REQUIRE_MTLS_INGRESS", "1")
    monkeypatch.setenv("PAARI_MTLS_TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
    async def invoke_middleware():
        passed = []
        sent = []
        async def downstream(_scope, _receive, _send):
            passed.append(True)
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}
        async def send(message):
            sent.append(message)
        scope = {"type": "http", "method": "POST", "path": "/v1/payments/intent",
                 "client": ("127.0.0.1", 12345),
                 "headers": [(b"x-paari-mtls-verify", b"SUCCESS"),
                             (b"x-paari-mtls-certificate", quote(certificate_pem, safe="").encode("ascii"))]}
        await GatewayMTLSMiddleware(downstream)(scope, receive, send)
        return passed, sent
    passed, sent = asyncio.run(invoke_middleware())
    assert passed == [True]
    assert not sent

    revoked = ctx.client.post(
        f"/control/v1/agents/{ctx.agent_id}/mtls-certificates/{fingerprint}/revoke",
        headers={"X-Admin-Api-Key": security._ADMIN_API_KEY},
        json={"reason": "Local sandbox certificate rotation test"},
    )
    assert revoked.status_code == 200, revoked.text
    with ctx.Session() as db:
        allowed, reason, _agent_id, _org = resolve_certificate_binding(fingerprint, db)
        assert not allowed and reason == "AGENT_CERTIFICATE_REVOKED"
    _passed, denied_messages = asyncio.run(invoke_middleware())
    assert any(message.get("status") == 403 for message in denied_messages)



def test_mtls_certificate_requires_agent_card_proof_of_possession(paari_client, monkeypatch, tmp_path):
    from scripts.mtls_pki import init_pki, issue_client
    ctx = paari_client
    pki = tmp_path / "pki-proof"
    init_pki(pki)
    with ctx.Session() as db:
        agent = db.query(models.Agent).filter_by(agent_id=ctx.agent_id).one()
        org_id, public_key, algorithm = agent.org_id, agent.public_key_pem, agent.public_key_algorithm or "ed25519"
    private_path, public_path = tmp_path / "agent-private.pem", tmp_path / "agent-public.pem"
    private_path.write_text(ctx.agent_private, encoding="utf-8")
    public_path.write_text(public_key, encoding="utf-8")
    issue_client(pki, ctx.agent_id, org_id=org_id, agent_card_private_key=private_path,
                 agent_card_public_key=public_path, agent_card_algorithm=algorithm)
    import json
    payload = json.loads((pki / "clients" / f"{ctx.agent_id}.register.json").read_text())
    monkeypatch.setenv("PAARI_MTLS_CA_CERT", str(pki / "ca.crt"))
    headers = {"X-Admin-Api-Key": security._ADMIN_API_KEY}
    bad = dict(payload)
    bad["agent_card_signature_b64"] = "A" * len(bad["agent_card_signature_b64"])
    denied = ctx.client.post(f"/control/v1/agents/{ctx.agent_id}/mtls-certificates", headers=headers, json=bad)
    assert denied.status_code == 403
    assert "proof-of-possession" in denied.text

    # A valid Agent Card signature for another organization must not bind this cert.
    from cryptography import x509
    from app import crypto_utils
    from app.mtls_gateway import build_agent_card_binding_payload
    cert = x509.load_pem_x509_certificate(payload["certificate_pem"].encode())
    wrong_org_binding = build_agent_card_binding_payload(
        ctx.agent_id, "different-organization", cert, public_key, algorithm)
    bad_org = dict(payload)
    bad_org["agent_card_signature_b64"] = crypto_utils.sign_with_private_key(
        ctx.agent_private, crypto_utils.canonical_json(wrong_org_binding), crypto_utils.Algorithm(algorithm))
    wrong_org_response = ctx.client.post(
        f"/control/v1/agents/{ctx.agent_id}/mtls-certificates", headers=headers, json=bad_org)
    assert wrong_org_response.status_code == 403

    accepted = ctx.client.post(f"/control/v1/agents/{ctx.agent_id}/mtls-certificates", headers=headers, json=payload)
    assert accepted.status_code == 201, accepted.text
    with ctx.Session() as db:
        row = db.query(models.AgentClientCertificate).filter_by(fingerprint_sha256=accepted.json()["fingerprint_sha256"]).one()
        assert row.agent_card_key_fingerprint
        agent = db.query(models.Agent).filter_by(agent_id=ctx.agent_id).one()
        old_key_fp = row.agent_card_key_fingerprint
        new_private, new_public = __import__("app.crypto_utils", fromlist=["generate_agent_keypair"]).generate_agent_keypair()
        agent.public_key_pem = new_public
        agent.public_key_algorithm = "ed25519"
        agent.old_public_key_pem = public_key
        agent.old_public_key_algorithm = algorithm
        agent.key_sunset_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        db.commit()
        grace_allowed, grace_reason, _agent_id, _org = resolve_certificate_binding(accepted.json()["fingerprint_sha256"], db)
        assert grace_allowed and grace_reason == "MTLS_AGENT_CARD_BOUND"
        agent.key_sunset_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
        allowed, reason, _agent_id, _org = resolve_certificate_binding(accepted.json()["fingerprint_sha256"], db)
        assert not allowed
        assert reason == "AGENT_CARD_KEY_ROTATED_CERT_REBIND_REQUIRED"


def test_mtls_certificate_profile_rejects_extra_san(paari_client, tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    from datetime import timedelta
    from app.mtls_gateway import _certificate_identity
    from scripts.mtls_pki import init_pki, issue_cert, load_ca
    from fastapi import HTTPException
    ctx = paari_client
    pki = tmp_path / "pki-san"
    init_pki(pki)
    ca_key, ca_cert = load_ca(pki)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ctx.agent_id)])
    cert = issue_cert(subject, key.public_key(), ca_key, ca_cert, client=True,
        sans=[x509.UniformResourceIdentifier(f"urn:paari:agent:{ctx.agent_id}"),
              x509.DNSName("unexpected.example")])
    with pytest.raises(HTTPException) as exc:
        _certificate_identity(cert, ctx.agent_id)
    assert exc.value.status_code == 422


def test_sandbox_kyb_simulation_is_explicit_and_never_claims_legal_verification(paari_client, monkeypatch):
    ctx = paari_client
    registration = _onboard_parent(ctx.client, monkeypatch)
    assert registration.status_code == 201, registration.text
    ref = registration.json()["registration_reference"]
    disabled = ctx.client.post(f"/v36/parents/{ref}/simulate-kyb", json={"scenario": "auto_approve"})
    assert disabled.status_code == 503
    monkeypatch.setenv("PAARI_KYB_SIMULATION", "1")
    simulated = ctx.client.post(f"/v36/parents/{ref}/simulate-kyb", json={"scenario": "auto_approve"})
    assert simulated.status_code == 200, simulated.text
    body = simulated.json()
    assert body["status"] == "active"
    assert body["outcome"] == "SIMULATED_VERIFIED"
    assert body["sandbox_only"] is True
    assert body["legal_identity_verified"] is False
    with ctx.Session() as db:
        parent = db.query(models.ParentAuthority).filter_by(parent_id=body["parent_id"]).one()
        assert parent.trust_tier == "sandbox_kyb"
        assert db.query(v36_models.KybSimulationCase).filter_by(case_id=body["case_id"], sandbox_only=True).one()
        audit = db.query(models.AuditEvent).filter_by(kind="sandbox_kyb_simulation").one()
        assert audit.detail["legal_identity_verified"] is False


@pytest.mark.parametrize(("scenario", "expected_status", "expected_outcome", "next_action", "suffix"), [
    ("auto_approve", "active", "SIMULATED_VERIFIED", "register_agent", "A"),
    ("review_required", "pending_verification", "REVIEW_REQUIRED", "manual_exception_review", "B"),
    ("reject", "rejected", "REJECTED", "registration_closed", "C"),
    ("provider_unavailable", "pending_verification", "UNAVAILABLE", "retry_provider_verification", "D"),
])
def test_sandbox_kyb_all_scenarios_have_explicit_next_action(
        paari_client, monkeypatch, scenario, expected_status, expected_outcome, next_action, suffix):
    ctx = paari_client
    registration = _onboard_parent(ctx.client, monkeypatch, identifier=f"ABCDE1234{suffix}")
    assert registration.status_code == 201, registration.text
    ref = registration.json()["registration_reference"]
    monkeypatch.setenv("PAARI_KYB_SIMULATION", "1")
    result = ctx.client.post(f"/v36/parents/{ref}/simulate-kyb", json={"scenario": scenario})
    assert result.status_code == 200, result.text
    assert result.json()["status"] == expected_status
    assert result.json()["outcome"] == expected_outcome
    assert result.json()["next_action"] == next_action
    assert result.json()["sandbox_only"] is True
    assert result.json()["legal_identity_verified"] is False
    status = ctx.client.get(f"/v36/parents/status/{ref}")
    assert status.status_code == 200
    assert status.json()["verification_outcome"] == expected_outcome
    assert status.json()["next_action"] == next_action
    assert status.json()["legal_identity_verified"] is False


def test_sandbox_kyb_exception_review_and_provider_retry(paari_client, monkeypatch):
    ctx = paari_client
    monkeypatch.setenv("PAARI_KYB_SIMULATION", "1")
    # Provider outage is retryable and each attempt remains in the audit trail.
    outage_reg = _onboard_parent(ctx.client, monkeypatch, identifier="ABCDE1234E")
    outage_ref = outage_reg.json()["registration_reference"]
    outage = ctx.client.post(f"/v36/parents/{outage_ref}/simulate-kyb", json={"scenario": "provider_unavailable"})
    assert outage.status_code == 200 and outage.json()["next_action"] == "retry_provider_verification"
    recovered = ctx.client.post(f"/v36/parents/{outage_ref}/simulate-kyb", json={"scenario": "auto_approve"})
    assert recovered.status_code == 200 and recovered.json()["outcome"] == "SIMULATED_VERIFIED"
    with ctx.Session() as db:
        assert db.query(v36_models.KybSimulationCase).filter_by(registration_ref=outage_ref).count() == 2

    # An exception is routed to the existing authenticated reviewer checklist.
    review_reg = _onboard_parent(ctx.client, monkeypatch, identifier="ABCDE1234G")
    review_ref = review_reg.json()["registration_reference"]
    parent_id = review_reg.json()["parent_id"]
    pending = ctx.client.post(f"/v36/parents/{review_ref}/simulate-kyb", json={"scenario": "review_required"})
    assert pending.status_code == 200 and pending.json()["next_action"] == "manual_exception_review"
    decision = ctx.client.post(f"/v36/admin/parents/{parent_id}/review",
        headers={"X-Admin-Api-Key": security._ADMIN_API_KEY},
        json={"approve": True, "identity_checked": True, "contact_checked": True,
              "representative_authority_checked": True, "reviewer_note": "Sandbox exception evidence checked"})
    assert decision.status_code == 200, decision.text
    status = ctx.client.get(f"/v36/parents/status/{review_ref}")
    assert status.json()["status"] == "active"
    assert status.json()["trust_tier"] == "admin_approved"
    with ctx.Session() as db:
        review_audit = db.query(models.AuditEvent).filter_by(kind="parent_manual_exception_review").one()
        assert review_audit.detail["reason_code"] == "KYB_MANUAL_EXCEPTION_APPROVED"
        assert review_audit.detail["checks"]["representative_authority_checked"] is True
        assert "reviewer_note_sha256" in review_audit.detail


def test_velocity_review_returns_structured_reason_code_and_threshold_evidence(paari_client):
    from tests.conftest import make_intent
    ctx = paari_client
    for index in range(5):
        result = make_intent(ctx, suffix=f"stage1-velocity-{index}")
        assert result["decision"] == "allow"
    reviewed = make_intent(ctx, suffix="stage1-velocity-over-limit")
    assert reviewed["decision"] == "review"
    assert "AGENT_VELOCITY_LIMIT_EXCEEDED" in reviewed["reason_codes"]
    evidence = reviewed["reason_evidence"]
    assert evidence["catalog_version"] == reviewed["reason_catalog_version"]
    assert evidence["observed"]["agent_request_count_in_window"] == 5
    assert evidence["observed"]["window_seconds"] == 60
    assert evidence["configured"]["agent_max_intents_per_window"] == 5
    assert evidence["configured"]["agent_velocity_window_seconds"] == 60
    velocity = next(item for item in evidence["policy_evaluations"] if item["policy_name"] == "velocity_check")
    assert velocity["passed"] is False
    with ctx.Session() as db:
        intent = db.query(models.PaymentIntent).filter_by(intent_id=reviewed["intent_id"]).one()
        assert "AGENT_VELOCITY_LIMIT_EXCEEDED" in intent.reason_codes
        audit = db.query(models.AuditEvent).filter_by(transaction_id=intent.transaction_id, kind="intent_decided").one()
        assert "AGENT_VELOCITY_LIMIT_EXCEEDED" in audit.detail["reason_codes"]
        assert audit.detail["reason_evidence"]["configured"]["agent_max_intents_per_window"] == 5


def test_reason_code_evidence_catalog_has_stable_explanations(paari_client):
    from app.reason_codes import CATALOG_VERSION, build_reason_evidence
    with paari_client.Session() as db:
        intent = models.PaymentIntent(
            intent_id="intent-evidence-test", transaction_id="txn-evidence-test",
            agent_id=paari_client.agent_id, org_id="default", merchant="TestMerchant",
            amount_minor_units=12500, currency="INR", action="make_payment",
            purpose="supplier payment", decision=models.GovernanceDecision.DENY,
            reasons=["Financial limit exceeded"], mfa_required=False,
        )
        agent = db.query(models.Agent).filter_by(agent_id=paari_client.agent_id).one()
        evidence = build_reason_evidence(reason_codes=["FINANCIAL_LIMIT_EXCEEDED"], intent=intent,
                                         agent=agent, policy_rules={"deny_threshold_bps": 9000})
        assert evidence["catalog_version"] == CATALOG_VERSION
        assert evidence["reason_items"][0]["title"] == "Financial limit exceeded"
        assert evidence["observed"]["amount_minor_units"] == 12500
        assert evidence["observed"]["delegated_limit_minor_units"] == agent.payment_limit_minor_units
        assert evidence["configured"]["deny_threshold_bps"] == 9000


def test_mtls_ingress_configuration_validation_fails_closed(monkeypatch, tmp_path):
    from app.mtls_gateway import _proxy_is_trusted, mtls_ca_certificate_valid, trusted_proxy_cidrs_valid
    monkeypatch.setenv("PAARI_MTLS_TRUSTED_PROXY_CIDRS", "not-a-cidr")
    assert trusted_proxy_cidrs_valid() is False
    assert _proxy_is_trusted("172.29.0.20") is False

    monkeypatch.setenv("PAARI_MTLS_TRUSTED_PROXY_CIDRS", "172.29.0.20/32,127.0.0.1/32")
    assert trusted_proxy_cidrs_valid() is True
    assert _proxy_is_trusted("172.29.0.20") is True
    monkeypatch.setenv("PAARI_MTLS_TRUSTED_PROXY_CIDRS", "0.0.0.0/0")
    assert trusted_proxy_cidrs_valid() is False
    assert _proxy_is_trusted("172.29.0.20") is False

    monkeypatch.setenv("PAARI_MTLS_CA_CERT", str(tmp_path / "missing-ca.pem"))
    assert mtls_ca_certificate_valid() is False
