"""v3.7.1 portal/API regressions found during end-to-end setup.

1. Agent Cards are signed over their *serialized* form. ``datetime.isoformat``
   emits ``+00:00`` while Pydantic serializes ``Z``, so signing the raw dict
   produced a signature that neither the public verification route nor the
   reference SDK could reproduce.
2. ``/v1/payments/intent`` accepted a request model without ``provider_id``;
   the v3.6 provider gate read the attribute directly and raised
   ``AttributeError`` (HTTP 500) for every v3.6-onboarded agent. It must return
   a governed DENY instead.
"""
import uuid

from app import crypto_utils
from app import security


SECRETS = {
    "PAARI_V36_KEY_ENCRYPTION_SECRET": "v36-key-encryption-only-local-test-key-1234",
    "PAARI_V36_PII_HMAC_SECRET": "v36-sensitive-identity-hmac-test-only-9876",
    "PAARI_V36_AUTH_SECRET": "v36-authentication-session-test-key-123456",
}


def _onboard_agent(client):
    parent = client.post("/v36/parents/register", json={
        "parent_type": "person", "name": "Ravi Kumar", "identifier": "ABCDE1234F",
        "representative_name": "Ravi Kumar", "representative_email": "ravi@local.invalid",
        "representative_phone": "9999999999",
        "password": "correct-horse-battery-staple",
        "accept_terms": True, "accept_privacy": True, "accept_agent_security": True,
    })
    assert parent.status_code == 201, parent.text
    parent_id = parent.json()["parent_id"]
    assert client.post(f"/v36/admin/parents/{parent_id}/review",
                       headers={"X-Admin-Api-Key": security._ADMIN_API_KEY},
                       json={"approve": True, "identity_checked": True, "contact_checked": True,
                             "representative_authority_checked": True,
                             "reviewer_note": "Reviewed local regression fixture"}).status_code == 200
    login = client.post("/v36/parents/login", json={
        "parent_id": parent_id, "password": "correct-horse-battery-staple"})
    assert login.status_code == 200, login.text
    private, public = crypto_utils.generate_agent_keypair()
    agent = client.post("/v36/agents/register",
                        headers={"Authorization": "Bearer " + login.json()["access_token"]},
                        json={
                            "basics": {"name": "PurchaseBot", "agent_type": "shopping_assistant",
                                       "purpose": "Buy approved supplies"},
                            "agent_public_key_pem": public,
                            "delegation": {"capabilities": ["make_payment"],
                                           "limit_minor_units": 10000, "currency": "INR",
                                           "valid_days": 10},
                            "escalation_contact": {"name": "Ravi Kumar",
                                                   "email": "ravi@local.invalid",
                                                   "phone": "9999999999"},
                            "accept_agent_security": True,
                        })
    assert agent.status_code == 201, agent.text
    body = agent.json()
    agent_id = body["agent_card"]["agent_id"]
    nonce = client.post("/v1/auth/challenge", json={"agent_id": agent_id}).json()["nonce"]
    auth = client.post("/v1/auth/verify", json={
        "agent_id": agent_id, "nonce": nonce,
        "signature_b64": crypto_utils.sign_with_private_key(private, nonce),
        "credential_jwt": body["credential_jwt"]})
    assert auth.status_code == 200, auth.text
    return agent_id, private, auth.json()["session_token"]


def test_agent_card_signature_verifies_over_serialized_response(paari_client, monkeypatch):
    for key, value in SECRETS.items():
        monkeypatch.setenv(key, value)
    c = paari_client.client
    agent_id, _private, _session = _onboard_agent(c)

    card = c.get(f"/agents/{agent_id}/card")
    assert card.status_code == 200, card.text
    payload = card.json()
    signature = payload.pop("card_signature_b64")
    payload.pop("paari_public_key_pem", None)
    assert signature
    # A relying party only has the serialized response; it must verify.
    assert security.verify_agent_card(payload, signature) is True

    public = c.get(f"/portal/v1/public/agent-cards/{agent_id}/verify")
    assert public.status_code == 200, public.text
    assert public.json()["signature_valid"] is True


def test_v1_intent_without_provider_is_denied_not_500(paari_client, monkeypatch):
    for key, value in SECRETS.items():
        monkeypatch.setenv(key, value)
    c = paari_client.client
    agent_id, private, session = _onboard_agent(c)

    suffix = uuid.uuid4().hex[:8]
    path = "/v1/payments/intent"
    proof = security.encode_request_proof(
        private, method="POST", path=path, access_token=session,
        agent_id=agent_id, jti=str(uuid.uuid4()))
    response = c.post(path, headers={"Authorization": "Bearer " + session,
                                     "X-Paari-Proof": proof}, json={
        "agent_id": agent_id, "transaction_id": "TXN-" + suffix,
        "idempotency_key": "idem-" + suffix, "merchant": "ApprovedSupplier",
        "amount_minor_units": 1200, "currency": "INR", "action": "make_payment",
        "purpose": "Pay supplier invoice",
    })
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "deny"
    assert body["authorization"] is None
    assert any("provider_id" in reason for reason in body["reasons"]), body["reasons"]
