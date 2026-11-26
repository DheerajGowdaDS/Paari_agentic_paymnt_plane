"""v3.4: receiving-side controls and signed evidence, without pretending settlement."""
from datetime import datetime, timedelta, timezone
import uuid
import pytest
from app import crypto_utils, models, security
from tests.conftest import make_intent


def _create(ctx, monkeypatch, org="default"):
    monkeypatch.setattr(security,"_ADMIN_API_KEY","v34-root-testing-only")
    db=ctx.Session()
    if not db.query(models.Organization).filter_by(org_id=org).first():
        db.add(models.Organization(org_id=org,name="Test Organization"));db.commit()
    db.close()
    response=ctx.client.post("/control/v1/admin-keys",headers={"X-Admin-Api-Key":"v34-root-testing-only"},json={
        "org_id":org,"scopes":["control:read","control:write"],
        "expires_at":(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()})
    assert response.status_code==201,response.text
    headers={"X-Paari-Control-Key":response.json()["secret"],"X-Paari-Org":org}
    receiver_private,receiver_public=crypto_utils.generate_agent_keypair()
    r=ctx.client.post("/control/v1/receivers/institutions",headers=headers,json={
        "external_id":"bank-test"+uuid.uuid4().hex[:8],"name":"Test Receiver Bank","rail":"BANK",
        "public_key_pem":receiver_public})
    assert r.status_code==201,r.text
    receiver_id=r.json()["receiver_id"]
    return headers,receiver_id,receiver_private


def _approve(ctx, receiver_id):
    r=ctx.client.post(f"/control/v1/receivers/institutions/{receiver_id}/approve",
        headers={"X-Admin-Api-Key":"v34-root-testing-only","X-Paari-Org":"default"},
        json={"verification_reference":"local-check-123"})
    assert r.status_code==200,r.text
    assert r.json()["identity_assurance"]=="ADMIN_APPROVED"


def _beneficiary(ctx, monkeypatch,headers,receiver_id):
    monkeypatch.setenv("PAARI_BENEFICIARY_HASH_SECRET","v34-test-key-sufficient-entropy-very-long")
    r=ctx.client.post("/control/v1/receivers/beneficiaries",headers=headers,json={
        "receiver_id":receiver_id,"alias":"TestMerchant","account_reference":"account-secret-reference-123",
        "currency":"INR","max_payment_minor_units":100000})
    assert r.status_code==201,r.text
    assert "account-secret-reference" not in r.text
    return r.json()["beneficiary_id"]


def _intent(ctx, beneficiary_id=None, suffix=None):
    suffix=suffix or uuid.uuid4().hex
    return ctx.client.post("/payments/intent",json={"session_token":ctx.session_token,
        "transaction_id":"TXN-v34-"+suffix,"idempotency_key":"idem-v34-"+suffix,
        "merchant":"TestMerchant","amount_minor_units":1000,"currency":"INR",
        "action":"make_payment","beneficiary_id":beneficiary_id})


def test_receiver_registration_does_not_self_approve(paari_client,monkeypatch):
    ctx=paari_client;headers,receiver_id,_=_create(ctx,monkeypatch)
    item=ctx.client.get("/control/v1/receivers/institutions",headers=headers).json()[0]
    assert item["status"]=="PENDING" and item["identity_assurance"]=="UNVERIFIED"
    assert "public_key_pem" not in item
    bad=ctx.client.post("/control/v1/receivers/institutions",headers=headers,json={
        "external_id":"bank-evil","name":"Evil","rail":"BANK","public_key_pem":"not-a-public-key"})
    assert bad.status_code==422
    unauthorized=ctx.client.post(f"/control/v1/receivers/institutions/{receiver_id}/approve",
        headers={"X-Admin-Api-Key":"wrong","X-Paari-Org":"default"},
        json={"verification_reference":"local-check-123"})
    assert unauthorized.status_code in (401,403)


def test_receiver_enforcement_and_revocation_on_execution(paari_client,monkeypatch):
    ctx=paari_client;headers,receiver_id,_=_create(ctx,monkeypatch)
    monkeypatch.setenv("PAARI_RECEIVER_ENFORCEMENT","1")
    missing=_intent(ctx)
    assert missing.status_code==200,missing.text
    assert missing.json()["decision"]=="deny"
    assert "beneficiary" in " ".join(missing.json()["reasons"]).lower()
    _approve(ctx,receiver_id)
    ben=_beneficiary(ctx,monkeypatch,headers,receiver_id)
    allowed=_intent(ctx,ben)
    assert allowed.status_code==200,allowed.text
    assert allowed.json()["decision"]=="allow",allowed.text
    auth=allowed.json()["authorization"]
    assert auth is not None
    # Block after authorizing; consume must fail BEFORE touching the provider
    blocked=ctx.client.post(f"/control/v1/receivers/beneficiaries/{ben}/block",
        headers=headers,json={"reason":"fraud risk incident"})
    assert blocked.status_code==200,blocked.text
    consumed=ctx.client.post(f"/payments/authorizations/{auth['authorization_id']}/consume",
        json={"session_token":ctx.session_token})
    assert consumed.status_code==403,consumed.text
    assert "Receiver" in str(consumed.json())
    db=ctx.Session()
    try:
        stored=db.query(models.BoundedAuthorization).filter_by(authorization_id=auth['authorization_id']).one()
        assert stored.usage_count==0
        assert all(t.state not in ("PROVIDER_SUBMITTED", "PAID", "CAPTURED") for t in db.query(models.ProviderTransaction).filter_by(authorization_id=stored.authorization_id).all())
    finally:db.close()


def test_signed_receiver_attestation_cannot_settle_and_replay_fails(paari_client,monkeypatch):
    ctx=paari_client;headers,receiver_id,private=_create(ctx,monkeypatch)
    _approve(ctx,receiver_id)
    ben=_beneficiary(ctx,monkeypatch,headers,receiver_id)
    monkeypatch.setenv("PAARI_RECEIVER_ENFORCEMENT","1")
    r=_intent(ctx,ben)
    assert r.status_code==200 and r.json()["decision"]=="allow",r.text
    iid=r.json()["intent_id"]
    claim={"event_id":"test-ack-"+uuid.uuid4().hex,"receiver_id":receiver_id,
           "beneficiary_id":ben,"intent_id":iid,"result":"CREDIT_ATTESTED",
           "provider_reference":"bank-ref-123","amount_minor_units":1000,"currency":"INR",
           "signed_at":datetime.now(timezone.utc).isoformat()}
    from app.receivers.router import ReceiverClaim
    sig=crypto_utils.sign_with_private_key(private,crypto_utils.canonical_json(ReceiverClaim.model_validate(claim).model_dump(mode="json")))
    endpoint="/control/v1/receivers/attestations"
    # Initial claimed credit cannot be accepted before provider capture.
    premature=ctx.client.post(endpoint,json={"claim":claim,"signature_b64":sig})
    assert premature.status_code==409
    db=ctx.Session()
    try:
        from app.transitions import transition_txn
        txn=db.query(models.ProviderTransaction).filter_by(intent_id=iid).one()
        transition_txn(txn,"PROVIDER_SUBMITTED")
        transition_txn(txn,"CAPTURED")
        db.commit()
    finally: db.close()
    bad=dict(claim,amount_minor_units=2000)
    assert ctx.client.post(endpoint,json={"claim":bad,"signature_b64":sig}).status_code==403
    good=ctx.client.post(endpoint,json={"claim":claim,"signature_b64":sig})
    assert good.status_code==201,good.text
    assert good.json()["receiver_signature_verified"] is True
    assert good.json()["settlement_confirmed"] is False
    evidence=ctx.client.get(f"/control/v1/receivers/payment-evidence/{iid}",headers=headers)
    assert evidence.status_code==200,evidence.text
    assert evidence.json()["receiver_credit_independently_verified"] is False
    assert evidence.json()["provider_settlement_status"] == "UNCONFIRMED"
    assert evidence.json()["audit_chain_valid"] is True
    assert evidence.json()["receiver_attestations"][0]["result"] == "CREDIT_ATTESTED"
    replay=ctx.client.post(endpoint,json={"claim":claim,"signature_b64":sig})
    assert replay.status_code==409
    events=ctx.client.get(f"/control/v1/receivers/attestations/{iid}",headers=headers)
    assert events.status_code==200 and len(events.json())==1
    assert events.json()[0]["settlement_confirmed"] is False
    db=ctx.Session()
    try:
        assert all(t.state != "PAID" for t in db.query(models.ProviderTransaction).all())
    finally:db.close()


def test_receiver_cross_tenant_cannot_read_registry(paari_client,monkeypatch):
    ctx=paari_client;headers,receiver_id,_=_create(ctx,monkeypatch)
    changed=dict(headers,**{"X-Paari-Org":"different"})
    assert ctx.client.get("/control/v1/receivers/institutions",headers=changed).status_code==401
    assert ctx.client.get("/control/v1/receivers/beneficiaries",headers=changed).status_code==401
    assert ctx.client.get("/control/v1/receivers/institutions",headers={"X-Paari-Org":"default"}).status_code==401


def test_receiver_idempotent_replay_cannot_swap_beneficiary(paari_client,monkeypatch):
    ctx=paari_client;headers,receiver_id,_=_create(ctx,monkeypatch)
    _approve(ctx,receiver_id)
    ben=_beneficiary(ctx,monkeypatch,headers,receiver_id)
    monkeypatch.setenv("PAARI_RECEIVER_ENFORCEMENT","1")
    suffix=uuid.uuid4().hex
    r=_intent(ctx,ben,suffix)
    assert r.json()["decision"]=="allow"
    changed=_intent(ctx,"different-beneficiary",suffix)
    assert changed.status_code==409
