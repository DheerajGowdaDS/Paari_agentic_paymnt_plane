"""Paari v3.5: every new cross-institution agreement is actually signed.

No fabricated settlement. These checks exercise the policy enforcement point
on the real FastAPI intent and authorization routes and the migrated schema.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import uuid

from app import crypto_utils, models, security
from app.federation.policy import policy_digest
from app.federation.contracts import AgreementClaims
from tests.test_v34_receivers import _create, _approve, _beneficiary
from tests.test_v2_governance import _signed_mandate_post


def _mandate(ctx):
    payload = {"user_id":"user-42", "agent_id":ctx.agent_id,
               "max_per_transaction":200000,"max_daily_amount":500000,"currency":"INR",
               "expires_at":(datetime.now(timezone.utc)+timedelta(days=5)).isoformat(),
               "approval_reference":"federation-mandate-user-42"}
    r=ctx.client.post('/v1/mandates',headers={"X-Admin-Api-Key":security._ADMIN_API_KEY},json=payload)
    assert r.status_code==200,r.text
    return r.json()


def _request(ctx, ben, suffix):
    x=uuid.uuid4().hex[:8]
    r=ctx.client.post('/payments/intent',json={"session_token":ctx.session_token,
        "transaction_id":f"fed-txn-{suffix}-{x}","idempotency_key":f"fed-idem-{suffix}-{x}",
        "merchant":"TestMerchant","beneficiary_id":ben,"amount_minor_units":1000,
        "currency":"INR","action":"make_payment","purpose":"approved vendor purchase"})
    assert r.status_code==200,r.text
    return r.json()


def _enroll(ctx,headers,subject_type,subject_id):
    private,public=crypto_utils.generate_agent_keypair()
    r=ctx.client.post('/control/v1/federation/signers',headers=headers,json={
        'subject_type':subject_type,'subject_id':subject_id,'public_key_pem':public})
    assert r.status_code==201,r.text
    return private, r.json()


def _sign(ctx,headers,ben,receiver_id,private,role,subject_id):
    db=ctx.Session()
    policy_hash=policy_digest(db,'default')
    db.close()
    ts=datetime.now(timezone.utc)
    claims={"agreement_id":str(uuid.uuid4()),"org_id":"default","agent_id":ctx.agent_id,
            "beneficiary_id":ben,"subject_type":role,"subject_id":subject_id,
            "purpose":"approved vendor purchase", "max_amount_minor_units":10000,
            "currency":"INR", "policy_digest":policy_hash,
            "document_digest":hashlib.sha256(f'{role}-policy-v1'.encode()).hexdigest(),
            "issued_at":ts.isoformat(),"expires_at":(ts+timedelta(days=3)).isoformat()}
    sig=crypto_utils.sign_with_private_key(private,crypto_utils.canonical_json(AgreementClaims.model_validate(claims).model_dump(mode="json")))
    r=ctx.client.post('/control/v1/federation/agreements',headers=headers,
                      json={"claims":claims,"signature_b64":sig})
    assert r.status_code==201,r.text
    return r.json()['agreement_id']


def _setup(ctx,monkeypatch):
    headers,recv,recv_private=_create(ctx,monkeypatch)
    _approve(ctx,recv)
    ben=_beneficiary(ctx,monkeypatch,headers,recv)
    sender_private,_=_enroll(ctx,headers,'SENDER_ORG','default')
    user_private,user_meta=_enroll(ctx,headers,'USER','user-42')
    db=ctx.Session()
    user_public=db.query(models.FederationSigner).filter_by(org_id='default',subject_type='USER',subject_id='user-42').one().public_key_pem
    db.close()
    _signed_mandate_post(ctx,user_private,user_public)
    return headers,recv,ben,recv_private,sender_private,user_private


def test_federation_missing_consent_denies_and_context_is_signed(paari_client,monkeypatch):
    ctx=paari_client
    headers,recv,ben,recv_private,sender_private,user_private=_setup(ctx,monkeypatch)
    monkeypatch.setenv('PAARI_FEDERATION_ENFORCEMENT','1')
    r=_request(ctx,ben,'missing')
    assert r['decision']=='deny' and r['authorization'] is None
    assert 'SENDER_ORG' in str(r['reasons'])
    proof=ctx.client.get(f"/control/v1/federation/contexts/{r['intent_id']}",headers=headers)
    assert proof.status_code==200,proof.text
    assert proof.json()['signature_valid'] is True
    assert proof.json()['payload']['execution_authority'] is False
    assert proof.json()['payload']['beneficiary_id']==ben


def test_signed_role_intersection_and_revocation_block_consumption(paari_client,monkeypatch):
    ctx=paari_client
    headers,recv,ben,recv_private,sender_private,user_private=_setup(ctx,monkeypatch)
    monkeypatch.setenv('PAARI_FEDERATION_ENFORCEMENT','1')
    # Exact three distinct signatures: org operator, signed user and receiver.
    s=_sign(ctx,headers,ben,recv,sender_private,'SENDER_ORG','default')
    u=_sign(ctx,headers,ben,recv,user_private,'USER','user-42')
    rr=_sign(ctx,headers,ben,recv,recv_private,'RECEIVER',recv)
    allowed=_request(ctx,ben,'signed')
    assert allowed['decision']=='allow',allowed
    auth=allowed['authorization']['authorization_id']
    # Before execute, the user revokes its signed consent: no provider call.
    revoked=ctx.client.post(f'/control/v1/federation/agreements/{u}/revoke',headers=headers,
               json={"reason":"User withdrew permission for this payment"})
    assert revoked.status_code==200,revoked.text
    consumed=ctx.client.post(f'/payments/authorizations/{auth}/consume',json={"session_token":ctx.session_token})
    assert consumed.status_code==403,consumed.text
    assert 'Federation revalidation' in str(consumed.json())
    db=ctx.Session()
    try:
        row=db.query(models.BoundedAuthorization).filter_by(authorization_id=auth).one()
        assert row.usage_count==0
    finally: db.close()


def test_forged_receiver_agreement_refused(paari_client,monkeypatch):
    ctx=paari_client
    headers,recv,ben,recv_private,sender_private,user_private=_setup(ctx,monkeypatch)
    # Attempt to sign the receiving bank's policy using an unrelated user key.
    now=datetime.now(timezone.utc)
    db=ctx.Session(); pd=policy_digest(db,'default');db.close()
    claims={"agreement_id":str(uuid.uuid4()),"org_id":"default","agent_id":ctx.agent_id,
            "beneficiary_id":ben,"subject_type":"RECEIVER","subject_id":recv,
            "purpose":"approved vendor purchase", "max_amount_minor_units":10000,"currency":"INR",
            "policy_digest":pd,"document_digest":'b'*64,
            "issued_at":now.isoformat(),"expires_at":(now+timedelta(days=2)).isoformat()}
    fake=crypto_utils.sign_with_private_key(user_private,crypto_utils.canonical_json(AgreementClaims.model_validate(claims).model_dump(mode="json")))
    r=ctx.client.post('/control/v1/federation/agreements',headers=headers,json={"claims":claims,"signature_b64":fake})
    assert r.status_code==403
    assert 'signature' in str(r.json()).lower()


def test_policy_drift_denies_even_valid_signed_receipts(paari_client,monkeypatch):
    ctx=paari_client
    headers,recv,ben,recv_private,sender_private,user_private=_setup(ctx,monkeypatch)
    monkeypatch.setenv('PAARI_FEDERATION_ENFORCEMENT','1')
    _sign(ctx,headers,ben,recv,sender_private,'SENDER_ORG','default')
    _sign(ctx,headers,ben,recv,user_private,'USER','user-42')
    _sign(ctx,headers,ben,recv,recv_private,'RECEIVER',recv)
    db=ctx.Session()
    try:
        db.add(models.PolicyBundle(org_id='default',policy_name='additional-security',version='1',
                status='ACTIVE',rules={'require_review':True},created_by='test-admin'))
        db.commit()
    finally:db.close()
    denied=_request(ctx,ben,'drift')
    assert denied['decision']=='deny' and 'SENDER_ORG' in str(denied['reasons'])


def test_tampered_signed_payment_context_fails_before_execution(paari_client,monkeypatch):
    ctx=paari_client
    headers,recv,ben,recv_private,sender_private,user_private=_setup(ctx,monkeypatch)
    monkeypatch.setenv('PAARI_FEDERATION_ENFORCEMENT','1')
    _sign(ctx,headers,ben,recv,sender_private,'SENDER_ORG','default')
    _sign(ctx,headers,ben,recv,user_private,'USER','user-42')
    _sign(ctx,headers,ben,recv,recv_private,'RECEIVER',recv)
    allowed=_request(ctx,ben,'tamper')
    assert allowed['decision']=='allow',allowed
    auth=allowed['authorization']['authorization_id']
    db=ctx.Session()
    try:
        record=db.query(models.PaymentContextEnvelope).filter_by(intent_id=allowed['intent_id']).one()
        changed=dict(record.payload)
        changed['amount_minor_units']=1
        record.payload=changed
        db.commit()
    finally:db.close()
    consumed=ctx.client.post(f'/payments/authorizations/{auth}/consume',json={'session_token':ctx.session_token})
    assert consumed.status_code==403,consumed.text
    assert 'context' in str(consumed.json()).lower()
    check=ctx.client.get(f"/control/v1/federation/contexts/{allowed['intent_id']}",headers=headers)
    assert check.status_code==200 and check.json()['signature_valid'] is False
    db=ctx.Session()
    try:
        assert db.query(models.BoundedAuthorization).filter_by(authorization_id=auth).one().usage_count==0
    finally:db.close()


def test_agreements_tenant_isolated(paari_client,monkeypatch):
    ctx=paari_client
    headers,recv,ben,recv_private,sender_private,user_private=_setup(ctx,monkeypatch)
    _sign(ctx,headers,ben,recv,sender_private,'SENDER_ORG','default')
    db=ctx.Session()
    try:
        db.add(models.Organization(org_id='other-institution',name='Separate Institution'))
        db.commit()
    finally:db.close()
    key=ctx.client.post('/control/v1/admin-keys',headers={"X-Admin-Api-Key":"v34-root-testing-only"},
                        json={"org_id":"other-institution","scopes":["control:read","control:write"],
                              "expires_at":(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()})
    assert key.status_code==201,key.text
    other={"X-Paari-Control-Key":key.json()['secret'],"X-Paari-Org":"other-institution"}
    r=ctx.client.get('/control/v1/federation/agreements',headers=other)
    assert r.status_code==200 and r.json()==[]
