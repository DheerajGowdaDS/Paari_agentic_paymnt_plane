"""Real HTTP + Alembic-backed v3.6 onboarding / governance regression tests."""
import uuid
from datetime import datetime, timezone
from app import crypto_utils, security as base_security
from app.v36 import models as vm
from app.models import ParentAuthority, UserPaymentMandate, PaymentIntent
from app.security import encode_request_proof

SECRETS = {
    'PAARI_V36_KEY_ENCRYPTION_SECRET':'v36-key-encryption-only-local-test-key-1234',
    'PAARI_V36_PII_HMAC_SECRET':'v36-sensitive-identity-hmac-test-only-9876',
    'PAARI_V36_AUTH_SECRET':'v36-authentication-session-test-key-123456',
}

def secrets_setup(monkeypatch):
    for key,value in SECRETS.items(): monkeypatch.setenv(key,value)


def parent_data(**kw):
    return {
        'parent_type':'person','name':'Ravi Kumar','identifier':'ABCDE1234F',
        'representative_name':'Ravi Kumar','representative_email':'ravi@local.invalid',
        'representative_phone':'9999999999','password':'correct-horse-battery-staple',
        'accept_terms':True,'accept_privacy':True,'accept_agent_security':True,**kw}


def approve(c, parent_id):
    return c.post(f'/v36/admin/parents/{parent_id}/review', headers={'X-Admin-Api-Key':base_security._ADMIN_API_KEY}, json={
       'approve':True,'identity_checked':True,'contact_checked':True,
       'representative_authority_checked':True,'reviewer_note':'Reviewed local demo registration data'})


def provider_register(c):
    r=c.post('/v36/providers/register',json={
      'legal_name':'Test Institution','registration_number':'REG12345',
      'contact_email':'bank@local.invalid','representative_name':'A. Officer',
      'payment_rail':'razorpay_simulator','currencies':['INR'],
      'accept_terms':True,'accept_privacy':True,'accept_provider_participation':True})
    assert r.status_code==201,r.text
    return r.json()['provider_id']


def post_payment(c, agent_id, session_token, private, provider_id, suffix, amount=1200):
    request={
       'session_token':session_token,'agent_id':agent_id,
       'transaction_id':'TXN-'+suffix,'idempotency_key':'idem-'+suffix,
       'merchant':'ApprovedSupplier','amount_minor_units':amount,'currency':'INR',
       'action':'make_payment','purpose':'Pay supplier invoice',
       'provider_id':provider_id}
    proof=encode_request_proof(private,method='POST',path='/payments/intent',access_token=session_token,agent_id=agent_id,jti=str(uuid.uuid4()))
    return c.post('/payments/intent',json=request,headers={'X-Paari-Proof':proof})


def test_parent_registration_manual_approval_login(paari_client, monkeypatch):
    secrets_setup(monkeypatch)
    c=paari_client.client
    assert c.post('/v36/parents/register',json=parent_data(accept_privacy=False)).status_code==422
    assert c.post('/v36/parents/register',json=parent_data(identifier='BADPAN')).status_code==422
    r=c.post('/v36/parents/register',json=parent_data())
    assert r.status_code==201,r.text
    pid=r.json()['parent_id']
    assert c.post('/v36/parents/login',json={'parent_id':pid,'password':parent_data()['password']}).status_code==403
    assert c.post(f'/parents/{pid}/approve',headers={'X-Admin-Api-Key':base_security._ADMIN_API_KEY}).status_code==409
    assert approve(c,pid).status_code==200
    login=c.post('/v36/parents/login',json={'parent_id':pid,'password':parent_data()['password']})
    assert login.status_code==200,login.text
    with paari_client.Session() as db:
        parent=db.query(ParentAuthority).filter_by(parent_id=pid).one()
        acc=db.query(vm.ParentAccount).filter_by(parent_pk=parent.id).one()
        assert acc.identifier_hmac and acc.identifier_last4=='234F'
        assert 'ABCDE1234F' not in str(acc.__dict__)
        assert db.query(vm.PolicyAcceptance).filter_by(subject_id=pid).count()==3


def test_full_v36_onboarding_signed_mandate_provider_policy(paari_client, monkeypatch):
    secrets_setup(monkeypatch)
    monkeypatch.setenv('RAZORPAY_API_BASE','http://127.0.0.1:9876')
    c=paari_client.client
    p=c.post('/v36/parents/register',json=parent_data());assert p.status_code==201,p.text
    pid=p.json()['parent_id'];assert approve(c,pid).status_code==200
    login=c.post('/v36/parents/login',json={'parent_id':pid,'password':parent_data()['password']});assert login.status_code==200,login.text
    hdr={'Authorization':'Bearer '+login.json()['access_token']}
    private,public=crypto_utils.generate_agent_keypair()
    agent=c.post('/v36/agents/register',headers=hdr,json={
        'basics':{'name':'PurchaseBot','agent_type':'shopping_assistant','purpose':'Buy approved supplies'},
        'agent_public_key_pem':public,
        'delegation':{'capabilities':['make_payment'],'limit_minor_units':10000,'currency':'INR','valid_days':10},
        'escalation_contact':{'name':'Ravi Kumar','email':'ravi@local.invalid','phone':'9999999999'},
        'accept_agent_security':True})
    assert agent.status_code==201,agent.text
    agent_id=agent.json()['agent_card']['agent_id']
    assert agent.json()['agent_card']['card_signature_b64']
    mandate=c.post('/v36/mandates/create',headers=hdr,json={
        'agent_id':agent_id,'max_per_transaction':5000,'max_daily_amount':10000,
        'currency':'INR','allowed_merchants':['ApprovedSupplier'],
        'confirm_payment_authority':True,'valid_days':5})
    assert mandate.status_code==201,mandate.text
    with paari_client.Session() as db:
        m=db.query(UserPaymentMandate).filter_by(mandate_id=mandate.json()['mandate_id']).one()
        from app.mandate_signing import verify_mandate_signature
        assert verify_mandate_signature(m).signature_valid
    provider_id=provider_register(c)
    provider_review=c.post(f'/v36/admin/providers/{provider_id}/review',headers={'X-Admin-Api-Key':base_security._ADMIN_API_KEY},json={
       'approve':True,'identity_checked':True,'contact_checked':True,
       'representative_authority_checked':True,'reviewer_note':'Local provider reviewed'})
    assert provider_review.status_code==200,provider_review.text
    r=c.post(f'/v36/admin/providers/{provider_id}/requirements',headers={'X-Admin-Api-Key':base_security._ADMIN_API_KEY},json={
      'required_context_fields':['merchant','purpose','parent_id','agent_id'],
      'max_amount_minor_units':4000,'required_currency':'INR'})
    assert r.status_code==201,r.text
    nonce=c.post('/auth/challenge',json={'agent_id':agent_id}).json()['nonce']
    signed=crypto_utils.sign_with_private_key(private,nonce)
    auth=c.post('/auth/verify',json={'agent_id':agent_id,'nonce':nonce,'signature_b64':signed,'credential_jwt':agent.json()['credential_jwt']})
    assert auth.status_code==200,auth.text
    session=auth.json()['session_token']
    bad=post_payment(c,agent_id,session,private,provider_id,'too-large',amount=4800)
    assert bad.status_code==200,bad.text
    assert bad.json()['decision']=='deny'
    assert any('Provider' in x for x in bad.json()['reasons'])
    missing=post_payment(c,agent_id,session,private,None,'no-provider')
    assert missing.status_code==200,missing.text
    assert missing.json()['decision']=='deny'
    ok=post_payment(c,agent_id,session,private,provider_id,'approved')
    assert ok.status_code==200,ok.text
    assert ok.json()['decision'] in ('allow','review'),ok.json()
    with paari_client.Session() as db:
        recorded=db.query(PaymentIntent).filter_by(transaction_id='TXN-approved').one()
        assert recorded.v36_provider_id==provider_id
        assert recorded.v36_provider_policy_version==1
    new_rules=c.post(f'/v36/admin/providers/{provider_id}/requirements',headers={'X-Admin-Api-Key':base_security._ADMIN_API_KEY},json={
      'required_context_fields':['merchant','purpose','parent_id'],
      'max_amount_minor_units':1000,'required_currency':'INR'})
    assert new_rules.status_code==201,new_rules.text
    if ok.json().get('authorization'):
        from app.v36.provider_policy import recheck_execution
        from fastapi import HTTPException
        with paari_client.Session() as db:
            recorded=db.query(PaymentIntent).filter_by(transaction_id='TXN-approved').one()
            import pytest
            with pytest.raises(HTTPException): recheck_execution(db,recorded)


def test_organization_and_parent_revocation(paari_client, monkeypatch):
    secrets_setup(monkeypatch)
    c=paari_client.client
    r=c.post('/v36/parents/register',json={
       'parent_type':'organization','name':'Example Consulting Limited',
       'identifier':'29ABCDE1234F1Z5','representative_name':'Authorized Contact',
       'representative_email':'contact@example.invalid','representative_phone':'9000000000',
       'password':'organization-sandbox-password-1234',
       'accept_terms':True,'accept_privacy':True,'accept_agent_security':True})
    assert r.status_code==201,r.text
    ref=r.json()['registration_reference']
    assert c.get(f'/v36/parents/status/{ref}').json()['status']=='pending_verification'
    pid=r.json()['parent_id']
    assert approve(c,pid).status_code==200
    assert c.get(f'/v36/parents/status/{ref}').json()['status']=='active'
    tok=c.post('/v36/parents/login',json={'parent_id':pid,'password':'organization-sandbox-password-1234'}).json()['access_token']
    _,public=crypto_utils.generate_agent_keypair()
    ar=c.post('/v36/agents/register',headers={'Authorization':'Bearer '+tok},json={
       'basics':{'name':'Accountant Bot','agent_type':'treasury','purpose':'Supplier settlements'},
       'agent_public_key_pem':public,
       'delegation':{'capabilities':['make_payment'],'limit_minor_units':20000,'currency':'INR'},
       'escalation_contact':{'name':'Authorized Contact','email':'contact@example.invalid','phone':'9000000000'},
       'accept_agent_security':True})
    assert ar.status_code==201,ar.text
    aid=ar.json()['agent_card']['agent_id']
    mandate=c.post('/v36/mandates/create',headers={'Authorization':'Bearer '+tok},json={
       'agent_id':aid,'max_per_transaction':20000,'max_daily_amount':20000,'currency':'INR',
       'allowed_merchants':['Supplier'], 'confirm_payment_authority':True})
    assert mandate.status_code==201,mandate.text
    mid=mandate.json()['mandate_id']
    assert c.post(f'/v36/mandates/{mid}/revoke',headers={'Authorization':'Bearer '+tok}).json()['status']=='revoked'
    assert c.post(f'/v36/agents/{aid}/revoke',headers={'Authorization':'Bearer '+tok}).json()['status']=='revoked'
    with paari_client.Session() as db:
        from app.models import Agent, Credential, MandateStatus
        assert db.query(Agent).filter_by(agent_id=aid).one().status.value=='revoked'
        assert db.query(UserPaymentMandate).filter_by(mandate_id=mid).one().status == MandateStatus.REVOKED
        assert db.query(Credential).filter_by(agent_pk=db.query(Agent).filter_by(agent_id=aid).one().id,revoked=False).count()==0
