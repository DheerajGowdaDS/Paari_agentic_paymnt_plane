"""V3.7 real FastAPI requests, Alembic-backed data and replay protection.

All values are fictitious; nothing contacts a live payment institution.
"""
import json
import uuid
from datetime import datetime, timezone
import pytest
from fastapi import HTTPException
from app import crypto_utils, security as platform_security, models as core
from app.security import encode_request_proof
from app.v36 import models as vm
from app.v37 import risk, models as em
from app.portability import build_agent_portability_package


def parent_setup(c, monkeypatch, name='Treasury Parent', identifier='ABCDE1234F'):
    from tests.test_v36_onboarding import parent_data, approve, secrets_setup
    secrets_setup(monkeypatch)
    r=c.post('/v36/parents/register',json=parent_data(name=name,identifier=identifier))
    assert r.status_code==201,r.text
    pid=r.json()['parent_id']
    assert approve(c,pid).status_code==200
    login=c.post('/v36/parents/login',json={'parent_id':pid,'password':parent_data()['password']})
    assert login.status_code==200,login.text
    return pid,{'Authorization':'Bearer '+login.json()['access_token']}


def agent_setup(c, headers, name='SpendBot'):
    private,public=crypto_utils.generate_agent_keypair()
    result=c.post('/v36/agents/register',headers=headers,json={
        'basics':{'name':name,'agent_type':'treasury','purpose':'Treasury approved supplier payments'},
        'agent_public_key_pem':public,
        'delegation':{'capabilities':['make_payment'],'limit_minor_units':5000,'currency':'INR','valid_days':10},
        'escalation_contact':{'name':'Owner','email':'owner@example.invalid','phone':'9876543210'},
        'accept_agent_security':True})
    assert result.status_code==201,result.text
    return result.json()['agent_card']['agent_id'],private,result.json()


def agent_session(c,agent_id,private,registered):
    nonce=c.post('/auth/challenge',json={'agent_id':agent_id}).json()['nonce']
    signed=crypto_utils.sign_with_private_key(private,nonce)
    a=c.post('/auth/verify',json={'agent_id':agent_id,'nonce':nonce,
          'signature_b64':signed,'credential_jwt':registered['credential_jwt']})
    assert a.status_code==200,a.text
    return a.json()['session_token']


def provider_setup(c):
    from tests.test_v36_onboarding import provider_register
    pid=provider_register(c)
    admin={'X-Admin-Api-Key':platform_security._ADMIN_API_KEY}
    assert c.post(f'/v36/admin/providers/{pid}/review',headers=admin,json={
       'approve':True,'identity_checked':True,'contact_checked':True,
       'representative_authority_checked':True,'reviewer_note':'Approved for test only'}).status_code==200
    r=c.post(f'/v36/admin/providers/{pid}/requirements',headers=admin,json={
       'required_context_fields':['merchant','purpose','agent_id','parent_id'],
       'max_amount_minor_units':5000,'required_currency':'INR'})
    assert r.status_code==201,r.text
    return pid


def mandate_setup(c,auth,agent_id):
    r=c.post('/v36/mandates/create',headers=auth,json={
         'agent_id':agent_id,'max_per_transaction':5000,'max_daily_amount':20000,
         'currency':'INR','allowed_merchants':['ApprovedSupplier'],
         'confirm_payment_authority':True,'valid_days':10})
    assert r.status_code==201,r.text


def pay(c,agent_id,session,private,provider_id,amount,nonce):
    req={'session_token':session,'agent_id':agent_id,'transaction_id':'TXN-'+nonce,
         'idempotency_key':'idem-'+nonce,'merchant':'ApprovedSupplier',
         'amount_minor_units':amount,'currency':'INR','action':'make_payment',
         'purpose':'Purchase approved materials','provider_id':provider_id}
    proof=encode_request_proof(private,method='POST',path='/payments/intent',access_token=session,
                               agent_id=agent_id,jti=str(uuid.uuid4()))
    return c.post('/payments/intent',json=req,headers={'X-Paari-Proof':proof})


def test_treasury_shared_budget_and_per_agent_limit(paari_client,monkeypatch):
    monkeypatch.setenv('RAZORPAY_API_BASE','http://127.0.0.1:9876')
    c=paari_client.client
    monkeypatch.setenv('PAARI_V37_DATA_ENCRYPTION_SECRET','v37-data-encryption-isolated-test-123456')
    pid,auth=parent_setup(c,monkeypatch)
    a1,k1,r1=agent_setup(c,auth,'Buyer 1')
    a2,k2,r2=agent_setup(c,auth,'Buyer 2')
    mandate_setup(c,auth,a1);mandate_setup(c,auth,a2)
    provider=provider_setup(c)
    p=c.put('/v37/enterprise/treasury/policy',headers=auth,json={'currency':'INR','daily_limit_minor_units':2000})
    assert p.status_code==200,p.text
    assert c.put(f'/v37/enterprise/treasury/agents/{a1}/risk',headers=auth,
                 json={'daily_limit_minor_units':1500,'suspended':False}).status_code==200
    s1=agent_session(c,a1,k1,r1)
    s2=agent_session(c,a2,k2,r2)
    allowed=pay(c,a1,s1,k1,provider,1200,'one')
    assert allowed.status_code==200,allowed.text
    assert allowed.json()['decision'] in ('allow','review'),allowed.text
    denied=pay(c,a2,s2,k2,provider,1100,'two')
    assert denied.status_code==200 and denied.json()['decision']=='deny',denied.text
    assert any('Shared treasury' in x for x in denied.json()['reasons'])
    again=pay(c,a1,s1,k1,provider,900,'three')
    assert again.json()['decision']=='deny'
    assert any('Shared treasury' in x or 'Agent daily' in x for x in again.json()['reasons'])
    stats=c.get('/v37/enterprise/treasury/exposure',headers=auth)
    assert stats.status_code==200 and stats.json()['agent_count']==2
    assert stats.json()['reserved_total_minor_units']==1200
    assert stats.json()['treasury_policy']['daily_limit_minor_units']==2000


def test_emergency_freeze_blocks_pending_and_agent_suspension(paari_client,monkeypatch):
    monkeypatch.setenv('RAZORPAY_API_BASE','http://127.0.0.1:9876')
    c=paari_client.client
    monkeypatch.setenv('PAARI_V37_DATA_ENCRYPTION_SECRET','v37-data-encryption-isolated-test-123456')
    pid,auth=parent_setup(c,monkeypatch)
    aid,private,registered=agent_setup(c,auth)
    mandate_setup(c,auth,aid)
    provider=provider_setup(c)
    assert c.put('/v37/enterprise/treasury/policy',headers=auth,json={
             'currency':'INR','daily_limit_minor_units':5000}).status_code==200
    token=agent_session(c,aid,private,registered)
    approved=pay(c,aid,token,private,provider,1000,'pre-freeze')
    assert approved.json()['decision'] in ('allow','review')
    intent_id=approved.json()['intent_id']
    assert c.post('/v37/enterprise/treasury/freeze',headers=auth).json()['state']=='FROZEN'
    denied=pay(c,aid,token,private,provider,1000,'post-freeze')
    assert denied.json()['decision']=='deny'
    with paari_client.Session() as db:
        intent=db.query(core.PaymentIntent).filter_by(intent_id=intent_id).one()
        with pytest.raises(HTTPException):risk.enforce_execution(db,intent)
    assert c.put('/v37/enterprise/treasury/policy',headers=auth,json={
             'currency':'INR','daily_limit_minor_units':100000}).status_code==409
    assert c.post(f'/v37/enterprise/admin/treasury/{pid}/unfreeze',headers={
          'X-Admin-Api-Key':'bad'}).status_code in (401,403)
    ok=c.post(f'/v37/enterprise/admin/treasury/{pid}/unfreeze',headers={
          'X-Admin-Api-Key':platform_security._ADMIN_API_KEY})
    assert ok.status_code==200,ok.text
    assert c.put(f'/v37/enterprise/treasury/agents/{aid}/risk',headers=auth,json={
             'daily_limit_minor_units':3000,'suspended':True}).status_code==200
    denied=pay(c,aid,token,private,provider,1000,'suspended')
    assert denied.json()['decision']=='deny'
    assert 'Agent suspended' in denied.json()['reasons'][0]


def test_data_grant_minimization_signed_export_and_revocation(paari_client,monkeypatch):
    c=paari_client.client
    monkeypatch.setenv('PAARI_V37_DATA_ENCRYPTION_SECRET','v37-data-encryption-isolated-test-123456')
    pid,auth=parent_setup(c,monkeypatch)
    aid,private,registered=agent_setup(c,auth)
    bad=c.post('/v37/enterprise/data/datasets',headers=auth,json={
         'kind':'balances','records':[{'account_number':'11223344','balance_minor_units':12345}]})
    assert bad.status_code==422
    record=c.post('/v37/enterprise/data/datasets',headers=auth,json={
         'kind':'balances','records':[{'account_alias':'Treasury A','balance_minor_units':12345,'currency':'INR'}]})
    assert record.status_code==201,record.text
    ds=record.json()['dataset_id']
    grant=c.post('/v37/enterprise/data/grants',headers=auth,json={
          'dataset_id':ds,'agent_id':aid,'allowed_fields':['balance_minor_units'],
          'purpose':'Daily exposure report','destination':'Treasury-B','valid_hours':3})
    assert grant.status_code==201,grant.text
    gid=grant.json()['grant_id']
    session=agent_session(c,aid,private,registered)
    no_proof=c.post('/v37/enterprise/data/export',json={
          'grant_id':gid,'purpose':'Daily exposure report','destination':'Treasury-B',
          'session_token':session})
    assert no_proof.status_code==401
    def export(destination='Treasury-B'):
        proof=encode_request_proof(private,method='POST',path='/v37/enterprise/data/export',
              access_token=session,agent_id=aid,jti=str(uuid.uuid4()))
        return c.post('/v37/enterprise/data/export',headers={'X-Paari-Proof':proof},json={
              'grant_id':gid,'purpose':'Daily exposure report','destination':destination,
              'session_token':session})
    assert export('Unapproved-Destination').status_code==403
    result=export()
    assert result.status_code==200,result.text
    item=result.json()
    assert item['records']==[{'balance_minor_units':12345}]
    assert 'account_alias' not in str(item['records'])
    signature=item.pop('issuer_signature_b64')
    issuer=item.pop('issuer_public_key_pem')
    # Export signature covers the issuer key field itself.
    item['issuer_public_key_pem']=issuer
    assert crypto_utils.verify_signature(issuer,crypto_utils.canonical_json(item),signature)
    assert c.post(f'/v37/enterprise/data/grants/{gid}/revoke',headers=auth).status_code==200
    assert export().status_code==403
    with paari_client.Session() as db:
        assert db.query(em.DataExportLog).count()==1
        assert db.query(core.AuditEvent).filter_by(kind='data_export_approved').count()==1


def test_agent_identity_portability_no_permission_transfer(paari_client,monkeypatch):
    c=paari_client.client
    monkeypatch.setenv('PAARI_V37_DATA_ENCRYPTION_SECRET','v37-data-encryption-isolated-test-123456')
    pid,auth=parent_setup(c,monkeypatch)
    aid,old_private,old_registered=agent_setup(c,auth,'Original TreasuryBot')
    from app.security import signing_backend_status,paari_public_key_pem
    signer=signing_backend_status()
    monkeypatch.setenv('PAARI_PORTABILITY_TRUSTED_ISSUERS_JSON',json.dumps({signer['key_id']:paari_public_key_pem()}))
    with paari_client.Session() as db:
        agent=db.query(core.Agent).filter_by(agent_id=aid).one()
        parent=db.query(core.ParentAuthority).filter_by(id=agent.parent_pk).one()
        delegation=db.query(core.DelegationRecord).filter_by(delegation_id=agent.delegation_id).one()
        cred=db.query(core.Credential).filter_by(agent_pk=agent.id,revoked=False).first()
        card_fields={
            'agent_id':agent.agent_id,'name':agent.name,'agent_type':agent.agent_type,
            'parent_id':parent.parent_id,'parent_name':parent.name,
            'identity_status':agent.status.value,'public_key_reference':agent.public_key_pem,
            'granted_capabilities':list(agent.granted_capabilities or []),
            'payment_limit_minor_units':int(agent.payment_limit_minor_units),'currency':agent.currency,
            'valid_until':agent.valid_until.isoformat() if agent.valid_until else None,
            'credential_id':cred.credential_id if cred else '', 'paari_endpoint':'/agents'}
        card={**card_fields,'card_signature_b64':platform_security.sign_agent_card(card_fields),
             'paari_public_key_pem':platform_security.paari_public_key_pem()}
        pkg=build_agent_portability_package(agent=agent,parent=parent,delegation_record=delegation,
                                             agent_card=card)
    broken=json.loads(json.dumps(pkg));broken['agent_card']['agent_id']='FAKE'
    assert c.post('/v37/enterprise/portability/stage',headers=auth,json={
         'package':broken,'confirm_identity_only':True}).status_code==422
    staged=c.post('/v37/enterprise/portability/stage',headers=auth,json={
         'package':pkg,'confirm_identity_only':True})
    assert staged.status_code==201,staged.text
    migration_id=staged.json()['migration_id']
    assert c.post('/v37/enterprise/portability/stage',headers=auth,json={
         'package':pkg,'confirm_identity_only':True}).status_code==409
    same=c.post(f'/v37/enterprise/portability/{migration_id}/activate',headers=auth,json={
         'destination_agent_id':aid,'acknowledge_new_delegation':True})
    assert same.status_code==403
    new_id,new_private,new_registered=agent_setup(c,auth,'New TreasuryBot')
    linked=c.post(f'/v37/enterprise/portability/{migration_id}/activate',headers=auth,json={
         'destination_agent_id':new_id,'acknowledge_new_delegation':True})
    assert linked.status_code==200,linked.text
    assert linked.json()['authority_transferred'] is False
    assert linked.json()['mandates_transferred'] is False
    assert c.post(f'/v37/enterprise/portability/{migration_id}/activate',headers=auth,json={
         'destination_agent_id':new_id,'acknowledge_new_delegation':True}).status_code==409
    with paari_client.Session() as db:
        assert db.query(core.UserPaymentMandate).filter_by(agent_id=new_id).count()==0


def test_parent_login_rate_limit_and_lockout(paari_client,monkeypatch):
    c=paari_client.client
    parent_id,_=parent_setup(c,monkeypatch)
    for i in range(5):
        r=c.post('/v36/parents/login',json={'parent_id':parent_id,'password':'incorrect-password'})
        assert r.status_code==401,r.text
    assert c.post('/v36/parents/login',json={
        'parent_id':parent_id,'password':'correct-horse-battery-staple'}).status_code==429
    with paari_client.Session() as db:
        parent=db.query(core.ParentAuthority).filter_by(parent_id=parent_id).one()
        acc=db.query(vm.ParentAccount).filter_by(parent_pk=parent.id).one()
        assert acc.failed_login_attempts==5 and acc.locked_until is not None


def test_agent_velocity_policy_enforced(paari_client,monkeypatch):
    monkeypatch.setenv('RAZORPAY_API_BASE','http://127.0.0.1:9876')
    c=paari_client.client
    monkeypatch.setenv('PAARI_V37_DATA_ENCRYPTION_SECRET','v37-data-encryption-isolated-test-123456')
    pid,auth=parent_setup(c,monkeypatch)
    aid,private,registered=agent_setup(c,auth)
    mandate_setup(c,auth,aid)
    provider=provider_setup(c)
    assert c.put('/v37/enterprise/treasury/policy',headers=auth,json={
             'currency':'INR','daily_limit_minor_units':5000}).status_code==200
    assert c.put(f'/v37/enterprise/treasury/agents/{aid}/risk',headers=auth,json={
             'daily_limit_minor_units':5000,'hourly_request_limit':1,'suspended':False}).status_code==200
    session=agent_session(c,aid,private,registered)
    first=pay(c,aid,session,private,provider,1000,'first')
    assert first.json()['decision'] in ('allow','review'),first.text
    second=pay(c,aid,session,private,provider,1000,'second')
    assert second.json()['decision']=='deny',second.text
    assert 'velocity' in second.json()['reasons'][0]


def test_data_purge_revokes_grants_and_wipes_ciphertext(paari_client,monkeypatch):
    monkeypatch.setenv('PAARI_V37_DATA_ENCRYPTION_SECRET','v37-data-encryption-isolated-test-123456')
    c=paari_client.client
    pid,auth=parent_setup(c,monkeypatch)
    aid,private,registered=agent_setup(c,auth)
    result=c.post('/v37/enterprise/data/datasets',headers=auth,json={
          'kind':'transactions','records':[{'transaction_id':'T001','amount_minor_units':800}]})
    assert result.status_code==201,result.text
    dataset_id=result.json()['dataset_id']
    grant=c.post('/v37/enterprise/data/grants',headers=auth,json={
          'dataset_id':dataset_id,'agent_id':aid,'allowed_fields':['amount_minor_units'],
          'purpose':'Portable expense report','destination':'Treasury-B','valid_hours':3})
    assert grant.status_code==201,grant.text
    wiped=c.delete(f'/v37/enterprise/data/datasets/{dataset_id}',headers=auth)
    assert wiped.status_code==200,wiped.text
    with paari_client.Session() as db:
        ds=db.query(em.DataSet).filter_by(dataset_id=dataset_id).one()
        assert ds.encrypted_content=='' and ds.deleted_at is not None
        gg=db.query(em.DataGrant).filter_by(grant_id=grant.json()['grant_id']).one()
        assert gg.revoked_at is not None


def test_encrypted_data_portability_uses_parent_pinned_destination_key(paari_client,monkeypatch):
    import base64
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    c=paari_client.client
    monkeypatch.setenv('PAARI_V37_DATA_ENCRYPTION_SECRET','v37-data-encryption-isolated-test-123456')
    monkeypatch.setenv('RAZORPAY_API_BASE','http://127.0.0.1:9876')
    pid,auth=parent_setup(c,monkeypatch)
    aid,private,registered=agent_setup(c,auth)
    recipient_private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    recipient_public=recipient_private.public_key().public_bytes(
        serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    ds=c.post('/v37/enterprise/data/datasets',headers=auth,json={
        'kind':'balances','records':[{'account_alias':'Main Treasury','balance_minor_units':92500,'currency':'INR'}]})
    assert ds.status_code==201,ds.text
    grant=c.post('/v37/enterprise/data/grants',headers=auth,json={
        'dataset_id':ds.json()['dataset_id'],'agent_id':aid,
        'allowed_fields':['balance_minor_units','currency'],'purpose':'Encrypted treasury data migration',
        'destination':'Treasury-Destination','valid_hours':3,
        'destination_public_key_pem':recipient_public})
    assert grant.status_code==201,grant.text
    assert grant.json()['encrypted_portability_enabled'] is True
    session=agent_session(c,aid,private,registered)
    proof=encode_request_proof(private,method='POST',path='/v37/enterprise/data/portability/export',
        access_token=session,agent_id=aid,jti=str(uuid.uuid4()))
    exported=c.post('/v37/enterprise/data/portability/export',headers={'X-Paari-Proof':proof},json={
        'grant_id':grant.json()['grant_id'],'purpose':'Encrypted treasury data migration',
        'destination':'Treasury-Destination','session_token':session})
    assert exported.status_code==200,exported.text
    envelope=exported.json()
    assert 'records' not in envelope and 'balance_minor_units' not in str(envelope)
    signed=dict(envelope)
    signature=signed.pop('issuer_signature_b64')
    issuer=signed['issuer_public_key_pem']
    assert crypto_utils.verify_signature(issuer,crypto_utils.canonical_json(signed),signature)
    def unb64(value): return base64.urlsafe_b64decode(value+'='*(-len(value)%4))
    cek=recipient_private.decrypt(unb64(envelope['encrypted_key_b64']),padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    plain=AESGCM(cek).decrypt(unb64(envelope['nonce_b64']),unb64(envelope['ciphertext_b64']),
        unb64(envelope['associated_data_b64']))
    decoded=json.loads(plain)
    assert decoded['records']==[{'balance_minor_units':92500,'currency':'INR'}]
    assert decoded['destination']=='Treasury-Destination'
    grants=c.get('/v37/enterprise/data/grants',headers=auth)
    assert grants.status_code==200 and grants.json()['items'][0]['encrypted_portability_enabled'] is True
    exports=c.get('/v37/enterprise/data/exports',headers=auth)
    assert exports.status_code==200 and exports.json()['items'][0]['export_id']==envelope['export_id']


def test_open_banking_and_stablecoin_route_previews_are_non_executing(paari_client,monkeypatch):
    monkeypatch.setenv('RAZORPAY_API_BASE','http://127.0.0.1:9876')
    c=paari_client.client
    pid,auth=parent_setup(c,monkeypatch)
    aid,private,registered=agent_setup(c,auth)
    mandate_setup(c,auth,aid)
    provider=provider_setup(c)
    token=agent_session(c,aid,private,registered)
    payment=pay(c,aid,token,private,provider,500,'rail-preview')
    assert payment.status_code==200 and payment.json()['decision']=='allow',payment.text
    intent_id=payment.json()['intent_id']

    capabilities=c.get('/v37/enterprise/rails/capabilities')
    assert capabilities.status_code==200
    assert capabilities.json()['execution_mode']=='SIMULATION_ONLY'
    assert capabilities.json()['live_submission_enabled'] is False

    open_banking=c.post('/v37/enterprise/rails/simulate',headers=auth,json={
        'intent_id':intent_id,'rail':'open_banking','sandbox_consent_reference':'sbx-consent-demo-001'})
    assert open_banking.status_code==201,open_banking.text
    assert open_banking.json()['status']=='OPEN_BANKING_ROUTE_PREVIEW_ONLY'
    assert open_banking.json()['authorization_consumed'] is False
    assert open_banking.json()['external_submission'] is False
    assert open_banking.json()['settlement_confirmed'] is False
    replay=c.post('/v37/enterprise/rails/simulate',headers=auth,json={
        'intent_id':intent_id,'rail':'open_banking','sandbox_consent_reference':'sbx-consent-demo-001'})
    assert replay.status_code==201 and replay.json()['idempotent_replay'] is True

    stablecoin=c.post('/v37/enterprise/rails/simulate',headers=auth,json={
        'intent_id':intent_id,'rail':'stablecoin','network':'local-evm-testnet','chain_id':31337,
        'asset_symbol':'USDC','destination_wallet':'0x'+'1'*40})
    assert stablecoin.status_code==201,stablecoin.text
    assert stablecoin.json()['status']=='STABLECOIN_TEST_NETWORK_ROUTE_PREVIEW_ONLY'
    assert stablecoin.json()['safe_context']['transaction_broadcast'] is False
    assert stablecoin.json()['safe_context']['chain_finality_confirmed'] is False

    with paari_client.Session() as db:
        bound=db.query(core.BoundedAuthorization).filter_by(intent_id=intent_id).one()
        txn=db.query(core.ProviderTransaction).filter_by(intent_id=intent_id).one()
        assert bound.usage_count==0
        assert txn.state=='AUTHORIZED'
    history=c.get('/v37/enterprise/rails/simulations',headers=auth)
    assert history.status_code==200 and len(history.json()['items'])==2


def test_parent_scoped_data_and_rail_records_are_tenant_isolated(paari_client,monkeypatch):
    c=paari_client.client
    monkeypatch.setenv('PAARI_V37_DATA_ENCRYPTION_SECRET','v37-data-encryption-isolated-test-123456')
    _,owner_auth=parent_setup(c,monkeypatch,name='Owner Treasury',identifier='ABCDE1234F')
    created=c.post('/v37/enterprise/data/datasets',headers=owner_auth,json={
        'kind':'balances','records':[{'account_alias':'OWNER','balance_minor_units':1000,'currency':'INR'}]})
    assert created.status_code==201,created.text
    dataset_id=created.json()['dataset_id']
    owner_list=c.get('/v37/enterprise/data/datasets',headers=owner_auth)
    assert owner_list.status_code==200
    assert [x['dataset_id'] for x in owner_list.json()['items']]==[dataset_id]

    _,other_auth=parent_setup(c,monkeypatch,name='Other Treasury',identifier='BCDEF2345G')
    other_list=c.get('/v37/enterprise/data/datasets',headers=other_auth)
    assert other_list.status_code==200 and other_list.json()['items']==[]
    assert c.delete(f'/v37/enterprise/data/datasets/{dataset_id}',headers=other_auth).status_code==404
    assert c.get('/v37/enterprise/data/grants',headers=other_auth).json()['items']==[]
    assert c.get('/v37/enterprise/data/exports',headers=other_auth).json()['items']==[]
    assert c.get('/v37/enterprise/rails/simulations',headers=other_auth).json()['items']==[]
