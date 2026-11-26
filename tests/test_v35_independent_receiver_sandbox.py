"""Separate receiver storage and signing authority; no fake settlement claims."""
import hashlib
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app import crypto_utils
from scripts.receiver_partner_sandbox import create_app


def _setup(tmp_path):
    recv_priv,recv_pub=crypto_utils.generate_agent_keypair()
    issuer_priv,issuer_pub=crypto_utils.generate_agent_keypair()
    api=create_app(receiver_id='recv-a',private_key_pem=recv_priv,
                   paari_public_key_pem=issuer_pub,
                   database_path=str(tmp_path/'receiver.sqlite3'),
                   allowed_beneficiaries={'approved-beneficiary'})
    return TestClient(api), issuer_priv, recv_pub


def _context(issuer_key, **changes):
    p={'type':'paari.payment-context.v1','intent_id':'int-local-123',
       'transaction_id':'txn-local-123', 'org_id':'sender-bank-a',
       'agent_id':'agent-543','beneficiary_id':'approved-beneficiary',
       'amount_minor_units':5000,'currency':'INR','decision':'allow',
       'execution_authority':False,'issued_at':datetime.now(timezone.utc).isoformat(),**changes}
    j=crypto_utils.canonical_json(p)
    return {'payload':p,'signature_b64':crypto_utils.sign_with_private_key(issuer_key,j),
            'payload_digest':hashlib.sha256(j.encode()).hexdigest()}


def test_receiver_acknowledgement_is_signed_and_restart_idempotent(tmp_path):
    client,issuer_key,pub=_setup(tmp_path)
    body={'receiver_id':'recv-a','provider_reference':'TEST_PROVIDER_REF',
          'context':_context(issuer_key)}
    r=client.post('/v1/acknowledge',json=body)
    assert r.status_code==200,r.text
    claim=r.json()
    assert claim['settlement_confirmed'] is False
    assert claim['receiving_credit_independently_verified'] is False
    assert crypto_utils.verify_signature(pub,crypto_utils.canonical_json(claim['claim']),claim['signature_b64'])
    assert client.post('/v1/acknowledge',json=body).json()==claim
    body['provider_reference']='CHANGED'
    assert client.post('/v1/acknowledge',json=body).status_code==409


def test_receiver_rejects_forged_context_blocked_destination_and_credit_claim(tmp_path):
    client,issuer_key,_=_setup(tmp_path)
    legit=_context(issuer_key)
    fake=dict(legit)
    fake['payload']=dict(legit['payload'],amount_minor_units=1)
    base={'receiver_id':'recv-a','provider_reference':'sandbox-reference','context':fake}
    assert client.post('/v1/acknowledge',json=base).status_code==403
    wrong=_context(issuer_key,beneficiary_id='not-approved')
    assert client.post('/v1/acknowledge',json=dict(base,context=wrong)).status_code==403
    denied=_context(issuer_key,decision='deny')
    assert client.post('/v1/acknowledge',json=dict(base,context=denied)).status_code==403
    assert client.post('/v1/acknowledge',json=dict(base,context=legit,result='CREDIT_ATTESTED')).status_code==422
    expired=_context(issuer_key,issued_at=(datetime.now(timezone.utc)-timedelta(minutes=8)).isoformat())
    assert client.post('/v1/acknowledge',json=dict(base,context=expired)).status_code==403
