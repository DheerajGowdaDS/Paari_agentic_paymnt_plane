"""Local UI guard/contract smoke tests; NOT full database/payment E2E tests."""
from datetime import datetime, timedelta, timezone
import json

import pytest
from fastapi.testclient import TestClient
from live_demo_mode.app import _mandate_canonical, build_app, DemoSession, MandateInput, ControlsInput
from scripts.start_live_demo import guarded_dsn


def test_live_demo_orchestrator_is_api_only():
    with TestClient(build_app(backend_url='http://127.0.0.1:8120',
                              stub_base='http://127.0.0.1:9911/v1',
                              admin_api_key='test-admin',
                              demo_api_token='test-demo-token')) as client:
        assert client.get('/').status_code == 404
        assert client.get('/api/agent/card').status_code == 200


def test_agent_card_endpoint_is_public_and_redacted():
    with TestClient(build_app(backend_url='http://127.0.0.1:8120',
                              stub_base='http://127.0.0.1:9911/v1',
                              admin_api_key='test-admin')) as client:
        r = client.get('/api/agent/card')
        assert r.status_code == 200
        body = r.json()
        # No agent registered yet: card is null and never carries a key or token.
        assert body['card'] is None
        assert body['verified'] is False
        assert 'private' not in json.dumps(body)


def test_parent_creation_requires_csrf_even_before_api_call():
    with TestClient(build_app(backend_url='http://127.0.0.1:8120',
                              stub_base='http://127.0.0.1:9911/v1',
                              admin_api_key='test-admin')) as client:
        r = client.post('/api/parent', json={'name': 'Test Parent', 'parent_type': 'developer',
                                               'contact': 'example@example.com'})
        assert r.status_code == 403
        assert 'CSRF' in str(r.json())


def test_disallow_external_payment_services():
    with pytest.raises(ValueError):
        build_app(backend_url='https://public.example',stub_base='http://127.0.0.1:9911/v1',admin_api_key='x')
    with pytest.raises(ValueError):
        guarded_dsn('postgresql+psycopg://someuser:pass@outside.example.com:5432/live')
    with pytest.raises(ValueError):
        guarded_dsn('postgresql://test:pass@127.0.0.1:5432/production')


def test_signed_mandate_canonical_has_dynamic_values():
    now=datetime.now(timezone.utc)
    fields={'mandate_id':'mandate-dynamic-abc','user_id':'person-10','agent_id':'agent-live',
            'currency':'INR','max_per_transaction':99111,'max_daily_amount':199222,
            'max_per_hour':None,'max_per_merchant_per_day':None,'max_category_per_day':None,
            'allowed_merchants':['Store-A'], 'allowed_categories':[], 'require_review_above':22222,
            'valid_from':now.isoformat(), 'expires_at':(now+timedelta(days=7)).isoformat()}
    p=json.loads(_mandate_canonical(fields))
    assert p['constraints']['max_per_transaction']==99111
    assert p['constraints']['allowed_merchants']==['Store-A']
    assert p['mandate_id']=='mandate-dynamic-abc'


def test_event_log_never_records_keys_or_tokens():
    s=DemoSession()
    out=s.record('test', {'parent_private_key':'SECRET1','secret':'SECRET2',
                          'session_token':'SECRET3','credential_jwt':'SECRET4','transaction_id':'dynamic'})
    assert 'SECRET' not in json.dumps(out)
    assert out['transaction_id']=='dynamic'


def test_controls_and_mandates_are_user_configurable():
    assert ControlsInput(resource_ref='any_account_ref',min_evidence_quality_bps=5000,
                         observe_threshold_bps=1200,escalate_threshold_bps=2400,deny_threshold_bps=8000)
    assert MandateInput(user_id='another-person',max_per_transaction=1,max_daily_amount=5,
                        allowed_merchants='StoreA,StoreB')


def test_session_starts_without_business_records():
    s = DemoSession()
    assert not s.parent_id and not s.agent_id and not s.mandate_id
    assert not s.principal_id and not s.resource_id and s.transactions == {}
    assert s.timeline == []


def test_live_envelope_has_real_agent_signature_and_exact_action_binding():
    from live_demo_mode.app import _signed_safr
    from paari_agent import generate_keypair
    from app import crypto_utils
    from app.safr.envelope import GovernanceEnvelope, signing_payload, compute_action_digest
    from paari_agent.crypto import verify_paari_card

    key, public = generate_keypair()
    s = DemoSession()
    s.agent_private, s.agent_public = key, public
    s.agent_id, s.parent_id, s.principal_id, s.resource_id = (
        'agent-dynamic', 'parent-dynamic', 'principal-dynamic', 'resource-dynamic'
    )
    s.mandate_id, s.currency = 'mandate-dynamic', 'INR'
    s.agent = object()  # _signed_safr only needs the registered agent to be present
    txn = {'transaction_id': 'TXN-custom', 'merchant': 'Shop-Custom',
           'amount_minor_units': 4321, 'purpose': 'Supplies for custom live task'}
    signed = _signed_safr(s, txn)
    envelope = GovernanceEnvelope.model_validate(signed)
    assert envelope.action_context.amount_minor_units == 4321
    assert envelope.action_context.merchant == 'Shop-Custom'
    assert signed['action_digest'] == compute_action_digest(envelope)
    assert crypto_utils.verify_signature(public,
        crypto_utils.canonical_json(signing_payload(envelope)), signed['signature_b64'])


def test_unknown_transaction_cannot_trigger_execution_or_parent_review():
    with TestClient(build_app(backend_url='http://127.0.0.1:8120',
                              stub_base='http://127.0.0.1:9911/v1',
                              admin_api_key='test-admin',
                              demo_api_token='unknown-tx-test-token')) as client:
        token='unknown-tx-test-token'
        for path in ('/api/execute','/api/review/parent-step-up', '/api/envelope'):
            response=client.post(path, json={'transaction_id':'no-record'},
                                 headers={'X-Paari-Demo-Token':token})
            assert response.status_code==404
