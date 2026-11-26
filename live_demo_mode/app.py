"""Paari Live Demo Mode: human-controlled, dynamically created records, real APIs.

Only for a loopback sandbox. No preset payment cases, no seed records, no database
shortcuts, no real provider rail. Keys held in process RAM; backend records persist.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'sdk'))
from paari_agent import PaariAgentClient, generate_keypair, sign_delegation, fingerprint
from paari_agent.crypto import verify_paari_card
from paari_agent.crypto import sign_text
from app import crypto_utils
from app.safr.envelope import (
    GovernanceEnvelope, beneficiary_reference_digest, compute_action_digest, signing_payload,
)

class ParentInput(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    contact: str = Field(min_length=5, max_length=200)
    parent_type: str = 'developer'


class AgentInput(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    agent_type: str = 'shopping_assistant'
    purpose: str = Field(default='Authorized delegated payments', max_length=500)
    currency: str = Field(default='INR', pattern=r'^[A-Z]{3}$')
    max_amount: int = Field(ge=1, le=10**12)
    delegation_days: int = Field(default=7, ge=1, le=90)


class MandateInput(BaseModel):
    user_id: str = Field(min_length=1, max_length=100)
    max_per_transaction: int = Field(ge=1, le=10**12)
    max_daily_amount: int = Field(ge=1, le=10**12)
    allowed_merchants: str = ''  # CSV; blank means any merchant
    require_review_above: int | None = Field(default=None, ge=1)
    validity_days: int = Field(default=30, ge=1, le=90)


class ControlsInput(BaseModel):
    resource_ref: str = Field(min_length=1, max_length=100)
    # Development-attested identities have 'low' assurance. In a local demonstration
    # only, choose a policy threshold consistent with that assurance. No direct DB writes.
    min_evidence_quality_bps: int = Field(default=0, ge=0, le=10000)
    observe_threshold_bps: int = Field(default=2500, ge=0, le=10000)
    escalate_threshold_bps: int = Field(default=6000, ge=0, le=10000)
    deny_threshold_bps: int = Field(default=9000, ge=0, le=10000)


class RequestInput(BaseModel):
    merchant: str = Field(min_length=1, max_length=120)
    amount_minor_units: int = Field(ge=1, le=10**12)
    purpose: str = Field(min_length=1, max_length=500)
    merchant_category: str | None = None


class TxInput(BaseModel):
    transaction_id: str = Field(min_length=1, max_length=100)


class DemoSession:
    def __init__(self):
        self.lock = threading.RLock()
        self.parent_private = ''
        self.parent_public = ''
        self.parent_id = ''
        self.agent_private = ''
        self.agent_public = ''
        self.agent: PaariAgentClient | None = None
        self.agent_id = ''
        self.user_private = ''
        self.user_public = ''
        self.user_id = ''
        self.mandate_id = ''
        self.currency = ''
        self.cap = 0
        self.control_key = ''
        self.principal_id = ''
        self.resource_id = ''
        self.transactions: dict[str, dict] = {}
        self.timeline: list[dict] = []
        self.requests_submitted = 0
        self.executed_payments = 0

    def record(self, action: str, result: dict):
        safe = {k: v for k, v in result.items() if k not in {
            'credential_jwt', 'session_token', 'secret', 'signature_b64',
            'user_private_key', 'agent_private_key', 'parent_private_key'}}
        self.timeline.append({'at': datetime.now(timezone.utc).isoformat(),
                              'action': action, 'response': safe})
        if len(self.timeline) > 150:
            self.timeline.pop(0)
        return safe


def _json(r: httpx.Response) -> dict:
    try:
        body = r.json()
    except ValueError:
        body = {'error': r.text[:300]}
    if r.status_code >= 400:
        raise HTTPException(r.status_code, {'upstream_http': r.status_code, 'response': body})
    return body


def _mandate_canonical(fields: dict) -> str:
    payload = {'purpose': 'paari_user_payment_mandate', 'mandate_version': 1,
               'mandate_id': fields['mandate_id'], 'user_id': fields['user_id'],
               'agent_id': fields['agent_id'], 'org_id': 'default',
               'constraints': {
                   'currency': fields['currency'],
                   'max_per_transaction': fields['max_per_transaction'],
                   'max_daily_amount': fields['max_daily_amount'],
                   'max_per_hour': fields.get('max_per_hour'),
                   'max_per_merchant_per_day': fields.get('max_per_merchant_per_day'),
                   'max_category_per_day': fields.get('max_category_per_day'),
                   'allowed_merchants': sorted(fields.get('allowed_merchants') or []),
                   'allowed_categories': sorted(fields.get('allowed_categories') or []),
                   'require_review_above': fields.get('require_review_above'),
               },
               'issued_at': int(datetime.fromisoformat(fields['valid_from']).timestamp()),
               'expires_at': int(datetime.fromisoformat(fields['expires_at']).timestamp())}
    return json.dumps(payload, sort_keys=True, separators=(',', ':'))


def _signed_safr(s: DemoSession, txn: dict) -> dict:
    agent = s.agent
    assert agent is not None
    now = datetime.now(timezone.utc)
    p = {'org_id': 'default', 'agent_id': s.agent_id,
         'mandate_id': s.mandate_id, 'transaction_id': txn['transaction_id'],
         'merchant': txn['merchant'], 'amount_minor_units': txn['amount_minor_units'],
         'currency': s.currency, 'action': 'make_payment', 'purpose': txn['purpose'],
         'merchant_category': txn.get('merchant_category')}
    digest = hashlib.sha256(crypto_utils.canonical_json(p).encode()).hexdigest()
    raw = {'envelope_type': 'paari.safr.governance-envelope', 'schema_version': '1.0',
           'envelope_id': str(uuid.uuid4()), 'tenant_id': 'default',
           'agent_id': s.agent_id, 'parent_id': s.parent_id,
           'principal_id': s.principal_id, 'resource_id': s.resource_id,
           'mandate_id': s.mandate_id, 'action_type': 'payment.execute',
           'action_context': {'resource_id': s.resource_id, 'operation': 'make_payment',
                              'amount_minor_units': txn['amount_minor_units'],
                              'currency': s.currency,
                              'beneficiary_ref_digest': beneficiary_reference_digest(txn['merchant']),
                              'merchant': txn['merchant'], 'purpose': txn['purpose'],
                              'provider_id': 'razorpay', 'jurisdiction': 'AE',
                              'request_context_digest': digest},
           'trace': {'trace_id': 'live-' + txn['transaction_id'],
                     'source_system': 'paari-live-demo-sdk-agent', 'sequence': 1,
                     'parent_trace_id': None,
                     'trace_digest': hashlib.sha256(txn['transaction_id'].encode()).hexdigest()},
           'evidence_refs': [], 'issued_at': now.isoformat(),
           'expires_at': (now + timedelta(minutes=2)).isoformat(),
           'signing_key_fingerprint': crypto_utils.public_key_fingerprint(s.agent_public),
           'action_digest': '0'*64, 'signature_b64': 'A'*88}
    envelope = GovernanceEnvelope.model_validate(raw)
    raw['action_digest'] = compute_action_digest(envelope)
    envelope = GovernanceEnvelope.model_validate(raw)
    raw['signature_b64'] = crypto_utils.sign_with_private_key(
        s.agent_private, crypto_utils.canonical_json(signing_payload(envelope)))
    return GovernanceEnvelope.model_validate(raw).model_dump(mode='json')


def build_app(*, backend_url: str, stub_base: str, admin_api_key: str,
              webhook_secret: str = 'stub_webhook_secret',
              demo_api_token: str | None = None) -> FastAPI:
    for url in (backend_url, stub_base):
        p = urlparse(url)
        if p.scheme != 'http' or p.hostname not in {'127.0.0.1', 'localhost'}:
            raise ValueError('Live demo supports loopback HTTP services only')
    if not admin_api_key or not stub_base:
        raise ValueError('Live demo requires an admin API key and a local payment simulator')
    # This service no longer serves a browser page, so the operator must supply
    # its API token out of band. Never expose the token through any GET endpoint.
    csrf = demo_api_token or os.environ.get('PAARI_DEMO_API_TOKEN') or secrets.token_urlsafe(32)
    s = DemoSession()
    app = FastAPI(title='Paari Live Demo Mode', docs_url=None, redoc_url=None, openapi_url=None)

    def require_local(request: Request, x_paari_demo_token: str = Header(default='')):
        # Loopback enforcement relaxed for shared tunnel testing; CSRF token still required.
        origin = request.headers.get('origin')
        if origin and origin != str(request.base_url).rstrip('/'):
            raise HTTPException(403, 'Cross-origin requests denied')
        if not secrets.compare_digest(x_paari_demo_token, csrf):
            raise HTTPException(403, 'CSRF token required')

    def api(path: str, payload: dict, *, admin=False, control=False) -> dict:
        headers = ({'X-Admin-Api-Key': admin_api_key} if admin else
                   {'X-Paari-Control-Key': s.control_key, 'X-Paari-Org': 'default'} if control else {})
        with httpx.Client(base_url=backend_url, timeout=30) as h:
            return _json(h.post(path, json=payload, headers=headers))

    @app.get('/api/agent/card')
    def agent_card():
        """Public, already-verified Agent Card snapshot for the live session agent.

        Identity/discovery evidence only - it is NOT payment authorization and it
        never carries a private key or bearer token.
        """
        with s.lock:
            if not s.agent or not s.agent.card:
                return {'card': None, 'verified': False, 'note': 'Agent not registered yet'}
            card = s.agent.card
            return {'card': card, 'verified': verify_paari_card(card)}

    @app.get('/api/status')
    def status():
        with s.lock:
            try:
                health = httpx.get(backend_url + '/health', timeout=2).json()
            except Exception:
                health = {'status': 'unavailable'}
            return {'sandbox_only': True, 'no_fixtures': True, 'server_health': health,
                    'parent_id': s.parent_id, 'agent_id': s.agent_id,
                    'mandate_id': s.mandate_id, 'principal_id': s.principal_id,
                    'resource_id': s.resource_id, 'transaction_count': len(s.transactions),
                    'requests_submitted': s.requests_submitted,
                    'executed_payments': s.executed_payments,
                    'currency': s.currency,
                    'timeline': s.timeline[-25:]}

    @app.post('/api/parent')
    def parent(request: Request, data: ParentInput, x_paari_demo_token: str = Header(default='')):
        require_local(request, x_paari_demo_token)
        with s.lock:
            if s.parent_id:
                raise HTTPException(409, 'Parent already created in this session; restart demo to start fresh')
            priv, pub = generate_keypair()
            payload = data.model_dump()
            # Map the control-plane UI's display labels to the backend's allowed values.
            type_map = {'Business': 'company', 'Individual': 'developer',
                        'Financial institution': 'company', 'Platform': 'platform',
                        'company': 'company', 'developer': 'developer',
                        'platform': 'platform', 'agent': 'agent', 'idp': 'idp'}
            payload['parent_type'] = type_map.get(payload.get('parent_type', ''), payload.get('parent_type', 'developer'))
            # Ensure contact is a verifiable email/URL for the backend validator.
            contact = payload.get('contact', '') or ''
            if '@' not in contact and not contact.startswith('http'):
                contact = (contact.replace(' ', '').lower() or 'demo') + '@example.com'
            payload['contact'] = contact
            response = api('/parents/register', {**payload, 'public_key_pem': pub})
            s.parent_private, s.parent_public = priv, pub
            s.parent_id = response['parent_id']
            return s.record('parent_registered', {**response, 'public_key_fingerprint': fingerprint(pub)})

    @app.post('/api/parent/approve')
    def parent_approve(request: Request, x_paari_demo_token: str = Header(default='')):
        require_local(request, x_paari_demo_token)
        with s.lock:
            if not s.parent_id:
                raise HTTPException(409, 'Register the parent first')
            response = api(f'/parents/{s.parent_id}/approve', {}, admin=True)
            return s.record('admin_parent_approval', response)

    @app.post('/api/agent')
    def onboard_agent(request: Request, data: AgentInput, x_paari_demo_token: str = Header(default='')):
        require_local(request, x_paari_demo_token)
        with s.lock:
            if not s.parent_id:
                raise HTTPException(409, 'Parent must be registered and approved first')
            if s.agent_id:
                raise HTTPException(409, 'Agent already registered in this session')
            priv, pub = generate_keypair()
            now = int(time.time())
            delegation = {'delegation_id': str(uuid.uuid4()), 'parent_id': s.parent_id,
                          'agent_public_key_fingerprint': fingerprint(pub),
                          'granted_capabilities': ['make_payment'],
                          'payment_limit_minor_units': data.max_amount,
                          'currency': data.currency, 'issued_at': now,
                          'expires_at': now + 86400*data.delegation_days}
            client = PaariAgentClient(backend_url, priv, pub)
            try:
                registered = client.register(name=data.name, agent_type=data.agent_type,
                    purpose=data.purpose, delegation=delegation,
                    delegation_signature_b64=sign_delegation(s.parent_private, delegation))
                authenticated = client.authenticate()
            except Exception:
                client.http.close()
                raise
            s.agent = client
            s.agent_id = client.agent_id
            s.agent_private, s.agent_public = priv, pub
            s.cap, s.currency = data.max_amount, data.currency
            return s.record('agent_registered_and_authenticated', {
                'agent_id': s.agent_id, 'authenticated': authenticated['authenticated'],
                'agent_card_signature_verified': verify_paari_card(registered['agent_card']),
                'parent_id': s.parent_id, 'delegation_id': delegation['delegation_id'],
                'limit_minor_units': s.cap, 'currency': s.currency,
                'agent_key_fingerprint': fingerprint(pub)})

    @app.post('/api/mandate')
    def mandate(request: Request, data: MandateInput, x_paari_demo_token: str = Header(default='')):
        require_local(request, x_paari_demo_token)
        with s.lock:
            if not s.agent_id:
                raise HTTPException(409, 'Agent registration required')
            if s.mandate_id:
                raise HTTPException(409, 'A mandate already exists for this session')
            private, public = generate_keypair()
            now = datetime.now(timezone.utc)
            mandate_id = 'UM-LIVE-' + uuid.uuid4().hex[:12]
            merchants = [x.strip() for x in data.allowed_merchants.split(',') if x.strip()]
            fields = {'mandate_id': mandate_id, 'user_id': data.user_id, 'agent_id': s.agent_id,
                      'max_per_transaction': data.max_per_transaction,
                      'max_daily_amount': data.max_daily_amount,
                      'max_per_hour': None, 'max_per_merchant_per_day': None,
                      'max_category_per_day': None, 'currency': s.currency,
                      'allowed_merchants': merchants, 'allowed_categories': [],
                      'require_review_above': data.require_review_above,
                      'valid_from': now.isoformat(),
                      'expires_at': (now + timedelta(days=data.validity_days)).isoformat(),
                      'approval_reference': 'live-consent-' + uuid.uuid4().hex[:12]}
            response = api('/v1/mandates', {**fields, 'user_public_key_pem': public,
                'mandate_signature_b64': sign_text(private, _mandate_canonical(fields)),
                'signing_key_id': 'live-user-'+uuid.uuid4().hex[:12]}, admin=True)
            if not response.get('signature_valid'):
                raise HTTPException(502, 'Backend did not confirm signed mandate')
            s.user_private, s.user_public = private, public
            s.user_id, s.mandate_id = data.user_id, mandate_id
            return s.record('user_signed_mandate', {
                'mandate_id': mandate_id, 'user_id': data.user_id,
                'signature_valid': response['signature_valid'], 'status': response['status'],
                'max_per_transaction': data.max_per_transaction, 'currency': s.currency,
                'allowed_merchants': merchants, 'require_review_above': data.require_review_above})

    @app.post('/api/controls')
    def control_plane(request: Request, data: ControlsInput, x_paari_demo_token: str = Header(default='')):
        require_local(request, x_paari_demo_token)
        with s.lock:
            if not s.mandate_id:
                raise HTTPException(409, 'Signed mandate required first')
            if s.resource_id:
                raise HTTPException(409, 'Controls already established this session')
            if not data.observe_threshold_bps < data.escalate_threshold_bps < data.deny_threshold_bps:
                raise HTTPException(422, 'Threshold order must be observe < escalate < deny')
            now = datetime.now(timezone.utc)
            control = api('/control/v1/admin-keys', {
                'org_id': 'default', 'scopes': ['control:read', 'control:write'],
                'expires_at': (now + timedelta(days=7)).isoformat()}, admin=True)
            s.control_key = control['secret']
            pr = api('/control/v1/principals', {
                'external_subject_id': s.user_id,
                'identity_provider': 'oidc:local-dev-idp',
                'display_name': 'Live dev principal '+s.user_id}, control=True)
            s.principal_id = pr['principal_id']
            principal = api('/control/v1/principals/'+s.principal_id+'/attest', {
                'attestation_reference': 'local-development-attestation-'+uuid.uuid4().hex[:12]}, control=True)
            res = api('/control/v1/resources', {
                'resource_type': 'bank_account', 'provider_id': 'razorpay',
                'external_resource_ref': data.resource_ref,
                'owner_principal_id': s.principal_id, 'currency': s.currency,
                'classification': 'restricted', 'metadata': {}}, control=True)
            s.resource_id = res['resource_id']
            pol = api('/control/v1/policies', {
                'policy_name': 'payment_execution', 'version': 'live-'+uuid.uuid4().hex[:12],
                'activate': True, 'min_evidence_quality_bps': data.min_evidence_quality_bps,
                'observe_threshold_bps': data.observe_threshold_bps,
                'escalate_threshold_bps': data.escalate_threshold_bps,
                'deny_threshold_bps': data.deny_threshold_bps,
                'require_signed_mandate': True}, control=True)
            for subject_type, subject_id in (('principal', s.principal_id), ('agent', s.agent_id)):
                api(f'/control/v1/resources/{s.resource_id}/grants', {
                    'subject_type': subject_type, 'subject_id': subject_id,
                    'actions': ['payment:execute'],
                    'consent_reference': 'live-'+subject_type+'-'+uuid.uuid4().hex[:12],
                    'valid_from': (now - timedelta(minutes=1)).isoformat(),
                    'valid_until': (now + timedelta(days=7)).isoformat()}, control=True)
            api(f'/v1/mandates/{s.mandate_id}/provider-binding', {
                'provider': 'razorpay', 'source_resource_id': s.resource_id,
                'provider_mandate_ref': 'live-provider-mandate-'+uuid.uuid4().hex[:12],
                'provider_instrument_ref': 'live-instrument-'+uuid.uuid4().hex[:12],
                'currency': s.currency, 'max_amount_minor_units': s.cap,
                'expires_at': (now + timedelta(days=7)).isoformat()}, admin=True)
            return s.record('institutional_controls_created', {
                'principal_id': s.principal_id, 'principal_status': principal['status'],
                'development_assurance_level': principal['assurance_level'],
                'resource_id': s.resource_id, 'policy_id': pol['policy_id'],
                'min_evidence_quality_bps': data.min_evidence_quality_bps,
                'note': 'Organizational dev attestation only; NOT verified KYC/KYB'})

    @app.post('/api/agent/request')
    def agent_request(request: Request, data: RequestInput, x_paari_demo_token: str = Header(default='')):
        require_local(request, x_paari_demo_token)
        with s.lock:
            if not s.resource_id or not s.agent or not s.agent.session_token:
                raise HTTPException(409, 'Complete live identity, mandate and controls first')
            txn_id = 'TXN-LIVE-'+uuid.uuid4().hex[:16]
            params = {'backend': backend_url, 'agent_private_key': s.agent_private,
                      'agent_public_key': s.agent_public, 'agent_id': s.agent_id,
                      'session_token': s.agent.session_token, 'transaction_id': txn_id,
                      'idempotency_key': str(uuid.uuid4()), 'merchant': data.merchant,
                      'amount_minor_units': data.amount_minor_units, 'currency': s.currency,
                      'purpose': data.purpose, 'merchant_category': data.merchant_category}
            result = subprocess.run([sys.executable, '-m', 'live_demo_mode.agent_worker'],
                                    input=json.dumps(params), text=True, capture_output=True,
                                    cwd=ROOT, timeout=30, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            try:
                worker = json.loads(result.stdout)
            except (ValueError, TypeError):
                raise HTTPException(502, 'Agent worker did not return a valid response')
            if result.returncode != 0 or not worker.get('ok'):
                raise HTTPException(502, {'agent_worker_error': worker.get('error', 'execution failed')})
            body = worker['result']
            # Snapshot the signed Agent Card at request time so the tracker shows
            # the exact identity that originated the payment, not a later state.
            card = s.agent.card if s.agent else None
            s.transactions[txn_id] = {**data.model_dump(), 'transaction_id': txn_id,
                                      'intent': body,
                                      'authorization_id': (body.get('authorization') or {}).get('authorization_id'),
                                      'agent_card': card,
                                      'envelope': None, 'review': None, 'outcome': None}
            decisions = _json(httpx.get(backend_url+'/control/v1/decisions',
                headers={'X-Paari-Control-Key': s.control_key, 'X-Paari-Org': 'default'}, timeout=15))
            match = next((d for d in decisions if d.get('intent_id') == body.get('intent_id')), None)
            s.requests_submitted += 1
            return s.record('agent_originated_payment_intent', {
                'transaction_id': txn_id, 'agent_process': 'separate SDK process',
                'intent': body, 'safr_decision': match})

    @app.post('/api/review/parent-step-up')
    def parent_step_up(request: Request, data: TxInput,
                       x_paari_demo_token: str = Header(default='')):
        """Explicit live parent-signed step-up: NEVER overrides an ESCALATE disposition.

        The Paari backend performs the verification and determines whether a bounded
        authorization can be minted. Its STRICT control plane still rejects the
        execution of an ESCALATE-held action until a newly governed permissive
        decision exists. This endpoint intentionally does not manufacture one.
        """
        require_local(request, x_paari_demo_token)
        with s.lock:
            txn = s.transactions.get(data.transaction_id)
            if not txn:
                raise HTTPException(404, 'Unknown transaction')
            intent = txn.get('intent') or {}
            if intent.get('decision') != 'review':
                raise HTTPException(409, 'This transaction is not awaiting review')
            if not intent.get('mfa_required'):
                raise HTTPException(409,
                    'This is a governance/reviewer hold, not a parent step-up challenge. '
                    'It cannot be auto-approved; use a separately governed new request.')
            if not s.parent_private or not s.agent:
                raise HTTPException(409, 'Active agent and parent are required')
            if txn.get('review'):
                raise HTTPException(409, 'Step-up already attempted for this transaction')
            path = '/v1/payments/mfa/challenge'
            challenge = s.agent._request('POST', path, auth=True, json={
                'intent_id': intent['intent_id'], 'session_token': s.agent.session_token}).json()
            signature = crypto_utils.sign_with_private_key(
                s.parent_private, challenge['context_to_sign'])
            approval = api('/v1/payments/mfa/verify', {
                'intent_id': intent['intent_id'],
                'challenge_id': challenge['challenge_id'],
                'parent_signature_b64': signature})
            txn['review'] = approval
            txn['authorization_id'] = (approval.get('authorization') or {}).get('authorization_id')
            return s.record('parent_signed_transaction_bound_step_up', {
                'transaction_id': data.transaction_id,
                'intent_id': intent['intent_id'], 'parent_signature_verified_by_paari': True,
                'review_result': approval,
                'warning': 'Parent step-up is NOT permission to execute an ESCALATE-held payment. '
                           'The original control-plane disposition and SAFR envelope remain mandatory.'})

    @app.post('/api/envelope')
    def envelope(request: Request, data: TxInput, x_paari_demo_token: str = Header(default='')):
        require_local(request, x_paari_demo_token)
        with s.lock:
            txn = s.transactions.get(data.transaction_id)
            if not txn:
                raise HTTPException(404, 'Unknown transaction')
            if txn['envelope']:
                raise HTTPException(409, 'Envelope already processed for this transaction')
            signed = _signed_safr(s, txn)
            response = api('/control/v1/governance/envelopes/process?transaction_id='+data.transaction_id,
                           signed, control=True)
            txn['envelope'] = response
            return s.record('live_signed_safr_envelope_processed', {
                'transaction_id': data.transaction_id,
                'envelope_id': signed['envelope_id'], 'result': response})

    @app.post('/api/execute')
    def execute(request: Request, data: TxInput, x_paari_demo_token: str = Header(default='')):
        require_local(request, x_paari_demo_token)
        with s.lock:
            txn = s.transactions.get(data.transaction_id)
            if not txn:
                raise HTTPException(404, 'Unknown transaction')
            if txn.get('outcome'):
                raise HTTPException(409, 'Transaction already processed in this session')
            env_receipt = txn.get('envelope') or {}
            if not env_receipt.get('execution_permitted'):
                raise HTTPException(403, 'SAFR envelope does not permit payment execution')
            auth = txn.get('authorization_id')
            if not auth:
                raise HTTPException(403, 'No bounded authorization issued for this transaction')
            # Paari, not this UI, enforces signed agent auth, fresh controls and atomic consume.
            try:
                consumed = s.agent.consume(auth)
            except Exception as exc:
                code = getattr(exc, 'status_code', 500)
                detail = getattr(exc, 'detail', str(exc))
                raise HTTPException(code if isinstance(code,int) else 500, detail)
            order = consumed.get('razorpay_order_id')
            if not order:
                # Uncertain state: do not create a second payment or claim success.
                raise HTTPException(502, 'Consume returned no provider order; check reconciliation')
            amount, currency = txn['amount_minor_units'], s.currency
            basic = ('sim_key', 'sim_secret')
            with httpx.Client(timeout=20, auth=basic) as h:
                payment = _json(h.post(stub_base+'/payments', json={
                    'order_id': order, 'amount': amount, 'currency': currency}))
                captured = _json(h.post(stub_base+'/payments/'+payment['id']+'/capture',
                                        json={'amount': amount, 'currency': currency}))
            raw = json.dumps({'entity': 'event', 'id': 'evt_LIVE_'+uuid.uuid4().hex,
                              'event': 'payment.captured', 'created_at': int(time.time()),
                              'payload': {'payment': {'entity': captured}}}).encode()
            signature = hmac.new(webhook_secret.encode(), raw, hashlib.sha256).hexdigest()
            wh = _json(httpx.post(backend_url+'/v1/payments/webhooks/razorpay',
                content=raw, headers={'X-Razorpay-Signature': signature,
                                     'Content-Type': 'application/json'}, timeout=20))
            reconciled = s.agent.reconcile(auth)
            proof = s.agent.proof_bundle(data.transaction_id)
            audit = (proof.get('artifacts') or {}).get('audit_record') or {}
            result_artifact = (proof.get('artifacts') or {}).get('payment_result') or {}
            state = reconciled.get('state') or reconciled.get('status')
            report = {'transaction_id': data.transaction_id,
                      'authorization_id': auth, 'order_id': order,
                      'provider_webhook': wh, 'reconciliation': reconciled,
                      'final_state': state, 'settlement_source': result_artifact.get('settlement_source'),
                      'audit_chain_verified': audit.get('chain_verified'),
                      'audit_events': [e.get('event_type') or e.get('kind') for e in audit.get('events', [])]}
            txn['outcome'] = report
            s.executed_payments += 1
            return s.record('simulated_payment_executed_and_audited', report)

    @app.post('/api/proof')
    def proof(request: Request, data: TxInput, x_paari_demo_token: str = Header(default='')):
        require_local(request, x_paari_demo_token)
        with s.lock:
            if not s.agent or data.transaction_id not in s.transactions:
                raise HTTPException(404, 'Unknown transaction')
            response = s.agent.proof_bundle(data.transaction_id)
            # Avoid echoing entire principal/agent tokens; proof bundle carries none.
            return s.record('live_proof_retrieved', {'transaction_id': data.transaction_id,
                                                     'bundle': response})

    @app.get('/api/transactions')
    def transactions():
        with s.lock:
            return [{'transaction_id': k, 'merchant': v['merchant'],
                     'amount_minor_units': v['amount_minor_units'],
                     'currency': s.currency, 'purpose': v.get('purpose'),
                     'intent': v['intent'], 'review': v.get('review'), 'envelope': v['envelope'],
                     'outcome': v['outcome'], 'agent_card': v.get('agent_card')}
                    for k, v in reversed(list(s.transactions.items()))]

    return app
