"""V3.6 API-only onboarding, manual verification and scoped provider policies.

Sandbox development endpoints. Production use requires KYC/KYB, managed keys,
regulated-provider integration and a separate security review.
"""
import hashlib
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app import models as core, schemas as legacy, security as platform_security, crypto_utils
from app.database import get_db
from app.routers.agents import register_agent as legacy_register_agent
from app.v36 import models, security

router = APIRouter(prefix='/v36', tags=['v3.6-onboarding'])
POLICIES = {
    'terms': ('0.1-demo', 'DEVELOPMENT TEMPLATE ONLY: Paari sandbox terms; not binding production legal terms.'),
    'privacy': ('0.1-demo', 'DEVELOPMENT TEMPLATE ONLY: Paari privacy notice. Do not enter live personal records.'),
    'agent_security': ('0.1-demo', 'DEVELOPMENT TEMPLATE ONLY: Agent security and delegation responsibilities.'),
    'provider_participation': ('0.1-demo', 'DEVELOPMENT TEMPLATE ONLY: Institutional participation and technical controls.'),
}

def policy_info(code):
    ver, doc = POLICIES[code]
    return {'code':code, 'version':ver, 'text':doc, 'sha256':hashlib.sha256(doc.encode()).hexdigest()}

@router.get('/agreements')
def agreements():
    return [policy_info(x) for x in POLICIES]


def capture_acceptance(db, kind, subject, codes):
    for code in codes:
        p=policy_info(code)
        db.add(models.PolicyAcceptance(subject_type=kind,subject_id=subject,policy_code=code,
                   version=p['version'],document_sha256=p['sha256']))


def admin_auth(key):
    platform_security.require_admin_org(key, None)


def parent_auth(token, db):
    pid=security.get_parent_from_token(token)
    parent=db.query(core.ParentAuthority).filter_by(parent_id=pid).first()
    if not parent or parent.status != core.ParentStatus.ACTIVE:
        raise HTTPException(403,'Parent account not approved or active')
    if not db.query(models.ParentAccount).filter_by(parent_pk=parent.id).first():
        raise HTTPException(403,'Not an onboarded v3.6 parent')
    return parent

class ParentCreate(BaseModel):
    parent_type: Literal['person','organization']
    name: str = Field(min_length=2,max_length=200)
    identifier: str = Field(min_length=10,max_length=15,description='PAN for person or GSTIN for organization')
    representative_name: str = Field(min_length=2,max_length=200)
    representative_email: str = Field(min_length=5,max_length=200)
    representative_phone: str = Field(min_length=7,max_length=30)
    address: str = Field(default='',max_length=500)
    password: str = Field(min_length=12,max_length=128)
    accept_terms: bool
    accept_privacy: bool
    accept_agent_security: bool
    @model_validator(mode='after')
    def validate_fields(self):
        v=self.identifier.strip().upper().replace(' ','')
        if self.parent_type=='person' and not re.fullmatch(r'[A-Z]{5}[0-9]{4}[A-Z]',v):
            raise ValueError('Invalid PAN format')
        if self.parent_type=='organization' and not re.fullmatch(r'[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][A-Z0-9]Z[A-Z0-9]',v):
            raise ValueError('Invalid GSTIN format')
        if '@' not in self.representative_email or self.representative_email.count('@')!=1:
            raise ValueError('Representative email is invalid')
        if not all([self.accept_terms,self.accept_privacy,self.accept_agent_security]):
            raise ValueError('All three onboarding agreements must be accepted')
        self.identifier=v
        return self

@router.post('/parents/register', status_code=201)
def parent_register(req: ParentCreate, db:Session=Depends(get_db)):
    security.sandbox_only()
    # Fail closed if sandbox secrets are unconfigured; never store plaintext identifier.
    identity_hash=security.digest_identity(req.identifier)
    if db.query(models.ParentAccount).filter_by(identifier_hmac=identity_hash).first():
        raise HTTPException(409,'This identity has a pending or existing registration')
    public, encrypted_private=security.generate_managed_parent_key()
    parent=core.ParentAuthority(name=req.name,parent_type='company' if req.parent_type=='organization' else 'person',
           contact=req.representative_email,public_key_pem=public,status=core.ParentStatus.PENDING_VERIFICATION,
           trust_tier='self_asserted')
    db.add(parent); db.flush()
    account=models.ParentAccount(parent_pk=parent.id,kind=req.parent_type,
          identifier_last4=req.identifier[-4:],identifier_hmac=identity_hash,
          representative_name=req.representative_name,representative_email=req.representative_email,
          representative_phone=req.representative_phone,address=req.address,
          password_hash=security.hash_password(req.password), encrypted_signing_key=encrypted_private)
    db.add(account)
    capture_acceptance(db,'parent',parent.parent_id,('terms','privacy','agent_security'))
    db.commit()
    return {'parent_id':parent.parent_id,'registration_reference':account.registration_ref,'status':'pending_verification',
            'verification_method':'not_verified',
            'message':'Registration received. Configure PAARI_KYB_SIMULATION=1 for the local synthetic KYB workflow; no legal identity verification has occurred.'}

class KYBSimulationRequest(BaseModel):
    scenario: Literal['auto_approve','review_required','reject','provider_unavailable'] = 'auto_approve'

@router.post('/parents/{registration_reference}/simulate-kyb')
def simulate_parent_kyb(registration_reference: str, req: KYBSimulationRequest, db: Session = Depends(get_db)):
    """Run a deterministic local KYB journey; it is never trusted legal evidence."""
    security.sandbox_only()
    if os.environ.get('PAARI_ENV', 'sandbox').strip().lower() not in {'sandbox', 'test', 'local'} or os.environ.get('PAARI_LIVE') == '1':
        raise HTTPException(503, 'Synthetic KYB simulation is available only in local sandbox/test environments')
    if os.environ.get('PAARI_KYB_SIMULATION') != '1':
        raise HTTPException(503, 'PAARI_KYB_SIMULATION=1 is required to enable the local KYB simulator')
    account = db.query(models.ParentAccount).filter_by(registration_ref=registration_reference).first()
    if not account:
        raise HTTPException(404, 'Registration reference not found')
    parent = db.query(core.ParentAuthority).filter_by(id=account.parent_pk).first()
    if not parent or parent.status != core.ParentStatus.PENDING_VERIFICATION:
        raise HTTPException(409, 'Parent is not awaiting identity verification')
    latest_case = (db.query(models.KybSimulationCase)
                   .filter_by(registration_ref=registration_reference)
                   .order_by(models.KybSimulationCase.created_at.desc(), models.KybSimulationCase.id.desc()).first())
    if latest_case and latest_case.outcome != 'UNAVAILABLE':
        raise HTTPException(409, 'A sandbox KYB decision already exists; only an unavailable provider case may be retried')

    import hashlib
    from uuid import uuid4
    case_id = str(uuid4())
    scenarios = {
        'auto_approve': ('SIMULATED_VERIFIED', ['SANDBOX_KYB_AUTO_APPROVED'], core.ParentStatus.ACTIVE),
        'review_required': ('REVIEW_REQUIRED', ['KYB_SIMULATED_REVIEW_REQUIRED'], core.ParentStatus.PENDING_VERIFICATION),
        'reject': ('REJECTED', ['KYB_SIMULATED_REJECTED'], core.ParentStatus.REJECTED),
        'provider_unavailable': ('UNAVAILABLE', ['KYB_SIMULATED_PROVIDER_UNAVAILABLE'], core.ParentStatus.PENDING_VERIFICATION),
    }
    outcome, reason_codes, target_status = scenarios[req.scenario]
    evidence_digest = hashlib.sha256(f'paari-sandbox-kyb-v1|{case_id}|{parent.parent_id}|{req.scenario}'.encode()).hexdigest()
    case = models.KybSimulationCase(case_id=case_id, parent_id=parent.parent_id,
        registration_ref=registration_reference, scenario=req.scenario, outcome=outcome,
        reason_codes=reason_codes, evidence_digest=evidence_digest, sandbox_only=True)
    db.add(case)
    parent.status = target_status
    if req.scenario == 'auto_approve':
        parent.trust_tier = 'sandbox_kyb'
        parent.kyb_provider_ref = f'SIMULATED:{case_id}'
        parent.verified_at = datetime.now(timezone.utc)
    elif req.scenario == 'reject':
        parent.trust_tier = 'self_asserted'
    from app.audit import record_audit
    record_audit(db, transaction_id=f'kyb-sim-{case_id}', agent_id=f'parent:{parent.parent_id}',
        parent_id=parent.parent_id, org_id=parent.org_id, kind='sandbox_kyb_simulation',
        detail={'case_id':case_id,'provider_id':'paari-sandbox-kyb','scenario':req.scenario,
                'outcome':outcome,'reason_codes':reason_codes,'evidence_digest':evidence_digest,
                'sandbox_only':True,'legal_identity_verified':False})
    db.commit()
    return {'case_id':case_id,'parent_id':parent.parent_id,'status':parent.status.value,
            'outcome':outcome,'reason_codes':reason_codes,'evidence_digest':evidence_digest,
            'provider_id':'paari-sandbox-kyb','sandbox_only':True,'legal_identity_verified':False,
            'next_action': {'auto_approve':'register_agent',
                            'review_required':'manual_exception_review',
                            'provider_unavailable':'retry_provider_verification',
                            'reject':'registration_closed'}[req.scenario]}

@router.get('/parents/status/{registration_reference}')
def registration_status(registration_reference:str,db:Session=Depends(get_db)):
    account=db.query(models.ParentAccount).filter_by(registration_ref=registration_reference).first()
    if not account: raise HTTPException(404,'Registration reference not found')
    parent=db.query(core.ParentAuthority).filter_by(id=account.parent_pk).first()
    case=db.query(models.KybSimulationCase).filter_by(registration_ref=registration_reference).order_by(
        models.KybSimulationCase.created_at.desc(), models.KybSimulationCase.id.desc()).first()
    outcome_actions = {'SIMULATED_VERIFIED':'register_agent',
                       'REVIEW_REQUIRED':'manual_exception_review',
                       'REJECTED':'registration_closed',
                       'UNAVAILABLE':'retry_provider_verification'}
    return {'status':parent.status.value,'trust_tier':parent.trust_tier,
            'verification_method':'sandbox_simulation' if case else 'not_verified',
            'verification_outcome':case.outcome if case else 'NOT_VERIFIED',
            'reason_codes':case.reason_codes or [] if case else [],
            'provider_id':case.provider_id if case else None,
            'evidence_digest':case.evidence_digest if case else None,
            'next_action':outcome_actions.get(case.outcome, 'await_verification') if case else 'await_verification',
            'sandbox_only':bool(case),'legal_identity_verified':False}

class ParentLogin(BaseModel):
    parent_id: str
    password: str

@router.post('/parents/login')
def login(req: ParentLogin, db:Session=Depends(get_db)):
    security.sandbox_only()
    parent=db.query(core.ParentAuthority).filter_by(parent_id=req.parent_id).first()
    acc=db.query(models.ParentAccount).filter_by(parent_pk=parent.id).with_for_update().first() if parent else None
    # Account-based throttling; do not leak registration state during failures.
    now=datetime.now(timezone.utc)
    if acc and acc.locked_until and acc.locked_until > now:
        raise HTTPException(429,'Account temporarily locked; try again later')
    if not acc or not security.check_password(req.password,acc.password_hash):
        if acc:
            acc.failed_login_attempts += 1
            if acc.failed_login_attempts >= 5:
                acc.locked_until=now+timedelta(minutes=15)
            db.commit()
        raise HTTPException(401,'Invalid credentials or registration not active')
    if acc.failed_login_attempts or acc.locked_until:
        acc.failed_login_attempts=0
        acc.locked_until=None
        db.commit()
    if parent.status != core.ParentStatus.ACTIVE:
        raise HTTPException(403,'Parent awaiting Paari approval or inactive')
    return {'parent_id':parent.parent_id,'access_token':security.issue_parent_token(parent.parent_id),
            'token_type':'bearer','expires_in':1800}

class Approval(BaseModel):
    approve: bool
    identity_checked: bool = False
    contact_checked: bool = False
    representative_authority_checked: bool = False
    reviewer_note: str = Field(min_length=5,max_length=1000)

@router.post('/admin/parents/{parent_id}/review')
def review_parent(parent_id:str, req:Approval, x_admin_api_key:str=Header(default=''), db:Session=Depends(get_db)):
    security.sandbox_only()
    parent=db.query(core.ParentAuthority).filter_by(parent_id=parent_id).first()
    if not parent or not db.query(models.ParentAccount).filter_by(parent_pk=parent.id).first():
        raise HTTPException(404,'Onboarded parent not found')
    platform_security.require_admin_org(x_admin_api_key,parent.org_id)
    if parent.status != core.ParentStatus.PENDING_VERIFICATION:
        raise HTTPException(409,'Parent is not awaiting review')
    checks={'identity_checked':req.identity_checked,'contact_checked':req.contact_checked,
            'representative_authority_checked':req.representative_authority_checked}
    if req.approve and not all(checks.values()):
        raise HTTPException(422,'Approval requires all manual checklist items; do not call this automated KYC/KYB')
    parent.status=core.ParentStatus.ACTIVE if req.approve else core.ParentStatus.REJECTED
    parent.trust_tier='admin_approved' if req.approve else 'self_asserted'
    if req.approve: parent.verified_at=datetime.now(timezone.utc)
    db.add(models.ManualApproval(subject_type='parent',subject_id=parent_id,decision='approved' if req.approve else 'rejected',
                                  checks=checks,reviewer_note=req.reviewer_note))
    from app.audit import record_audit
    review_reason = 'KYB_MANUAL_EXCEPTION_APPROVED' if req.approve else 'KYB_MANUAL_EXCEPTION_REJECTED'
    record_audit(db, transaction_id=f"kyb-review-{parent.parent_id}-{uuid.uuid4().hex}",
        agent_id=f"parent:{parent.parent_id}", parent_id=parent.parent_id, org_id=parent.org_id,
        kind='parent_manual_exception_review',
        detail={'reason_code':review_reason, 'decision':'approved' if req.approve else 'rejected',
                'checks':checks, 'reviewer_note_sha256':hashlib.sha256(req.reviewer_note.encode()).hexdigest(),
                'trust_tier':parent.trust_tier, 'sandbox_only':True})
    db.commit()
    return {'parent_id':parent_id,'status':parent.status.value,'verification_method':'manual_admin_review_not_kyc'}

class AgentBasics(BaseModel):
    name: str = Field(min_length=2,max_length=200)
    agent_type: str = Field(min_length=2,max_length=80)
    purpose: str = Field(min_length=3,max_length=500)
    description: str = Field(default='',max_length=500)
    software_operator: str = Field(default='',max_length=200)

class AgentDelegation(BaseModel):
    capabilities: list[str] = Field(min_length=1,max_length=16)
    limit_minor_units: int = Field(gt=0,le=1_000_000_000)
    currency: str = Field(pattern=r'^[A-Z]{3}$')
    valid_days: int = Field(default=30,ge=1,le=365)

class HumanContact(BaseModel):
    name: str = Field(min_length=2,max_length=200)
    email: str = Field(min_length=5,max_length=200)
    phone: str = Field(min_length=7,max_length=30)
    alternate_email: str | None = None

class AgentCreate(BaseModel):
    basics: AgentBasics
    agent_public_key_pem: str = Field(description='Generated automatically by agent SDK; agent private key stays with agent')
    delegation: AgentDelegation
    escalation_contact: HumanContact
    accept_agent_security: bool

@router.post('/agents/register', status_code=201)
def agent_register(req:AgentCreate, authorization:str=Header(default=''), db:Session=Depends(get_db)):
    security.sandbox_only()
    if not authorization.lower().startswith('bearer '): raise HTTPException(401,'Parent access token required')
    parent=parent_auth(authorization[7:].strip(),db)
    if not req.accept_agent_security: raise HTTPException(422,'Agent security agreement required')
    acc=db.query(models.ParentAccount).filter_by(parent_pk=parent.id).one()
    now=int(datetime.now(timezone.utc).timestamp())
    deleg=legacy.DelegationDocument(delegation_id=str(uuid.uuid4()),parent_id=parent.parent_id,
          agent_public_key_fingerprint=crypto_utils.public_key_fingerprint(req.agent_public_key_pem),
          granted_capabilities=req.delegation.capabilities,payment_limit_minor_units=req.delegation.limit_minor_units,
          currency=req.delegation.currency,issued_at=now,expires_at=now+req.delegation.valid_days*86400)
    signature=security.sign_parent(acc.encrypted_signing_key,crypto_utils.canonical_json(deleg.model_dump(mode='json')))
    registered=legacy_register_agent(legacy.AgentRegistrationRequest(name=req.basics.name,
        agent_type=req.basics.agent_type,purpose=req.basics.purpose,public_key_pem=req.agent_public_key_pem,
        delegation=deleg,delegation_signature_b64=signature),db)
    db.add(models.AgentRegistration(agent_id=registered.agent_card.agent_id,parent_id=parent.parent_id,
        agent_description=req.basics.description,software_operator=req.basics.software_operator,
        approver_name=req.escalation_contact.name,approver_email=req.escalation_contact.email,
        approver_phone=req.escalation_contact.phone,alternate_email=req.escalation_contact.alternate_email))
    capture_acceptance(db,'agent',registered.agent_card.agent_id,('agent_security',))
    db.commit()
    return {'agent_card':registered.agent_card.model_dump(mode='json'),
            'credential_jwt':registered.credential_jwt,'credential_expires_at':registered.credential_expires_at,
            'escalation_contact_registered':True}

class ProviderCreate(BaseModel):
    legal_name: str = Field(min_length=2,max_length=200)
    registration_number: str = Field(min_length=3,max_length=80)
    contact_email: str = Field(min_length=5,max_length=200)
    representative_name: str = Field(min_length=2,max_length=200)
    payment_rail: str = Field(min_length=2,max_length=50)
    currencies: list[str] = Field(min_length=1,max_length=12)
    accept_terms: bool
    accept_privacy: bool
    accept_provider_participation: bool
    @model_validator(mode='after')
    def validate_acceptance(self):
        if not all([self.accept_terms,self.accept_privacy,self.accept_provider_participation]):
            raise ValueError('Institutional agreement acceptance is required')
        if '@' not in self.contact_email: raise ValueError('Institution email is invalid')
        if any(not re.fullmatch(r'[A-Z]{3}',c) for c in self.currencies):
            raise ValueError('Currency must be ISO-like three uppercase letters')
        return self

@router.post('/providers/register', status_code=201)
def provider_register(req:ProviderCreate, db:Session=Depends(get_db)):
    security.sandbox_only()
    provider=models.ProviderApplication(legal_name=req.legal_name,
         registration_number=req.registration_number,contact_email=req.contact_email,
         representative_name=req.representative_name,payment_rail=req.payment_rail,currencies=req.currencies)
    db.add(provider);db.flush()
    capture_acceptance(db,'provider',provider.provider_id,('terms','privacy','provider_participation'))
    db.commit()
    return {'provider_id':provider.provider_id,'status':provider.status}

@router.post('/admin/providers/{provider_id}/review')
def provider_review(provider_id:str, req:Approval,x_admin_api_key:str=Header(default=''),db:Session=Depends(get_db)):
    security.sandbox_only()
    admin_auth(x_admin_api_key)
    provider=db.query(models.ProviderApplication).filter_by(provider_id=provider_id).first()
    if not provider: raise HTTPException(404,'Provider not found')
    if provider.status!='pending_approval': raise HTTPException(409,'Provider already reviewed')
    checks={'identity_checked':req.identity_checked,'contact_checked':req.contact_checked,
            'representative_authority_checked':req.representative_authority_checked}
    if req.approve and not all(checks.values()): raise HTTPException(422,'Institution approval checklist incomplete')
    provider.status='approved' if req.approve else 'rejected'
    db.add(models.ManualApproval(subject_type='provider',subject_id=provider_id,
        decision=provider.status,checks=checks,reviewer_note=req.reviewer_note))
    db.commit()
    return {'provider_id':provider_id,'status':provider.status,'verification_method':'manual_admin_review'}

ALLOWED_FIELDS={'merchant','purpose','beneficiary_id','transaction_id','idempotency_key',
                'amount_minor_units','currency','agent_id','parent_id','mandate_id','merchant_category'}
class RequirementsCreate(BaseModel):
    required_context_fields: list[str] = Field(min_length=1,max_length=12)
    max_amount_minor_units: int = Field(gt=0)
    required_currency: str = Field(pattern=r'^[A-Z]{3}$')
    @field_validator('required_context_fields')
    @classmethod
    def fields_allowed(cls, fields):
        if not set(fields).issubset(ALLOWED_FIELDS) or len(set(fields))!=len(fields):
            raise ValueError('Unknown or repeated provider requirement field')
        return fields

@router.post('/admin/providers/{provider_id}/requirements',status_code=201)
def set_requirements(provider_id:str, req:RequirementsCreate,x_admin_api_key:str=Header(default=''), db:Session=Depends(get_db)):
    security.sandbox_only(); admin_auth(x_admin_api_key)
    provider=db.query(models.ProviderApplication).filter_by(provider_id=provider_id).first()
    if not provider or provider.status!='approved': raise HTTPException(409,'Provider not approved')
    if req.required_currency not in provider.currencies: raise HTTPException(422,'Provider does not support currency')
    previous=db.query(models.ProviderRequirements).filter_by(provider_id=provider_id).order_by(models.ProviderRequirements.version.desc()).first()
    if previous: previous.active=False
    current=models.ProviderRequirements(provider_id=provider_id,version=(previous.version+1) if previous else 1,
        required_context_fields=req.required_context_fields,max_amount_minor_units=req.max_amount_minor_units,
        required_currency=req.required_currency,active=True)
    db.add(current);db.commit()
    return {'provider_id':provider_id,'version':current.version,'active':True}

@router.get('/providers/{provider_id}/requirements')
def read_requirements(provider_id:str,db:Session=Depends(get_db)):
    provider=db.query(models.ProviderApplication).filter_by(provider_id=provider_id,status='approved').first()
    if not provider: raise HTTPException(404,'Provider not approved')
    r=db.query(models.ProviderRequirements).filter_by(provider_id=provider_id,active=True).first()
    if not r: raise HTTPException(404,'No active payment requirements')
    return {'provider_id':provider_id,'version':r.version,'required_context_fields':r.required_context_fields,
            'max_amount_minor_units':r.max_amount_minor_units,'required_currency':r.required_currency}

class ParentMandateCreate(BaseModel):
    agent_id: str
    max_per_transaction: int = Field(gt=0, le=1_000_000_000)
    max_daily_amount: int = Field(gt=0, le=2_000_000_000)
    currency: str = Field(pattern=r'^[A-Z]{3}$')
    allowed_merchants: list[str] = Field(min_length=1,max_length=50)
    require_review_above: int | None = Field(default=None, gt=0)
    valid_days: int = Field(default=30,ge=1,le=365)
    confirm_payment_authority: bool
    @model_validator(mode='after')
    def validate_mandate(self):
        if not self.confirm_payment_authority: raise ValueError('Explicit payer payment-consent confirmation required')
        if self.max_per_transaction>self.max_daily_amount: raise ValueError('Invalid mandate limits')
        return self

@router.post('/mandates/create',status_code=201)
def create_parent_mandate(req:ParentMandateCreate, authorization:str=Header(default=''),db:Session=Depends(get_db)):
    """Local sandbox: parent is explicitly the payer. NOT external bank consent."""
    security.sandbox_only()
    if not authorization.lower().startswith('bearer '): raise HTTPException(401,'Parent login required')
    parent=parent_auth(authorization[7:].strip(),db)
    agent=db.query(core.Agent).filter_by(agent_id=req.agent_id,parent_pk=parent.id,status=core.AgentStatus.ACTIVE).first()
    if not agent: raise HTTPException(404,'Active delegated agent not found under this parent')
    if req.currency!=agent.currency or req.max_per_transaction>agent.payment_limit_minor_units:
        raise HTTPException(422,'Mandate exceeds delegated currency or amount limit')
    from app.mandate_signing import canonical_payload_bytes, verify_mandate_signature
    acc=db.query(models.ParentAccount).filter_by(parent_pk=parent.id).one()
    dt=datetime.now(timezone.utc).replace(microsecond=0)
    row=core.UserPaymentMandate(mandate_id=str(uuid.uuid4()),user_id=parent.parent_id,
       agent_id=agent.agent_id,org_id=agent.org_id,max_per_transaction=req.max_per_transaction,
       max_daily_amount=req.max_daily_amount, currency=req.currency,allowed_merchants=req.allowed_merchants,
       allowed_categories=[],require_review_above=req.require_review_above,
       valid_from=dt,expires_at=dt+timedelta(days=req.valid_days),
       approval_reference='v36-sandbox-parent-consent',status=core.MandateStatus.ACTIVE)
    row.user_public_key_pem=parent.public_key_pem
    row.signing_key_id='v36-parent:'+parent.parent_id
    row.signing_algorithm='ed25519'
    row.signed_at=dt
    row.signature_b64=security.sign_parent(acc.encrypted_signing_key,canonical_payload_bytes(row))
    if not verify_mandate_signature(row).signature_valid:
        raise HTTPException(500,'Mandate signing check failed')
    db.add(row)
    from app.audit import record_audit
    record_audit(db,transaction_id='mandate:'+row.mandate_id,agent_id=agent.agent_id,
       parent_id=parent.parent_id,kind='user_mandate_created',
       detail={'mandate_id':row.mandate_id,'signed':True,'user_id':row.user_id,
               'payer_authority':'parent_sandbox_only','currency':row.currency},org_id=agent.org_id)
    db.commit()
    return {'mandate_id':row.mandate_id,'status':'active','signed':True,
       'payer_id':parent.parent_id,'message':'Paari local simulated payer consent; NOT provider consent or bank authorization'}


@router.post('/agents/{agent_id}/revoke')
def parent_revoke_agent(agent_id:str,authorization:str=Header(default=''),db:Session=Depends(get_db)):
    security.sandbox_only()
    if not authorization.lower().startswith('bearer '): raise HTTPException(401,'Parent login required')
    parent=parent_auth(authorization[7:].strip(),db)
    agent=db.query(core.Agent).filter_by(agent_id=agent_id,parent_pk=parent.id).first()
    if not agent: raise HTTPException(404,'Agent not found under this parent')
    if agent.status==core.AgentStatus.REVOKED: return {'agent_id':agent_id,'status':'revoked'}
    agent.status=core.AgentStatus.REVOKED
    db.query(core.Credential).filter_by(agent_pk=agent.id,revoked=False).update({'revoked':True})
    from app.audit import record_audit
    record_audit(db,transaction_id='agent_revoke:'+agent_id,agent_id=agent_id,
        parent_id=parent.parent_id,kind='agent_revoked_by_parent',
        detail={'agent_id':agent_id,'parent_id':parent.parent_id},org_id=agent.org_id)
    db.commit()
    return {'agent_id':agent_id,'status':'revoked'}

@router.post('/mandates/{mandate_id}/revoke')
def parent_revoke_mandate(mandate_id:str,authorization:str=Header(default=''),db:Session=Depends(get_db)):
    security.sandbox_only()
    if not authorization.lower().startswith('bearer '): raise HTTPException(401,'Parent login required')
    parent=parent_auth(authorization[7:].strip(),db)
    mandate=db.query(core.UserPaymentMandate).filter_by(mandate_id=mandate_id,user_id=parent.parent_id).first()
    if not mandate: raise HTTPException(404,'Mandate not found under this payer')
    if mandate.status==core.MandateStatus.REVOKED: return {'mandate_id':mandate_id,'status':'revoked'}
    mandate.status=core.MandateStatus.REVOKED
    mandate.revoked_at=datetime.now(timezone.utc)
    from app.audit import record_audit
    record_audit(db,transaction_id='mandate:'+mandate_id,agent_id=mandate.agent_id,
        parent_id=parent.parent_id,kind='user_mandate_revoked',
        detail={'mandate_id':mandate_id},org_id=mandate.org_id)
    db.commit()
    return {'mandate_id':mandate_id,'status':'revoked'}
