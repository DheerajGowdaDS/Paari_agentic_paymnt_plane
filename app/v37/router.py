"""V3.7 sandbox enterprise portfolio risk, agent/data portability and evidence APIs.

These HTTP endpoints deliberately use existing v3.6 authenticated parents and
signed agent request-proof authentication. They do not mint bank permissions.
"""
import hashlib
import base64
import json
import jwt as pyjwt
from uuid import uuid4
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime, timedelta, timezone
from typing import Literal
import re
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app import models as core, crypto_utils, security as platform_security
from app.audit import record_audit
from app.database import get_db
from app.v36.router import parent_auth
from app.v36 import security as sandbox
from app.v37 import models as enterprise, risk

router = APIRouter(prefix='/v37/enterprise', tags=['v3.7-enterprise'])


def utcnow(): return datetime.now(timezone.utc)


def data_vault():
    # Independent sandbox encryption key; never reuse parent's signing vault key.
    raw=hashlib.sha256(sandbox.secret('PAARI_V37_DATA_ENCRYPTION_SECRET').encode()).digest()
    return Fernet(base64.urlsafe_b64encode(raw))


def _rsa_recipient_key(pem: str):
    try:
        key = serialization.load_pem_public_key(pem.encode('utf-8'))
    except Exception as exc:
        raise HTTPException(422, 'Destination key must be a valid PEM public key') from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise HTTPException(422, 'Encrypted portability requires an RSA public key of at least 2048 bits')
    return key


def _key_fingerprint(public_key) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def parent_session(auth: str, db):
    sandbox.sandbox_only()
    if not auth.lower().startswith('bearer '):
        raise HTTPException(401, 'Approved parent login required')
    return parent_auth(auth[7:].strip(), db)


def own_agent(db, parent, agent_id):
    agent = db.query(core.Agent).filter_by(agent_id=agent_id, parent_pk=parent.id).first()
    if not agent: raise HTTPException(404, 'Agent is not registered to this parent')
    return agent


def audit(db, parent, action, details, agent_id=None):
    record_audit(db, transaction_id=f'enterprise:{action}:{uuid4()}',
                 agent_id=agent_id or f"parent:{parent.parent_id}", parent_id=parent.parent_id, org_id=parent.org_id,
                 kind=action, detail=details)


class TreasuryLimits(BaseModel):
    currency: str = Field(pattern=r'^[A-Z]{3}$')
    daily_limit_minor_units: int = Field(gt=0, le=10**14)


@router.put('/treasury/policy')
def set_treasury_policy(req: TreasuryLimits, authorization: str = Header(default=''), db: Session = Depends(get_db)):
    parent = parent_session(authorization, db)
    policy = db.query(enterprise.TreasuryPolicy).filter_by(parent_id=parent.parent_id).with_for_update().first()
    if policy and policy.state == 'FROZEN':
        raise HTTPException(409, 'Frozen treasury must be reviewed and unfrozen by a Paari admin')
    if not policy:
        policy = enterprise.TreasuryPolicy(parent_id=parent.parent_id, currency=req.currency,
                          daily_limit_minor_units=req.daily_limit_minor_units)
        db.add(policy)
    else:
        policy.currency=req.currency
        policy.daily_limit_minor_units=req.daily_limit_minor_units
        policy.version += 1
        policy.updated_at=utcnow()
    db.flush()
    audit(db, parent, 'treasury_policy_updated', {'version':policy.version,'currency':policy.currency,
          'daily_limit_minor_units':policy.daily_limit_minor_units})
    db.commit()
    return {'parent_id':parent.parent_id,'state':policy.state,'version':policy.version,
            'daily_limit_minor_units':policy.daily_limit_minor_units,'currency':policy.currency}


@router.post('/treasury/freeze')
def freeze_treasury(authorization: str = Header(default=''), db: Session = Depends(get_db)):
    parent = parent_session(authorization, db)
    policy = db.query(enterprise.TreasuryPolicy).filter_by(parent_id=parent.parent_id).with_for_update().first()
    if not policy:
        raise HTTPException(409,'Set enterprise treasury limits before using emergency freeze')
    if policy.state != 'FROZEN':
        policy.state = 'FROZEN'; policy.version += 1; policy.updated_at=utcnow()
        audit(db,parent,'treasury_emergency_frozen',{'version':policy.version})
        db.commit()
    return {'parent_id':parent.parent_id,'state':policy.state,'blocks':'new intents, execution, data exports'}


@router.post('/admin/treasury/{parent_id}/unfreeze')
def unfreeze_treasury(parent_id: str, x_admin_api_key: str = Header(default=''), db: Session = Depends(get_db)):
    sandbox.sandbox_only()
    parent = db.query(core.ParentAuthority).filter_by(parent_id=parent_id,status=core.ParentStatus.ACTIVE).first()
    if not parent: raise HTTPException(404,'Active parent not found')
    platform_security.require_admin_org(x_admin_api_key,parent.org_id)
    policy = db.query(enterprise.TreasuryPolicy).filter_by(parent_id=parent_id).with_for_update().first()
    if not policy: raise HTTPException(404,'Treasury policy not found')
    policy.state='ACTIVE'; policy.version+=1; policy.updated_at=utcnow()
    audit(db,parent,'treasury_admin_unfrozen',{'version':policy.version})
    db.commit()
    return {'state':'ACTIVE','version':policy.version}


class AgentLimit(BaseModel):
    daily_limit_minor_units: int = Field(ge=0,le=10**14)
    suspended: bool = False
    hourly_request_limit: int = Field(default=20,ge=1,le=10000)


@router.put('/treasury/agents/{agent_id}/risk')
def configure_agent_risk(agent_id: str, req: AgentLimit, authorization: str = Header(default=''), db: Session=Depends(get_db)):
    parent=parent_session(authorization,db)
    own_agent(db,parent,agent_id)
    policy=db.query(enterprise.TreasuryPolicy).filter_by(parent_id=parent.parent_id).first()
    if not policy: raise HTTPException(409,'Create treasury policy before configuring agent risk')
    if policy.state != 'ACTIVE' and not req.suspended:
        raise HTTPException(409,'Cannot reactivate agent while treasury is frozen')
    row=db.query(enterprise.AgentRiskRule).filter_by(agent_id=agent_id).first()
    if not row:
        row=enterprise.AgentRiskRule(agent_id=agent_id,parent_id=parent.parent_id,
             daily_limit_minor_units=req.daily_limit_minor_units,suspended=req.suspended,
             hourly_request_limit=req.hourly_request_limit)
        db.add(row)
    else:
        row.daily_limit_minor_units=req.daily_limit_minor_units
        row.suspended=req.suspended
        row.hourly_request_limit=req.hourly_request_limit
        row.updated_at=utcnow()
    audit(db,parent,'enterprise_agent_risk_updated',{'agent_id':agent_id,'suspended':req.suspended,
          'daily_limit_minor_units':req.daily_limit_minor_units,
          'hourly_request_limit':req.hourly_request_limit},agent_id=agent_id)
    db.commit()
    return {'agent_id':agent_id,'suspended':row.suspended,
            'daily_limit_minor_units':row.daily_limit_minor_units,'hourly_request_limit':row.hourly_request_limit}


@router.get('/treasury/exposure')
def treasury_exposure(authorization: str=Header(default=''),db:Session=Depends(get_db)):
    parent=parent_session(authorization,db)
    from app.models import GovernanceDecision
    policy=db.query(enterprise.TreasuryPolicy).filter_by(parent_id=parent.parent_id).first()
    agents=db.query(core.Agent).filter_by(parent_pk=parent.id).all()
    since=datetime.combine(utcnow().date(),datetime.min.time(),tzinfo=timezone.utc)
    totals={}
    for agent in agents:
        reserved = risk._spent(db,[agent.agent_id],policy.currency,since) if policy else 0
        rule = db.query(enterprise.AgentRiskRule).filter_by(parent_id=parent.parent_id,agent_id=agent.agent_id).first()
        cap = rule.daily_limit_minor_units if rule else None
        totals[agent.agent_id]={
            'name':agent.name,'status':agent.status.value if hasattr(agent.status,'value') else str(agent.status),
            'risk_suspended':bool(rule.suspended) if rule else False,
            'reserved_minor_units':reserved,
            'daily_limit_minor_units':cap,
            'remaining_minor_units':max(0,cap-reserved) if cap is not None else None,
            'utilization_bps':min(10000,(reserved*10000)//cap) if cap else None,
            'hourly_request_limit':rule.hourly_request_limit if rule else None,
        }
    reserved_total=sum(x['reserved_minor_units'] for x in totals.values())
    return {'parent_id':parent.parent_id,'agent_count':len(agents),'treasury_policy':
            {'state':policy.state,'currency':policy.currency,'version':policy.version,
             'daily_limit_minor_units':policy.daily_limit_minor_units,
             'remaining_minor_units':max(0,policy.daily_limit_minor_units-reserved_total),
             'utilization_bps':min(10000,(reserved_total*10000)//policy.daily_limit_minor_units)} if policy else None,
            'reserved_total_minor_units':reserved_total,
            'agents':totals,'notes':'non-denied intents conservatively count as exposure, including in-flight/unknown payments; figures are reservations, not settled balances'}

@router.get('/treasury/signals')
def treasury_risk_signals(authorization:str=Header(default=''), db:Session=Depends(get_db)):
    """Deterministic early-warning signals scoped only to the authenticated parent.

    Signals are observations, not proof of fraud and not execution decisions.
    """
    parent=parent_session(authorization,db)
    agent_ids=[x.agent_id for x in db.query(core.Agent).filter_by(parent_pk=parent.id).all()]
    if not agent_ids:
        return {'parent_id':parent.parent_id,'signals':[],'window_minutes':60}
    since=utcnow()-timedelta(hours=1)
    recent=db.query(core.PaymentIntent).filter(
        core.PaymentIntent.agent_id.in_(agent_ids),core.PaymentIntent.created_at>=since,
        core.PaymentIntent.decision!=core.GovernanceDecision.DENY).all()
    per_agent={}; per_merchant={}
    for item in recent:
        per_agent[item.agent_id]=per_agent.get(item.agent_id,0)+1
        per_merchant.setdefault(item.merchant,set()).add(item.agent_id)
    signals=[]
    for aid,count in per_agent.items():
        if count>=10:
            signals.append({'type':'HIGH_AGENT_REQUEST_VELOCITY','agent_id':aid,
                            'request_count':count,'window_minutes':60})
    for merchant,agents in per_merchant.items():
        if len(agents)>=3:
            signals.append({'type':'MULTIPLE_AGENTS_SAME_MERCHANT','merchant':merchant,
                            'distinct_agent_count':len(agents),'window_minutes':60})
    # Cross-agent exact merchant/amount/currency patterns are advisory only.
    day_start=utcnow()-timedelta(hours=24)
    day_rows=db.query(core.PaymentIntent).filter(
        core.PaymentIntent.agent_id.in_(agent_ids), core.PaymentIntent.created_at>=day_start,
        core.PaymentIntent.decision!=core.GovernanceDecision.DENY).all()
    duplicate_groups={}
    for item in day_rows:
        key=(str(item.merchant or '').strip().casefold(),int(item.amount_minor_units),str(item.currency or '').upper())
        duplicate_groups.setdefault(key,set()).add(item.agent_id)
    for (merchant,amount,currency),participants in duplicate_groups.items():
        if len(participants)>=2:
            signals.append({'type':'POTENTIAL_DUPLICATE_PAYMENT_PATTERN','merchant':merchant,
                'amount_minor_units':amount,'currency':currency,'distinct_agent_count':len(participants),
                'window_hours':24,'advisory_only':True})
    return {'parent_id':parent.parent_id,'signals':signals,'window_minutes':60,'duplicate_pattern_window_hours':24,
            'note':'heuristic observations only; signals are not proof of fraud and do not replace governance/mandate decisions'}

# Data portability is restricted to a deliberately small, non-sensitive demo schema.
FIELDS = {
    'balances':frozenset({'account_alias','balance_minor_units','currency','as_of'}),
    'transactions':frozenset({'transaction_id','amount_minor_units','currency','merchant','date','category'}),
}


class DataSetCreate(BaseModel):
    kind: Literal['balances','transactions']
    records: list[dict] = Field(min_length=1,max_length=100)
    @model_validator(mode='after')
    def safe_fields(self):
        for row in self.records:
            if not row or not set(row).issubset(FIELDS[self.kind]):
                raise ValueError('Dataset accepts only the specified non-sensitive demo fields')
            if any(isinstance(value,(dict,list)) or len(str(value))>200 for value in row.values()):
                raise ValueError('Nested or oversized data field not permitted')
        return self


@router.get('/data/datasets')
def list_demo_datasets(authorization:str=Header(default=''),db:Session=Depends(get_db)):
    """Return only this parent's dataset metadata; encrypted records are never listed here."""
    parent=parent_session(authorization,db)
    rows=(db.query(enterprise.DataSet).filter_by(parent_id=parent.parent_id)
          .order_by(enterprise.DataSet.created_at.desc()).limit(500).all())
    return {'parent_id':parent.parent_id,'items':[{
        'dataset_id':r.dataset_id,'kind':r.kind,'fields':r.fields,
        'content_sha256':r.content_sha256,'created_at':r.created_at,
        'deleted_at':r.deleted_at,'status':'DELETED' if r.deleted_at else 'ACTIVE',
    } for r in rows]}


@router.post('/data/datasets',status_code=201)
def register_demo_dataset(req: DataSetCreate, authorization:str=Header(default=''),db:Session=Depends(get_db)):
    parent=parent_session(authorization,db)
    # Encrypt at rest using sandbox vault material; no raw account numbers, PAN, or secrets.
    payload=crypto_utils.canonical_json(req.records)
    row=enterprise.DataSet(parent_id=parent.parent_id,kind=req.kind,
          fields=sorted(set().union(*(set(x) for x in req.records))),
          encrypted_content=data_vault().encrypt(payload.encode()).decode(),
          content_sha256=hashlib.sha256(payload.encode()).hexdigest())
    db.add(row); db.flush()
    audit(db,parent,'demo_data_registered',{'dataset_id':row.dataset_id,'kind':req.kind,'sha256':row.content_sha256})
    db.commit()
    return {'dataset_id':row.dataset_id,'kind':row.kind,'available_fields':row.fields,
            'note':'Sandbox test data only; not bank-sourced data'}


@router.delete('/data/datasets/{dataset_id}')
def delete_demo_dataset(dataset_id:str,authorization:str=Header(default=''),db:Session=Depends(get_db)):
    parent=parent_session(authorization,db)
    dataset=db.query(enterprise.DataSet).filter_by(dataset_id=dataset_id,parent_id=parent.parent_id).first()
    if not dataset:raise HTTPException(404,'Dataset not found')
    if dataset.deleted_at is None:
        dataset.deleted_at=utcnow()
        dataset.encrypted_content=''  # Remove live ciphertext; backups require separate retention control.
        for row in db.query(enterprise.DataGrant).filter_by(dataset_id=dataset.dataset_id,
                                                 parent_id=parent.parent_id).all():
            if row.revoked_at is None:row.revoked_at=utcnow()
        audit(db,parent,'data_dataset_purged',{'dataset_id':dataset_id,
                  'original_content_sha256':dataset.content_sha256})
        db.commit()
    return {'dataset_id':dataset_id,'state':'DELETED','active_grants_revoked':True,
            'note':'Live ciphertext removed; external backups follow operator retention policy'}

class DataAccessGrant(BaseModel):
    dataset_id: str
    agent_id: str
    allowed_fields: list[str] = Field(min_length=1,max_length=10)
    purpose: str = Field(min_length=3,max_length=200)
    destination: str = Field(min_length=3,max_length=200)
    valid_hours: int = Field(default=24,ge=1,le=720)
    # Optional key is pinned at parent-consent time; agents cannot change it later.
    destination_public_key_pem: str | None = Field(default=None,max_length=8192)


@router.post('/data/grants',status_code=201)
def create_data_grant(req:DataAccessGrant,authorization:str=Header(default=''),db:Session=Depends(get_db)):
    parent=parent_session(authorization,db)
    agent=own_agent(db,parent,req.agent_id)
    if agent.status != core.AgentStatus.ACTIVE: raise HTTPException(403,'Agent inactive')
    data=db.query(enterprise.DataSet).filter_by(dataset_id=req.dataset_id,parent_id=parent.parent_id).first()
    if not data or data.deleted_at is not None: raise HTTPException(404,'Active dataset not found under parent')
    if not set(req.allowed_fields).issubset(set(data.fields)) or len(set(req.allowed_fields))!=len(req.allowed_fields):
        raise HTTPException(422,'Requested grant fields not available in dataset')
    destination_fingerprint = None
    if req.destination_public_key_pem:
        recipient_key = _rsa_recipient_key(req.destination_public_key_pem)
        destination_fingerprint = _key_fingerprint(recipient_key)
    row=enterprise.DataGrant(parent_id=parent.parent_id,agent_id=req.agent_id,
           dataset_id=req.dataset_id,allowed_fields=req.allowed_fields,purpose=req.purpose,
           destination=req.destination,destination_public_key_pem=req.destination_public_key_pem,
           destination_key_fingerprint=destination_fingerprint,
           expires_at=utcnow()+timedelta(hours=req.valid_hours))
    db.add(row);db.flush()
    audit(db,parent,'data_consent_granted',{'grant_id':row.grant_id,'agent_id':req.agent_id,
          'fields':req.allowed_fields,'destination':req.destination,'purpose':req.purpose,
          'destination_key_fingerprint':destination_fingerprint,
          'encrypted_portability_enabled':bool(destination_fingerprint)},agent_id=req.agent_id)
    db.commit()
    return {'grant_id':row.grant_id,'expires_at':row.expires_at,'status':'ACTIVE',
            'encrypted_portability_enabled':bool(destination_fingerprint),
            'destination_key_fingerprint':destination_fingerprint}


@router.get('/data/grants')
def list_data_grants(authorization:str=Header(default=''),db:Session=Depends(get_db)):
    parent=parent_session(authorization,db)
    rows=db.query(enterprise.DataGrant).filter_by(parent_id=parent.parent_id).order_by(enterprise.DataGrant.created_at.desc()).limit(500).all()
    now=utcnow()
    return {'parent_id':parent.parent_id,'items':[{
        'grant_id':r.grant_id,'agent_id':r.agent_id,'dataset_id':r.dataset_id,
        'allowed_fields':r.allowed_fields,'purpose':r.purpose,'destination':r.destination,
        'expires_at':r.expires_at,'revoked_at':r.revoked_at,
        'status':'REVOKED' if r.revoked_at else ('EXPIRED' if r.expires_at<=now else 'ACTIVE'),
        'encrypted_portability_enabled':bool(r.destination_key_fingerprint),
        'destination_key_fingerprint':r.destination_key_fingerprint,
    } for r in rows]}


@router.get('/data/exports')
def list_data_exports(authorization:str=Header(default=''),db:Session=Depends(get_db)):
    parent=parent_session(authorization,db)
    rows=(db.query(enterprise.DataExportLog).join(enterprise.DataGrant,
        enterprise.DataGrant.grant_id==enterprise.DataExportLog.grant_id)
        .filter(enterprise.DataGrant.parent_id==parent.parent_id)
        .order_by(enterprise.DataExportLog.exported_at.desc()).limit(500).all())
    return {'parent_id':parent.parent_id,'items':[{
        'export_id':r.export_id,'grant_id':r.grant_id,'agent_id':r.agent_id,
        'destination':r.destination,'fields':r.fields,'payload_sha256':r.payload_sha256,
        'exported_at':r.exported_at,
    } for r in rows]}


@router.post('/data/grants/{grant_id}/revoke')
def revoke_data_grant(grant_id:str,authorization:str=Header(default=''),db:Session=Depends(get_db)):
    parent=parent_session(authorization,db)
    row=db.query(enterprise.DataGrant).filter_by(grant_id=grant_id,parent_id=parent.parent_id).first()
    if not row:raise HTTPException(404,'Grant not found')
    if row.revoked_at is None:
        row.revoked_at=utcnow()
        audit(db,parent,'data_consent_revoked',{'grant_id':grant_id},agent_id=row.agent_id)
        db.commit()
    return {'grant_id':grant_id,'status':'REVOKED'}


class ExportDataRequest(BaseModel):
    grant_id: str
    purpose: str
    destination: str
    session_token: str | None = None


@router.post('/data/export')
def export_scoped_data(req:ExportDataRequest, request:Request,
                       authorization:str=Header(default=''),x_paari_proof:str=Header(default=''),
                       db:Session=Depends(get_db)):
    sandbox.sandbox_only()
    # Uses same agent session and proof-of-possession as payment requests.
    from app.routers.payments import _authenticate, _resolve_session_token, _key_for_session
    token=_resolve_session_token(req.session_token,authorization)
    if not x_paari_proof:
        raise HTTPException(401,'Agent data export requires signed request proof')
    agent, claims = _authenticate(db,token,request=request,proof=x_paari_proof)
    # Legacy v3.6 enrolled agents do not automatically require proof on every
    # endpoint. Data exports are always PoP-protected, regardless of that mode.
    import os
    if claims.get('protocol_version') != '1.0' and os.getenv('PAARI_REQUIRE_REQUEST_PROOF') != '1':
        try:
            public_key,_=_key_for_session(agent,claims)
            platform_security.verify_request_proof(x_paari_proof,token,agent_id=agent.agent_id,
                  public_key_pem=public_key,method=request.method,path=request.url.path,
                  db=db,org_id=agent.org_id)
        except pyjwt.PyJWTError as exc:
            raise HTTPException(401,'Invalid or replayed agent data export proof') from exc
    grant=db.query(enterprise.DataGrant).filter_by(grant_id=req.grant_id,agent_id=agent.agent_id).first()
    if not grant or grant.revoked_at is not None or grant.expires_at <= utcnow():
        raise HTTPException(403,'Data grant absent, expired or revoked')
    if req.purpose!=grant.purpose or req.destination!=grant.destination:
        raise HTTPException(403,'Export purpose or destination outside consent')
    parent=db.query(core.ParentAuthority).filter_by(parent_id=grant.parent_id,
                                                     id=agent.parent_pk,status=core.ParentStatus.ACTIVE).first()
    if not parent: raise HTTPException(403,'Parent consent binding changed or revoked')
    policy=db.query(enterprise.TreasuryPolicy).filter_by(parent_id=parent.parent_id).first()
    restriction=db.query(enterprise.AgentRiskRule).filter_by(parent_id=parent.parent_id,agent_id=agent.agent_id).first()
    if (policy and policy.state!='ACTIVE') or (restriction and restriction.suspended):
        raise HTTPException(403,'Enterprise or agent security freeze active')
    dataset=db.query(enterprise.DataSet).filter_by(dataset_id=grant.dataset_id,parent_id=parent.parent_id).first()
    if not dataset or dataset.deleted_at is not None: raise HTTPException(403,'Dataset missing or deleted')
    data=json.loads(data_vault().decrypt(dataset.encrypted_content.encode()).decode())
    records=[{f:item[f] for f in grant.allowed_fields if f in item} for item in data]
    payload={'schema':'paari.sandbox.data-portability.v1','agent_id':agent.agent_id,
            'grant_id':grant.grant_id,'purpose':req.purpose,'destination':req.destination,
            'dataset_id':dataset.dataset_id,'fields':grant.allowed_fields,'records':records,
            'issued_at':utcnow().isoformat()}
    digest=hashlib.sha256(crypto_utils.canonical_json(payload).encode()).hexdigest()
    evidence=enterprise.DataExportLog(grant_id=grant.grant_id,agent_id=agent.agent_id,
                    destination=req.destination,fields=grant.allowed_fields,payload_sha256=digest)
    db.add(evidence);db.flush()
    payload['export_id']=evidence.export_id
    payload['payload_sha256']=digest
    # Signature protects returned payload integrity; trust in issuer key remains out-of-band.
    payload['issuer_public_key_pem']=platform_security.paari_public_key_pem()
    payload['issuer_signature_b64']=platform_security.sign_agent_card(payload)
    audit(db,parent,'data_export_approved',{'export_id':evidence.export_id,'grant_id':grant.grant_id,
          'payload_sha256':digest,'destination':req.destination},agent_id=agent.agent_id)
    db.commit()
    return payload


@router.post('/data/portability/export')
def export_encrypted_portability(req:ExportDataRequest, request:Request,
                       authorization:str=Header(default=''),x_paari_proof:str=Header(default=''),
                       db:Session=Depends(get_db)):
    """Export consented fields encrypted to the recipient key pinned at grant time."""
    sandbox.sandbox_only()
    from app.routers.payments import _authenticate, _resolve_session_token, _key_for_session
    token=_resolve_session_token(req.session_token,authorization)
    if not x_paari_proof:
        raise HTTPException(401,'Encrypted data export requires signed request proof')
    agent, claims = _authenticate(db,token,request=request,proof=x_paari_proof)
    import os
    if claims.get('protocol_version') != '1.0' and os.getenv('PAARI_REQUIRE_REQUEST_PROOF') != '1':
        try:
            public_key,_=_key_for_session(agent,claims)
            platform_security.verify_request_proof(x_paari_proof,token,agent_id=agent.agent_id,
                  public_key_pem=public_key,method=request.method,path=request.url.path,
                  db=db,org_id=agent.org_id)
        except pyjwt.PyJWTError as exc:
            raise HTTPException(401,'Invalid or replayed encrypted data export proof') from exc
    grant=(db.query(enterprise.DataGrant).filter_by(grant_id=req.grant_id,agent_id=agent.agent_id)
           .with_for_update().first())
    if not grant or grant.revoked_at is not None or grant.expires_at<=utcnow():
        raise HTTPException(403,'Data grant absent, expired or revoked')
    if req.purpose!=grant.purpose or req.destination!=grant.destination:
        raise HTTPException(403,'Export purpose or destination outside consent')
    if not grant.destination_public_key_pem or not grant.destination_key_fingerprint:
        raise HTTPException(409,'This grant has no destination encryption key pinned at consent time')
    recipient=_rsa_recipient_key(grant.destination_public_key_pem)
    if _key_fingerprint(recipient)!=grant.destination_key_fingerprint:
        raise HTTPException(403,'Pinned destination key fingerprint changed')
    parent=db.query(core.ParentAuthority).filter_by(parent_id=grant.parent_id,
        id=agent.parent_pk,status=core.ParentStatus.ACTIVE).first()
    if not parent: raise HTTPException(403,'Parent consent binding changed or revoked')
    policy=db.query(enterprise.TreasuryPolicy).filter_by(parent_id=parent.parent_id).first()
    restriction=db.query(enterprise.AgentRiskRule).filter_by(parent_id=parent.parent_id,agent_id=agent.agent_id).first()
    if (policy and policy.state!='ACTIVE') or (restriction and restriction.suspended):
        raise HTTPException(403,'Enterprise or agent security freeze active')
    dataset=db.query(enterprise.DataSet).filter_by(dataset_id=grant.dataset_id,parent_id=parent.parent_id).first()
    if not dataset or dataset.deleted_at is not None: raise HTTPException(403,'Dataset missing or deleted')
    records=json.loads(data_vault().decrypt(dataset.encrypted_content.encode()).decode())
    minimized=[{field:item[field] for field in grant.allowed_fields if field in item} for item in records]
    export_id=str(uuid4())
    issued=utcnow().isoformat()
    payload={'schema':'paari.encrypted-data-portability.v1','export_id':export_id,
        'agent_id':agent.agent_id,'grant_id':grant.grant_id,'dataset_id':dataset.dataset_id,
        'purpose':req.purpose,'destination':req.destination,'fields':grant.allowed_fields,
        'records':minimized,'issued_at':issued}
    plaintext=crypto_utils.canonical_json(payload).encode('utf-8')
    digest=hashlib.sha256(plaintext).hexdigest()
    aad_obj={'schema':'paari.encrypted-data-portability-envelope.v1','export_id':export_id,
        'destination':grant.destination,'recipient_key_fingerprint':grant.destination_key_fingerprint,
        'content_encryption':'AES-256-GCM','key_encryption':'RSA-OAEP-SHA256',
        'payload_sha256':digest,'issued_at':issued}
    aad=crypto_utils.canonical_json(aad_obj).encode('utf-8')
    cek=__import__('secrets').token_bytes(32)
    nonce=__import__('secrets').token_bytes(12)
    ciphertext=AESGCM(cek).encrypt(nonce,plaintext,aad)
    wrapped_key=recipient.encrypt(cek,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),label=None))
    row=enterprise.DataExportLog(grant_id=grant.grant_id,agent_id=agent.agent_id,
        destination=grant.destination,fields=grant.allowed_fields,payload_sha256=digest,export_id=export_id)
    db.add(row);db.flush()
    envelope={**aad_obj,'export_id':row.export_id,'associated_data_b64':_b64(aad),
        'nonce_b64':_b64(nonce),'encrypted_key_b64':_b64(wrapped_key),
        'ciphertext_b64':_b64(ciphertext),'issuer_public_key_pem':platform_security.paari_public_key_pem()}
    envelope['issuer_signature_b64']=platform_security.sign_agent_card(envelope)
    audit(db,parent,'encrypted_data_portability_exported',{
        'export_id':row.export_id,'grant_id':grant.grant_id,'destination':grant.destination,
        'destination_key_fingerprint':grant.destination_key_fingerprint,
        'payload_sha256':digest,'fields':grant.allowed_fields},agent_id=agent.agent_id)
    db.commit()
    return envelope


class RailSimulationRequest(BaseModel):
    intent_id: str = Field(min_length=1,max_length=64)
    rail: Literal['open_banking','stablecoin']
    sandbox_consent_reference: str | None = Field(default=None,min_length=8,max_length=128)
    network: str | None = Field(default=None,min_length=3,max_length=48)
    chain_id: int | None = Field(default=None,gt=0)
    asset_symbol: str | None = Field(default=None,min_length=2,max_length=16)
    destination_wallet: str | None = Field(default=None,min_length=10,max_length=128)


@router.get('/rails/capabilities')
def rail_capabilities():
    return {'execution_mode':'SIMULATION_ONLY','live_submission_enabled':False,'items':[
        {'rail':'open_banking','label':'Open banking / account-to-account','simulation_available':True,
         'external_adapter':'NOT_CONFIGURED','consent_provider_validation':False,'live_payment_initiation':False,
         'requirements':['regulated provider/TPP contract','verified customer consent','bank payment-initiation API','signed webhook and reconciliation']},
        {'rail':'stablecoin','label':'Stablecoin test-network route','simulation_available':True,
         'external_adapter':'NOT_CONFIGURED','wallet_signer':'NOT_CONFIGURED','rpc_connectivity':False,
         'broadcast_enabled':False,
         'requirements':['approved token and chain allowlist','managed wallet/custody signing','RPC provider and transaction broadcast','screening, confirmations and finality monitoring']},
    ],'note':'The included route preview is not an open-banking payment initiation, blockchain broadcast, settlement or testnet transaction.'}


@router.post('/rails/simulate',status_code=201)
def simulate_payment_rail(req:RailSimulationRequest,authorization:str=Header(default=''),db:Session=Depends(get_db)):
    """Create an auditable route preview for an already-allowed bounded intent."""
    parent=parent_session(authorization,db)
    if req.rail=='open_banking':
        if not req.sandbox_consent_reference or not req.sandbox_consent_reference.lower().startswith('sbx-'):
            raise HTTPException(422,'Open-banking route preview requires a synthetic sbx- consent reference')
        safe={'consent_reference_sha256':hashlib.sha256(req.sandbox_consent_reference.encode()).hexdigest(),
              'consent_verified_by_bank':False,'payment_initiation_submitted':False}
        status='OPEN_BANKING_ROUTE_PREVIEW_ONLY'
    else:
        if not req.network or not req.chain_id or not req.asset_symbol or not req.destination_wallet:
            raise HTTPException(422,'Stablecoin preview requires network, chain_id, asset_symbol and destination_wallet')
        if not re.fullmatch(r'0x[a-fA-F0-9]{40}',req.destination_wallet):
            raise HTTPException(422,'Stablecoin sandbox preview accepts an EVM-format public wallet address only')
        safe={'network':req.network.strip(),'chain_id':req.chain_id,'asset_symbol':req.asset_symbol.upper(),
              'destination_wallet_fingerprint':hashlib.sha256(req.destination_wallet.lower().encode()).hexdigest(),
              'wallet_screening_performed':False,'transaction_broadcast':False,'chain_finality_confirmed':False}
        status='STABLECOIN_TEST_NETWORK_ROUTE_PREVIEW_ONLY'
    agent_ids=[a.agent_id for a in db.query(core.Agent).filter_by(parent_pk=parent.id).all()]
    intent=(db.query(core.PaymentIntent).filter(core.PaymentIntent.intent_id==req.intent_id,
             core.PaymentIntent.agent_id.in_(agent_ids)).with_for_update().first())
    if not intent or intent.decision!=core.GovernanceDecision.ALLOW:
        raise HTTPException(404,'An allowed payment intent under this parent is required')
    bound=db.query(core.BoundedAuthorization).filter_by(intent_id=intent.intent_id,agent_id=intent.agent_id).first()
    if not bound or bound.usage_count>=bound.max_usage or bound.expires_at<=utcnow():
        raise HTTPException(409,'A current unused bounded authorization is required for rail preview')
    txn=db.query(core.ProviderTransaction).filter_by(intent_id=intent.intent_id,org_id=intent.org_id).first()
    if not txn or txn.state!='AUTHORIZED':
        raise HTTPException(409,'Rail preview is available only before provider submission')
    digest=hashlib.sha256(crypto_utils.canonical_json({'intent_id':intent.intent_id,'rail':req.rail,'context':safe}).encode()).hexdigest()
    existing=db.query(enterprise.RailSimulation).filter_by(intent_id=intent.intent_id,rail=req.rail).first()
    if existing:
        if existing.request_digest!=digest:
            raise HTTPException(409,'A different route preview already exists for this intent and rail')
        return {'simulation_id':existing.simulation_id,'intent_id':intent.intent_id,'rail':req.rail,
            'status':existing.status,'safe_context':existing.safe_context,'authorization_consumed':False,
            'external_submission':False,'settlement_confirmed':False,'idempotent_replay':True}
    row=enterprise.RailSimulation(parent_id=parent.parent_id,org_id=intent.org_id,intent_id=intent.intent_id,
        rail=req.rail,status=status,request_digest=digest,safe_context=safe)
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        # The database uniqueness constraint is the final idempotency guard if
        # two route-preview requests race after the optimistic lookup above.
        db.rollback()
        raced=db.query(enterprise.RailSimulation).filter_by(intent_id=req.intent_id,rail=req.rail).first()
        if raced and raced.request_digest==digest:
            return {'simulation_id':raced.simulation_id,'intent_id':raced.intent_id,'rail':raced.rail,
                'status':raced.status,'safe_context':raced.safe_context,'authorization_consumed':False,
                'external_submission':False,'settlement_confirmed':False,'idempotent_replay':True}
        raise HTTPException(409,'A route preview already exists for this intent and rail')
    audit(db,parent,'payment_rail_route_previewed',{'simulation_id':row.simulation_id,'intent_id':intent.intent_id,
        'rail':req.rail,'status':status,'external_submission':False,'settlement_confirmed':False},agent_id=intent.agent_id)
    db.commit()
    return {'simulation_id':row.simulation_id,'intent_id':intent.intent_id,'rail':req.rail,
        'status':status,'safe_context':safe,'authorization_consumed':False,
        'external_submission':False,'settlement_confirmed':False,'idempotent_replay':False}


@router.get('/rails/simulations')
def list_rail_simulations(authorization:str=Header(default=''),db:Session=Depends(get_db)):
    parent=parent_session(authorization,db)
    rows=db.query(enterprise.RailSimulation).filter_by(parent_id=parent.parent_id).order_by(enterprise.RailSimulation.created_at.desc()).limit(500).all()
    return {'parent_id':parent.parent_id,'items':[{'simulation_id':r.simulation_id,'intent_id':r.intent_id,
        'rail':r.rail,'status':r.status,'safe_context':r.safe_context,'created_at':r.created_at,
        'external_submission':False,'settlement_confirmed':False} for r in rows]}


class PortabilityStage(BaseModel):
    package: dict
    confirm_identity_only: bool


@router.post('/portability/stage',status_code=201)
def stage_migration(req:PortabilityStage,authorization:str=Header(default=''),db:Session=Depends(get_db)):
    parent=parent_session(authorization,db)
    if not req.confirm_identity_only:raise HTTPException(422,'Destination acknowledges no payment authority transfers')
    from app.control_plane.router import _trusted_portability_issuers
    from app.portability import validate_agent_portability_package,PortabilityValidationError
    try:
        verified=validate_agent_portability_package(req.package,trusted_issuer_keys=_trusted_portability_issuers())
    except PortabilityValidationError as ex:
        raise HTTPException(422,'Invalid signed portability package: '+str(ex)) from ex
    if str(verified.get('agent_status_at_export','')).lower() not in {'active'}:
        raise HTTPException(403,'Source agent was not active at export')
    card=req.package.get('agent_card') or {}
    claims=(req.package.get('delegation') or {}).get('claims') or {}
    try:
        expires_at=int(claims.get('expires_at',0))
        valid_until=datetime.fromisoformat(str(card.get('valid_until','')).replace('Z','+00:00'))
    except (ValueError,TypeError) as exc:
        raise HTTPException(422,'Invalid signed agent/delegation expiry') from exc
    if valid_until.tzinfo is None:
        raise HTTPException(422,'Source Agent Card expiry lacks timezone')
    if expires_at<=int(utcnow().timestamp()) or valid_until<=utcnow():
        raise HTTPException(403,'Source agent card or delegation expired')
    visible=db.query(core.Agent).filter_by(agent_id=verified['agent_id']).first()
    if visible and visible.status!=core.AgentStatus.ACTIVE:
        raise HTTPException(403,'Known source agent was revoked or inactive')
    content=crypto_utils.canonical_json(req.package)
    digest=hashlib.sha256(content.encode()).hexdigest()
    if db.query(enterprise.AgentMigration).filter_by(package_digest=digest).first():
        raise HTTPException(409,'Package already staged (replay detected)')
    source=req.package.get('agent_key_binding') or {}
    row=enterprise.AgentMigration(package_digest=digest,source_agent_id=str(verified['agent_id']),
        source_parent_id=str(verified['parent_id']),source_key_fingerprint=source['fingerprint'],
        destination_parent_id=parent.parent_id,verified_evidence={'source_signatures':verified['signatures_verified'],
        'issuer_key_id':req.package['issuer']['key_id'],'authority_transferred':False})
    db.add(row);db.flush()
    audit(db,parent,'agent_portability_identity_staged',{'migration_id':row.migration_id,
          'source_agent_id':row.source_agent_id,'package_digest':digest})
    db.commit()
    return {'migration_id':row.migration_id,'state':'STAGED','source_agent_id':row.source_agent_id,
            'authority_transferred':False,'next_step':'Register fresh destination agent and fresh payment mandate'}


class MigrationActivate(BaseModel):
    destination_agent_id: str
    acknowledge_new_delegation: bool


@router.post('/portability/{migration_id}/activate')
def activate_migration(migration_id:str,req:MigrationActivate,authorization:str=Header(default=''),db:Session=Depends(get_db)):
    parent=parent_session(authorization,db)
    row=db.query(enterprise.AgentMigration).filter_by(migration_id=migration_id,
                              destination_parent_id=parent.parent_id).with_for_update().first()
    if not row:raise HTTPException(404,'Destination migration not found')
    if row.state!='STAGED':raise HTTPException(409,'Migration already used')
    if not req.acknowledge_new_delegation:raise HTTPException(422,'New parent delegation confirmation required')
    if row.created_at+timedelta(hours=24) <= utcnow():raise HTTPException(403,'Staged migration expired')
    agent=own_agent(db,parent,req.destination_agent_id)
    if (agent.status!=core.AgentStatus.ACTIVE or agent.agent_id==row.source_agent_id
            or agent.created_at < row.created_at):
        raise HTTPException(403,'Fresh active destination agent registration after staging required')
    if crypto_utils.public_key_fingerprint(agent.public_key_pem).lower()==row.source_key_fingerprint.lower():
        raise HTTPException(403,'Fresh destination agent key required')
    from app.v36.models import AgentRegistration
    if not db.query(AgentRegistration).filter_by(agent_id=agent.agent_id).first():
        raise HTTPException(403,'Destination agent must pass four-part v3.6 onboarding')
    if db.query(enterprise.AgentMigration).filter_by(destination_agent_id=agent.agent_id).first():
        raise HTTPException(409,'Destination agent already linked to another migration')
    # Check original source remains active if source is visible to this Paari instance.
    source=db.query(core.Agent).filter_by(agent_id=row.source_agent_id).first()
    if source and source.status!=core.AgentStatus.ACTIVE:
        raise HTTPException(403,'Source agent was revoked after export')
    row.destination_agent_id=agent.agent_id;row.state='IDENTITY_LINKED';row.activated_at=utcnow()
    audit(db,parent,'agent_portability_identity_linked',{'migration_id':row.migration_id,
           'destination_agent_id':agent.agent_id,'authority_transferred':False},agent_id=agent.agent_id)
    db.commit()
    return {'state':row.state,'destination_agent_id':agent.agent_id,'source_agent_id':row.source_agent_id,
            'authority_transferred':False,'mandates_transferred':False,'data_grants_transferred':False,
            'message':'Identity link only. New parent mandate and resource/data grants required.'}
