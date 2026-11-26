"""Requirements enforcement at intent, review, and execution boundaries.

This registry governs the existing local Razorpay-compatible adapter only:
registering a bank or a blockchain rail DOES NOT implement a payment adapter.
"""
from fastapi import HTTPException
from urllib.parse import urlparse
import os
from app.v36.models import ProviderApplication, ProviderRequirements, AgentRegistration

SUPPORTED_RAIL = 'razorpay_simulator'

def is_enrolled(db, agent_id: str) -> bool:
    return db.query(AgentRegistration).filter_by(agent_id=agent_id).first() is not None

def evaluate(db, provider_id:str | None, data:dict, *, require:bool=True):
    if not provider_id:
        if require: return False,'v3.6 agent request requires approved provider_id',None
        return True,'not applicable',None
    p=db.query(ProviderApplication).filter_by(provider_id=provider_id).first()
    if not p or p.status!='approved': return False,'Provider not approved or not found',None
    if p.payment_rail != SUPPORTED_RAIL:
        return False,'Provider has no compatible implemented execution adapter (only razorpay_simulator sandbox supported)',None
    # V3.6 local adapter gate: an approved registry entry must never route to a live API.
    url=os.getenv('RAZORPAY_API_BASE','')
    parsed=urlparse(url)
    if parsed.scheme not in ('http','https') or parsed.hostname not in ('127.0.0.1','localhost','::1'):
        return False,'v3.6 execution requires an explicitly configured loopback Razorpay simulator',None
    if os.getenv('RAZORPAY_KEY_ID','').startswith('rzp_live_'):
        return False,'Live provider keys forbidden for v3.6 sandbox enrollment',None
    requirements=db.query(ProviderRequirements).filter_by(provider_id=provider_id,active=True).first()
    if not requirements: return False,'Provider has no active approved requirements',None
    if data.get('currency') != requirements.required_currency:
        return False,'Provider requires different currency',requirements
    if int(data.get('amount_minor_units') or 0) > requirements.max_amount_minor_units:
        return False,'Provider amount cap exceeded',requirements
    for field in requirements.required_context_fields:
        if not data.get(field): return False,'Missing required provider context: '+field,requirements
    return True,'provider requirements satisfied',requirements

def validate_intent(db, agent_id, req, parent_id):
    """Return (ok, reason, policy_version) for enrolled v3.6 agents."""
    if not is_enrolled(db,agent_id): return True,'legacy agent',None
    data=req.model_dump(exclude_none=False)
    data['parent_id']=parent_id
    data['agent_id']=agent_id
    # A request model without an explicit provider field is a governance
    # failure (DENY), never an AttributeError/HTTP 500.
    ok,why,policy=evaluate(db,getattr(req,'provider_id',None),data)
    return ok,why,policy.version if policy else None

def recheck_execution(db,intent):
    if not is_enrolled(db,intent.agent_id): return
    from app import models
    agent=db.query(models.Agent).filter_by(agent_id=intent.agent_id).first()
    parent=db.query(models.ParentAuthority).filter_by(id=agent.parent_pk).first() if agent else None
    d={k:getattr(intent,k,None) for k in (
        'merchant','purpose','beneficiary_id','transaction_id','idempotency_key',
        'amount_minor_units','currency','agent_id','mandate_id','merchant_category')}
    d['parent_id']=parent.parent_id if parent else None
    ok,reason,policy=evaluate(db,intent.v36_provider_id,d)
    if not ok or policy.version != intent.v36_provider_policy_version:
        raise HTTPException(403,'Provider policy revalidation failed or changed: '+reason)
