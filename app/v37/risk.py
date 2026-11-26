"""Database-backed enterprise risk gates for parent-owned treasury agent portfolios.

Daily portfolio risk counts all non-denied intents as reserved exposure, not
just settled payments. This errs on the side of blocking; canceled/unknown
intents need safe reconciliation before the budget can be released. The
PostgreSQL lock on the parent policy serializes compliant intent admissions.
"""
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException
from sqlalchemy import func
from app import models as core
from app.v37.models import TreasuryPolicy, AgentRiskRule


def now(): return datetime.now(timezone.utc)


def parent_scope(db, agent):
    parent = db.query(core.ParentAuthority).filter_by(id=agent.parent_pk).first()
    return parent.parent_id if parent else None


def _spent(db, agent_ids, currency, start, exclude_intent_id=None):
    if not agent_ids:
        return 0
    q = db.query(func.coalesce(func.sum(core.PaymentIntent.amount_minor_units), 0)).filter(
        core.PaymentIntent.agent_id.in_(agent_ids),
        core.PaymentIntent.currency == currency,
        core.PaymentIntent.created_at >= start,
        core.PaymentIntent.decision != core.GovernanceDecision.DENY,
    )
    if exclude_intent_id:
        q = q.filter(core.PaymentIntent.intent_id != exclude_intent_id)
    return int(q.scalar() or 0)


def evaluate(db, agent, amount_minor_units, currency, *, existing_intent_id=None, reserve=True):
    """Return (ok, reason). Only activates when parent opts in to portfolio policy.

    Lock is held through payment intent insertion/commit for PG concurrency safety.
    A read-only execution check includes the current authorized intent but
    excludes it from additional exposure; it never reserves a second time.
    """
    pid = parent_scope(db, agent)
    rule = db.query(TreasuryPolicy).filter_by(parent_id=pid).with_for_update().first()
    if not rule:
        return True, 'no enterprise treasury policy configured'
    if rule.state != 'ACTIVE':
        return False, 'Enterprise emergency freeze is active'
    if rule.currency != currency:
        return False, 'Treasury policy currency mismatch'
    agent_rule = db.query(AgentRiskRule).filter_by(parent_id=pid, agent_id=agent.agent_id).first()
    if agent_rule and agent_rule.suspended:
        return False, 'Agent suspended by enterprise risk control'
    hour_start=now()-timedelta(hours=1)
    if agent_rule and reserve and not existing_intent_id:
        count=db.query(func.count(core.PaymentIntent.id)).filter(
            core.PaymentIntent.agent_id==agent.agent_id,
            core.PaymentIntent.created_at>=hour_start,
            core.PaymentIntent.decision!=core.GovernanceDecision.DENY).scalar() or 0
        if count >= agent_rule.hourly_request_limit:
            return False, 'Agent hourly authorization-request velocity limit exceeded'
    start = datetime.combine(now().date(), datetime.min.time(), tzinfo=timezone.utc)
    agents = [a.agent_id for a in db.query(core.Agent).filter_by(parent_pk=agent.parent_pk).all()]
    total = _spent(db, agents, currency, start, exclude_intent_id=existing_intent_id)
    individual = _spent(db, [agent.agent_id], currency, start, exclude_intent_id=existing_intent_id)
    addition = amount_minor_units if reserve else 0
    if total + addition > rule.daily_limit_minor_units:
        return False, 'Shared treasury daily spending/reservation limit exceeded'
    if agent_rule and individual + addition > agent_rule.daily_limit_minor_units:
        return False, 'Agent daily spending/reservation limit exceeded'
    return True, 'Enterprise treasury risk checks passed'


def enforce_execution(db, intent):
    if intent is None:
        raise HTTPException(403, 'Missing payment intent for enterprise risk revalidation')
    agent = db.query(core.Agent).filter_by(agent_id=intent.agent_id).first()
    if not agent:
        raise HTTPException(403, 'Missing agent for enterprise risk revalidation')
    ok, reason = evaluate(db, agent, intent.amount_minor_units, intent.currency,
                          existing_intent_id=intent.intent_id, reserve=True)
    if not ok:
        raise HTTPException(403, 'Enterprise risk revalidation failed: ' + reason)
