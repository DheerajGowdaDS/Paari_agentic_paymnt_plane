"""Database-backed institutional policy evaluation used by the payment gateway."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os

from sqlalchemy.orm import Session

from app import crypto_utils, models
from app.control_plane.engine import ControlFacts, Disposition, Evaluation, PolicyThresholds, calculate_rule_risk_score_bps, evaluate


@dataclass(frozen=True)
class RuntimeDecision:
    policy_name: str
    policy_version: str
    principal_id: str | None
    resource_id: str | None
    evaluation: Evaluation
    transaction_digest: str


def _digest(*, org_id: str, agent_id: str, mandate_id: str | None, transaction_id: str,
            merchant: str, amount_minor: int, currency: str, action: str, purpose: str,
            merchant_category: str | None) -> str:
    payload = {"org_id": org_id, "agent_id": agent_id, "mandate_id": mandate_id,
               "transaction_id": transaction_id, "merchant": merchant,
               "amount_minor_units": amount_minor, "currency": currency,
               "action": action, "purpose": purpose, "merchant_category": merchant_category}
    return hashlib.sha256(crypto_utils.canonical_json(payload).encode("utf-8")).hexdigest()


def _deny(policy_name: str, policy_version: str, principal_id: str | None, resource_id: str | None,
          digest: str, code: str) -> RuntimeDecision:
    return RuntimeDecision(policy_name, policy_version, principal_id, resource_id,
                           Evaluation(Disposition.DENY, (code,), None, None), digest)


def _has_grant(db: Session, *, org_id: str, resource_id: str, subject_type: str,
               subject_id: str, now: datetime) -> bool:
    rows = db.query(models.ResourceAccessGrant).filter_by(
        org_id=org_id, resource_id=resource_id, subject_type=subject_type,
        subject_id=subject_id, status="ACTIVE",
    ).all()
    return any(row.valid_from <= now < row.valid_until and "payment:execute" in (row.actions or []) for row in rows)


def evaluate_payment_control_plane(db: Session, *, agent: models.Agent, mandate: models.UserPaymentMandate,
                                   req, now: datetime, intents_in_last_minute: int) -> RuntimeDecision:
    """Resolve facts from Paari's own stores and evaluate the active tenant policy.

    No trust booleans, risk scores, resource IDs or policy version are accepted
    from the agent's request body. A missing or ambiguous required object denies.
    """
    digest = _digest(org_id=agent.org_id, agent_id=agent.agent_id, mandate_id=mandate.mandate_id,
                    transaction_id=req.transaction_id, merchant=req.merchant,
                    amount_minor=req.amount_minor_units, currency=req.currency,
                    action=req.action, purpose=req.purpose, merchant_category=req.merchant_category)
    policy = db.query(models.PolicyBundle).filter_by(
        org_id=agent.org_id, policy_name="payment_execution", status="ACTIVE").first()
    if not policy:
        return _deny("payment_execution", "missing", None, None, digest, "ACTIVE_POLICY_MISSING")
    rules = policy.rules or {}
    policy_name, policy_version = policy.policy_name, policy.version
    try:
        thresholds = PolicyThresholds(
            min_evidence_quality_bps=int(rules["min_evidence_quality_bps"]),
            observe_threshold_bps=int(rules["observe_threshold_bps"]),
            escalate_threshold_bps=int(rules["escalate_threshold_bps"]),
            deny_threshold_bps=int(rules["deny_threshold_bps"]),
        )
    except (KeyError, TypeError, ValueError):
        return _deny(policy_name, policy_version, None, None, digest, "ACTIVE_POLICY_INVALID")
    if not thresholds.valid() or rules.get("require_signed_mandate") is not True:
        return _deny(policy_name, policy_version, None, None, digest, "POLICY_SECURITY_POSTURE_INVALID")

    organization = db.query(models.Organization).filter_by(org_id=agent.org_id).first()
    parent = db.query(models.ParentAuthority).filter_by(id=agent.parent_pk, org_id=agent.org_id).first()
    if (not organization or organization.status != "ACTIVE" or not parent
            or parent.status != models.ParentStatus.ACTIVE):
        return _deny(policy_name, policy_version, None, None, digest, "ORGANIZATION_OR_PARENT_NOT_TRUSTED")

    principals = db.query(models.PrincipalIdentity).filter_by(
        org_id=agent.org_id, external_subject_id=mandate.user_id).all()
    # Ambiguous mappings across identity providers are unsafe; never choose the first row.
    if len(principals) != 1 or principals[0].status != "ACTIVE":
        return _deny(policy_name, policy_version, principals[0].principal_id if len(principals) == 1 else None,
                     None, digest, "PRINCIPAL_MISSING_INACTIVE_OR_AMBIGUOUS")
    principal = principals[0]
    # Production strict mode requires provider-backed evidence and refreshes the
    # provider case status before every new payment decision. Organization or
    # parent attestations stay useful for sandbox onboarding but are not KYC/KYB.
    deployment_env = os.environ.get("PAARI_ENV", "sandbox").strip().lower()
    identity_required = deployment_env in {"prod", "prod-live"} or os.environ.get("PAARI_LIVE") == "1"
    if identity_required:
        from app.identity_providers.runtime import verify_current_principal
        identity_ok, identity_reason = verify_current_principal(principal, now=now)
        if not identity_ok:
            return _deny(policy_name, policy_version, principal.principal_id, None, digest,
                         identity_reason or "TRUSTED_PRINCIPAL_IDENTITY_NOT_VERIFIED")

    bindings = db.query(models.PaymentInstrumentBinding).filter_by(
        org_id=agent.org_id, mandate_id=mandate.mandate_id, status="active").all()
    live_bindings = [b for b in bindings if b.expires_at is None or b.expires_at > now]
    if len(live_bindings) != 1:
        return _deny(policy_name, policy_version, principal.principal_id, None, digest,
                     "PROVIDER_BINDING_MISSING_INACTIVE_OR_AMBIGUOUS")
    binding = live_bindings[0]
    if not binding.source_resource_id:
        return _deny(policy_name, policy_version, principal.principal_id, None, digest, "SOURCE_RESOURCE_BINDING_MISSING")
    resource = db.query(models.GovernedResource).filter_by(
        org_id=agent.org_id, resource_id=binding.source_resource_id, status="ACTIVE").first()
    if not resource:
        return _deny(policy_name, policy_version, principal.principal_id, binding.source_resource_id, digest,
                     "SOURCE_RESOURCE_MISSING_OR_INACTIVE")
    if resource.resource_type not in {"bank_account", "open_banking_account", "stablecoin_wallet", "treasury_account", "provider_mandate"}:
        return _deny(policy_name, policy_version, principal.principal_id, resource.resource_id, digest,
                     "RESOURCE_TYPE_NOT_PAYMENT_SOURCE")
    if resource.provider_id.casefold() != binding.provider.casefold():
        return _deny(policy_name, policy_version, principal.principal_id, resource.resource_id, digest,
                     "RESOURCE_PROVIDER_MISMATCH")
    if resource.currency and resource.currency != req.currency:
        return _deny(policy_name, policy_version, principal.principal_id, resource.resource_id, digest,
                     "RESOURCE_CURRENCY_MISMATCH")
    if binding.currency != req.currency or (binding.max_amount_minor_units < req.amount_minor_units):
        return _deny(policy_name, policy_version, principal.principal_id, resource.resource_id, digest,
                     "PROVIDER_BINDING_SCOPE_MISMATCH")

    grant_agent = _has_grant(db, org_id=agent.org_id, resource_id=resource.resource_id,
                             subject_type="agent", subject_id=agent.agent_id, now=now)
    grant_principal = _has_grant(db, org_id=agent.org_id, resource_id=resource.resource_id,
                                 subject_type="principal", subject_id=principal.principal_id, now=now)
    if not grant_agent or not grant_principal:
        # Evaluator returns a specific code for each missing grant.
        agent_grant_ok, principal_grant_ok = grant_agent, grant_principal
    else:
        agent_grant_ok, principal_grant_ok = True, True

    from app.mandate_signing import verify_mandate_signature
    sig_result = verify_mandate_signature(mandate)
    allowed_merchants = [str(x).casefold() for x in (mandate.allowed_merchants or [])]
    allowed_categories = [str(x).casefold() for x in (mandate.allowed_categories or [])]
    merchant_authorized = not allowed_merchants or req.merchant.casefold() in allowed_merchants
    category_authorized = not allowed_categories or (req.merchant_category or "").casefold() in allowed_categories
    allowed_purpose_codes = resource.resource_metadata.get("allowed_purpose_codes") if isinstance(resource.resource_metadata, dict) else None
    purpose_authorized = bool(req.purpose.strip()) and (not allowed_purpose_codes or req.purpose.strip() in allowed_purpose_codes)

    parent_quality = {"kyb_verified": 10000, "admin_approved": 9500, "self_asserted": 5000}.get(parent.trust_tier, 5000)
    principal_quality = {"high": 10000, "substantial": 9500, "low": 5000}.get(principal.assurance_level, 5000)
    evidence_quality = min(parent_quality, principal_quality)
    applicable_limit = min(agent.payment_limit_minor_units, mandate.max_per_transaction, binding.max_amount_minor_units)
    if applicable_limit <= 0:
        return _deny(policy_name, policy_version, principal.principal_id, resource.resource_id, digest, "FINANCIAL_LIMIT_INVALID")
    risk_score = calculate_rule_risk_score_bps(amount_minor=req.amount_minor_units,
                                               applicable_limit_minor=applicable_limit,
                                               intents_in_last_minute=intents_in_last_minute)
    facts = ControlFacts(
        tenant_matches=bool(agent.org_id and mandate.org_id == agent.org_id and resource.org_id == agent.org_id),
        agent_active=agent.status == models.AgentStatus.ACTIVE,
        organization_active=(organization is not None and organization.status == "ACTIVE"
                             and parent.status == models.ParentStatus.ACTIVE),
        principal_active=principal.status == "ACTIVE",
        mandate_active=(mandate.status == models.MandateStatus.ACTIVE and mandate.valid_from <= now < mandate.expires_at),
        mandate_signature_valid=sig_result.signature_valid,
        provider_binding_active=(binding.status == "active" and (binding.expires_at is None or binding.expires_at > now)),
        source_resource_active=resource.status == "ACTIVE",
        agent_resource_grant=agent_grant_ok,
        principal_resource_grant=principal_grant_ok,
        action_authorized=req.action in (agent.granted_capabilities or []),
        amount_minor=req.amount_minor_units,
        amount_limit_minor=applicable_limit,
        currency_matches=(req.currency == agent.currency == mandate.currency == binding.currency),
        beneficiary_authorized=merchant_authorized,
        purpose_authorized=purpose_authorized and category_authorized,
        consent_current=(mandate.status == models.MandateStatus.ACTIVE and mandate.valid_from <= now < mandate.expires_at),
        evidence_verified=(sig_result.signature_valid and grant_agent and grant_principal and resource.status == "ACTIVE"),
        evidence_quality_bps=evidence_quality,
        risk_score_bps=risk_score,
        review_required=(mandate.require_review_above is not None and req.amount_minor_units > mandate.require_review_above),
    )
    result = evaluate(facts, thresholds)
    return RuntimeDecision(policy_name, policy_version, principal.principal_id, resource.resource_id, result, digest)


def persist_control_plane_decision(db: Session, *, intent: models.PaymentIntent,
                                   decision: RuntimeDecision | None, fallback_reason: str | None = None) -> models.ControlPlaneDecision | None:
    """Persist exactly one immutable disposition per intent and chain its audit event."""
    if db.query(models.ControlPlaneDecision).filter_by(intent_id=intent.intent_id).first():
        return None
    if decision is None:
        active_policy = db.query(models.PolicyBundle).filter_by(org_id=intent.org_id, policy_name="payment_execution", status="ACTIVE").first()
        policy_name = active_policy.policy_name if active_policy else "payment_execution"
        policy_version = active_policy.version if active_policy else "missing"
        reason_codes = [fallback_reason or "LEGACY_GOVERNANCE_DENIAL"]
        disposition = Disposition.DENY
        principal_id = resource_id = None
        risk_score = evidence_quality = None
        digest_payload = {"org_id": intent.org_id, "intent_id": intent.intent_id,
                          "agent_id": intent.agent_id, "merchant": intent.merchant,
                          "amount_minor_units": intent.amount_minor_units,
                          "currency": intent.currency, "action": intent.action}
        digest = hashlib.sha256(crypto_utils.canonical_json(digest_payload).encode()).hexdigest()
    else:
        policy_name, policy_version = decision.policy_name, decision.policy_version
        reason_codes = list(decision.evaluation.reason_codes)
        disposition = decision.evaluation.disposition
        principal_id, resource_id = decision.principal_id, decision.resource_id
        risk_score = decision.evaluation.risk_score_bps
        evidence_quality = decision.evaluation.evidence_quality_bps
        digest = decision.transaction_digest
    from app.reason_codes import build_reason_evidence, CATALOG_VERSION
    agent = db.query(models.Agent).filter_by(agent_id=intent.agent_id, org_id=intent.org_id).first()
    active_policy = db.query(models.PolicyBundle).filter_by(
        org_id=intent.org_id, policy_name=policy_name, version=policy_version
    ).first()
    evidence = build_reason_evidence(
        reason_codes=reason_codes, intent=intent, decision=decision,
        agent=agent, policy_rules=(active_policy.rules if active_policy else {}),
    )
    row = models.ControlPlaneDecision(intent_id=intent.intent_id, org_id=intent.org_id,
                                      principal_id=principal_id, resource_id=resource_id,
                                      policy_name=policy_name, policy_version=policy_version,
                                      disposition=disposition.value, reason_codes=reason_codes,
                                      reason_evidence=evidence, reason_catalog_version=CATALOG_VERSION,
                                      risk_score_bps=risk_score, evidence_quality_bps=evidence_quality,
                                      transaction_digest=digest)
    db.add(row)
    db.flush()  # resolve database-generated decision_id before it enters the audit digest
    from app.audit import record_audit
    record_audit(db, transaction_id=intent.transaction_id, agent_id=intent.agent_id,
                 parent_id=None, kind="control_plane_disposition",
                 detail={"decision_id": row.decision_id, "intent_id": intent.intent_id,
                         "disposition": disposition.value, "reason_codes": reason_codes,
                         "reason_evidence": evidence, "reason_catalog_version": CATALOG_VERSION,
                         "policy_name": policy_name, "policy_version": policy_version,
                         "principal_id": principal_id, "resource_id": resource_id,
                         "risk_score_bps": risk_score, "evidence_quality_bps": evidence_quality,
                         "transaction_digest": digest}, org_id=intent.org_id)
    db.flush()
    return row
