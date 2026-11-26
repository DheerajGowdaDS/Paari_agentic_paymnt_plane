"""Deterministic SAFR-style governance engine for Paari's institutional control plane.

This module has no HTTP or database side effects. Its inputs must be authoritative,
server-derived facts; callers must never pass an agent-asserted `verified` flag.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping


class Disposition(StrEnum):
    DENY = "DENY"
    ESCALATE = "ESCALATE"
    AUTO_EXECUTE = "AUTO_EXECUTE"
    OBSERVE = "OBSERVE"


@dataclass(frozen=True)
class ControlFacts:
    tenant_matches: bool
    agent_active: bool
    organization_active: bool
    principal_active: bool
    mandate_active: bool
    mandate_signature_valid: bool
    provider_binding_active: bool
    source_resource_active: bool
    agent_resource_grant: bool
    principal_resource_grant: bool
    action_authorized: bool
    amount_minor: int
    amount_limit_minor: int
    currency_matches: bool
    beneficiary_authorized: bool
    purpose_authorized: bool
    consent_current: bool
    evidence_verified: bool
    evidence_quality_bps: int | None
    risk_score_bps: int | None
    review_required: bool = False


@dataclass(frozen=True)
class PolicyThresholds:
    min_evidence_quality_bps: int = 8500
    observe_threshold_bps: int = 2500
    escalate_threshold_bps: int = 6000
    deny_threshold_bps: int = 9000

    def valid(self) -> bool:
        return (
            0 <= self.min_evidence_quality_bps <= 10000
            and 0 <= self.observe_threshold_bps < self.escalate_threshold_bps
            < self.deny_threshold_bps <= 10000
        )


@dataclass(frozen=True)
class Evaluation:
    disposition: Disposition
    reason_codes: tuple[str, ...]
    risk_score_bps: int | None
    evidence_quality_bps: int | None
    requires_monitoring: bool = False


_HARD_DENY = (
    ("TENANT_MISMATCH", "tenant_matches"),
    ("AGENT_NOT_ACTIVE", "agent_active"),
    ("ORGANIZATION_NOT_ACTIVE", "organization_active"),
    ("PRINCIPAL_NOT_ACTIVE", "principal_active"),
    ("MANDATE_NOT_ACTIVE", "mandate_active"),
    ("MANDATE_SIGNATURE_INVALID", "mandate_signature_valid"),
    ("PROVIDER_BINDING_INACTIVE", "provider_binding_active"),
    ("SOURCE_RESOURCE_INACTIVE", "source_resource_active"),
    ("AGENT_RESOURCE_ACCESS_MISSING", "agent_resource_grant"),
    ("PRINCIPAL_RESOURCE_ACCESS_MISSING", "principal_resource_grant"),
    ("ACTION_NOT_AUTHORIZED", "action_authorized"),
    ("CURRENCY_NOT_AUTHORIZED", "currency_matches"),
    ("BENEFICIARY_NOT_AUTHORIZED", "beneficiary_authorized"),
    ("PURPOSE_NOT_AUTHORIZED", "purpose_authorized"),
    ("CONSENT_NOT_CURRENT", "consent_current"),
)


def evaluate(facts: ControlFacts, thresholds: PolicyThresholds) -> Evaluation:
    """Evaluate hard controls first, then evidence, review and risk thresholds.

    The first disposition is stable and reproducible. Missing evidence or risk is
    never interpreted as a zero-risk result. Hard controls cannot be overridden
    by any risk model result.
    """
    if not thresholds.valid():
        return Evaluation(Disposition.DENY, ("INVALID_POLICY_THRESHOLDS",), facts.risk_score_bps, facts.evidence_quality_bps)
    if facts.amount_minor <= 0:
        return Evaluation(Disposition.DENY, ("AMOUNT_MUST_BE_POSITIVE",), facts.risk_score_bps, facts.evidence_quality_bps)
    if facts.amount_limit_minor < 0 or facts.amount_minor > facts.amount_limit_minor:
        return Evaluation(Disposition.DENY, ("FINANCIAL_LIMIT_EXCEEDED",), facts.risk_score_bps, facts.evidence_quality_bps)
    for code, attribute in _HARD_DENY:
        if not getattr(facts, attribute):
            return Evaluation(Disposition.DENY, (code,), facts.risk_score_bps, facts.evidence_quality_bps)
    if not facts.evidence_verified:
        return Evaluation(Disposition.DENY, ("REQUIRED_EVIDENCE_UNVERIFIED",), facts.risk_score_bps, facts.evidence_quality_bps)
    if facts.evidence_quality_bps is None:
        return Evaluation(Disposition.ESCALATE, ("EVIDENCE_QUALITY_UNASSESSED",), facts.risk_score_bps, None)
    if not 0 <= facts.evidence_quality_bps <= 10000:
        return Evaluation(Disposition.DENY, ("INVALID_EVIDENCE_QUALITY_SCORE",), facts.risk_score_bps, facts.evidence_quality_bps)
    if facts.evidence_quality_bps < thresholds.min_evidence_quality_bps:
        return Evaluation(Disposition.ESCALATE, ("EVIDENCE_QUALITY_BELOW_THRESHOLD",), facts.risk_score_bps, facts.evidence_quality_bps)
    if facts.review_required:
        return Evaluation(Disposition.ESCALATE, ("MANDATE_REQUIRES_HUMAN_REVIEW",), facts.risk_score_bps, facts.evidence_quality_bps)
    if facts.risk_score_bps is None:
        return Evaluation(Disposition.ESCALATE, ("RISK_ASSESSMENT_UNAVAILABLE",), None, facts.evidence_quality_bps)
    if not 0 <= facts.risk_score_bps <= 10000:
        return Evaluation(Disposition.DENY, ("INVALID_RISK_SCORE",), facts.risk_score_bps, facts.evidence_quality_bps)
    if facts.risk_score_bps >= thresholds.deny_threshold_bps:
        return Evaluation(Disposition.DENY, ("RISK_DENY_THRESHOLD",), facts.risk_score_bps, facts.evidence_quality_bps)
    if facts.risk_score_bps >= thresholds.escalate_threshold_bps:
        return Evaluation(Disposition.ESCALATE, ("RISK_ESCALATION_THRESHOLD",), facts.risk_score_bps, facts.evidence_quality_bps)
    if facts.risk_score_bps >= thresholds.observe_threshold_bps:
        return Evaluation(Disposition.OBSERVE, ("RISK_OBSERVATION_THRESHOLD",), facts.risk_score_bps, facts.evidence_quality_bps, True)
    return Evaluation(Disposition.AUTO_EXECUTE, ("ALL_MANDATORY_CONTROLS_PASSED",), facts.risk_score_bps, facts.evidence_quality_bps)


def calculate_rule_risk_score_bps(*, amount_minor: int, applicable_limit_minor: int, intents_in_last_minute: int) -> int:
    """Small explainable baseline risk score, not an ML model.

    All inputs must be computed from Paari records. Threshold and weights are
    versioned in docs. A bank/PSP may replace this with a validated risk service.
    """
    if amount_minor <= 0 or applicable_limit_minor <= 0 or intents_in_last_minute < 0:
        raise ValueError("risk inputs are outside valid bounds")
    score = 0
    ratio = amount_minor / applicable_limit_minor
    if ratio >= 0.75:
        score += 2500
    elif ratio >= 0.50:
        score += 1200
    if intents_in_last_minute >= 4:
        score += 6500
    elif intents_in_last_minute >= 3:
        score += 2500
    elif intents_in_last_minute >= 2:
        score += 1000
    return min(10000, score)
