from app.control_plane.engine import (
    ControlFacts, Disposition, PolicyThresholds, calculate_rule_risk_score_bps, evaluate,
)


def base_facts(**overrides):
    values = dict(
        tenant_matches=True, agent_active=True, organization_active=True,
        principal_active=True, mandate_active=True, mandate_signature_valid=True,
        provider_binding_active=True, source_resource_active=True,
        agent_resource_grant=True, principal_resource_grant=True,
        action_authorized=True, amount_minor=1000, amount_limit_minor=10000,
        currency_matches=True, beneficiary_authorized=True, purpose_authorized=True,
        consent_current=True, evidence_verified=True, evidence_quality_bps=10000,
        risk_score_bps=0, review_required=False,
    )
    values.update(overrides)
    return ControlFacts(**values)


def test_low_risk_passes_to_auto_execute():
    result = evaluate(base_facts(), PolicyThresholds())
    assert result.disposition is Disposition.AUTO_EXECUTE
    assert result.reason_codes == ("ALL_MANDATORY_CONTROLS_PASSED",)


def test_hard_tenant_denial_wins_even_with_zero_risk():
    result = evaluate(base_facts(tenant_matches=False, risk_score_bps=0), PolicyThresholds())
    assert result.disposition is Disposition.DENY
    assert result.reason_codes == ("TENANT_MISMATCH",)


def test_agent_and_principal_resource_grants_are_both_required():
    assert evaluate(base_facts(agent_resource_grant=False), PolicyThresholds()).reason_codes == ("AGENT_RESOURCE_ACCESS_MISSING",)
    assert evaluate(base_facts(principal_resource_grant=False), PolicyThresholds()).reason_codes == ("PRINCIPAL_RESOURCE_ACCESS_MISSING",)


def test_invalid_signature_is_a_hard_deny():
    result = evaluate(base_facts(mandate_signature_valid=False, risk_score_bps=0), PolicyThresholds())
    assert result.disposition is Disposition.DENY
    assert result.reason_codes == ("MANDATE_SIGNATURE_INVALID",)


def test_missing_risk_assessment_escalates_not_autoruns():
    result = evaluate(base_facts(risk_score_bps=None), PolicyThresholds())
    assert result.disposition is Disposition.ESCALATE
    assert result.reason_codes == ("RISK_ASSESSMENT_UNAVAILABLE",)


def test_missing_evidence_denies_and_low_quality_escalates():
    assert evaluate(base_facts(evidence_verified=False), PolicyThresholds()).disposition is Disposition.DENY
    result = evaluate(base_facts(evidence_quality_bps=7000), PolicyThresholds())
    assert result.disposition is Disposition.ESCALATE
    assert result.reason_codes == ("EVIDENCE_QUALITY_BELOW_THRESHOLD",)


def test_risk_thresholds_map_to_observe_escalate_and_deny():
    assert evaluate(base_facts(risk_score_bps=2500), PolicyThresholds()).disposition is Disposition.OBSERVE
    assert evaluate(base_facts(risk_score_bps=6000), PolicyThresholds()).disposition is Disposition.ESCALATE
    assert evaluate(base_facts(risk_score_bps=9000), PolicyThresholds()).disposition is Disposition.DENY


def test_mandate_review_cannot_be_overridden_by_low_risk():
    result = evaluate(base_facts(review_required=True, risk_score_bps=0), PolicyThresholds())
    assert result.disposition is Disposition.ESCALATE


def test_rule_risk_score_is_bounded_and_explainable():
    assert calculate_rule_risk_score_bps(amount_minor=100, applicable_limit_minor=1000, intents_in_last_minute=1) == 0
    assert calculate_rule_risk_score_bps(amount_minor=800, applicable_limit_minor=1000, intents_in_last_minute=1) == 2500
    assert calculate_rule_risk_score_bps(amount_minor=900, applicable_limit_minor=1000, intents_in_last_minute=4) == 9000
