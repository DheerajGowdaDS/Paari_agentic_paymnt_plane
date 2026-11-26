"""Versioned, regulator-facing SAFR reason-code catalogue and evidence helpers."""
from __future__ import annotations

CATALOG_VERSION = "1.0"

REASON_CODES: dict[str, dict[str, str]] = {
    "AGENT_NOT_REGISTERED": {"title": "Agent is not registered", "explanation": "The presented agent identity is not present in Paari's active agent registry."},
    "AGENT_CERTIFICATE_REVOKED": {"title": "Agent client certificate is revoked", "explanation": "The certificate fingerprint is present in Paari's certificate registry with a revoked status."},
    "AGENT_CERTIFICATE_UNKNOWN": {"title": "Agent certificate is not registered", "explanation": "The client certificate has not been bound to an approved Agent Card in Paari."},
    "MTLS_CLIENT_CERTIFICATE_INVALID": {"title": "mTLS client certificate was not verified", "explanation": "The trusted ingress proxy did not report a successful client-certificate verification."},
    "MTLS_UNTRUSTED_PROXY": {"title": "Request did not arrive through a trusted ingress", "explanation": "The application did not receive the request from a configured trusted mTLS proxy network."},
    "PARENT_AUTHORITY_INACTIVE": {"title": "Parent authority is inactive", "explanation": "The parent organization associated with the Agent Card is not active."},
    "DELEGATION_EXPIRED": {"title": "Delegation has expired", "explanation": "The parent-signed delegation is outside its recorded validity period."},
    "MANDATE_SIGNATURE_INVALID": {"title": "Mandate signature is invalid", "explanation": "The persisted mandate signature did not validate against the authoritative key."},
    "FINANCIAL_LIMIT_EXCEEDED": {"title": "Financial limit exceeded", "explanation": "The requested amount exceeds the applicable parent-delegated or policy limit."},
    "AGENT_VELOCITY_LIMIT_EXCEEDED": {"title": "Agent request velocity exceeded", "explanation": "The agent's observed request count exceeded the configured time-window threshold."},
    "BENEFICIARY_NOT_AUTHORIZED": {"title": "Beneficiary is not authorized", "explanation": "The beneficiary does not satisfy the active sender-side or receiver-side authorization policy."},
    "REQUIRED_EVIDENCE_UNVERIFIED": {"title": "Required evidence is not verified", "explanation": "A required identity, mandate, grant or resource evidence item is missing, expired or unverified."},
    "RISK_ESCALATION_THRESHOLD": {"title": "Risk score requires escalation", "explanation": "The server-calculated risk score reached the configured escalation threshold."},
    "RISK_ASSESSMENT_UNAVAILABLE": {"title": "Risk assessment is unavailable", "explanation": "Paari could not obtain the required risk assessment; the request is escalated fail-closed."},
    "ALL_MANDATORY_CONTROLS_PASSED": {"title": "Mandatory controls passed", "explanation": "All mandatory controls recorded for this decision passed."},
    "STEP_UP_REQUIRED": {"title": "Additional parent verification required", "explanation": "The request reached a configured step-up threshold and requires a separate parent-authorized verification before execution."},
    "MANDATE_REQUIRES_HUMAN_REVIEW": {"title": "User mandate requires human review", "explanation": "The active user mandate requires additional review for this amount or purpose."},
    "CAPABILITY_NOT_DELEGATED": {"title": "Requested capability is not delegated", "explanation": "The Agent Card does not carry the capability required for this payment action."},
    "CURRENCY_NOT_AUTHORIZED": {"title": "Currency is not authorized", "explanation": "The requested payment currency does not match the currency authorized by the parent delegation or mandate."},
    "PARENT_MANDATE_NOT_ACTIVE": {"title": "Parent or user mandate is not active", "explanation": "The required parent authority or user mandate is not currently active."},
    "INVALID_PAYMENT_AMOUNT": {"title": "Payment amount is invalid", "explanation": "The requested amount failed a server-side amount validation."},
    "INSTITUTIONAL_POLICY_DENIED": {"title": "Institutional policy denied the request", "explanation": "An active institutional, receiver or federation policy rejected the proposed action."},
    "GOVERNANCE_REVIEW_REQUIRED": {"title": "Governance review required", "explanation": "One or more governance controls require review before authorization can be issued."},
    "GOVERNANCE_DENIED": {"title": "Governance denied the request", "explanation": "One or more mandatory governance controls rejected the proposed action."},
    "KYB_MANUAL_EXCEPTION_APPROVED": {"title": "KYB exception approved by an authorized reviewer", "explanation": "An authorized reviewer completed the required exception checklist and recorded an approval in the sandbox workflow."},
    "KYB_MANUAL_EXCEPTION_REJECTED": {"title": "KYB exception rejected by an authorized reviewer", "explanation": "An authorized reviewer recorded a rejection in the sandbox workflow."},
    "AGENT_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID": {"title": "Agent client certificate is outside its validity period", "explanation": "The client certificate is expired or its not-before time has not yet been reached."},
    "AGENT_NOT_ACTIVE": {"title": "Agent is not active", "explanation": "The Agent Card is not in the active status required for payment ingress and authorization."},
    "TENANT_MISMATCH": {"title": "Organization or tenant identity mismatch", "explanation": "The request identity does not match the organization boundary associated with the payment resource."},
    "ORGANIZATION_NOT_ACTIVE": {"title": "Organization is not active", "explanation": "The organization associated with the request is not active."},
    "PRINCIPAL_NOT_ACTIVE": {"title": "User principal is not active", "explanation": "The human principal associated with the request is not active or sufficiently attested."},
    "MANDATE_NOT_ACTIVE": {"title": "User mandate is not active", "explanation": "The user payment mandate is expired, revoked or otherwise inactive."},
    "PROVIDER_BINDING_INACTIVE": {"title": "Provider mandate binding is inactive", "explanation": "The provider-side mandate or instrument binding is not active."},
    "SOURCE_RESOURCE_INACTIVE": {"title": "Payment source resource is inactive", "explanation": "The source account or payment resource is not active for this transaction."},
    "AGENT_RESOURCE_ACCESS_MISSING": {"title": "Agent lacks resource access", "explanation": "The agent has no current grant for the requested payment resource and action."},
    "PRINCIPAL_RESOURCE_ACCESS_MISSING": {"title": "User lacks resource access", "explanation": "The human principal has no current grant for the requested payment resource and action."},
    "ACTION_NOT_AUTHORIZED": {"title": "Payment action is not authorized", "explanation": "The requested action is outside the active agent, parent or user authority."},
    "PURPOSE_NOT_AUTHORIZED": {"title": "Payment purpose is not authorized", "explanation": "The proposed payment purpose does not satisfy the active mandate or resource policy."},
    "CONSENT_NOT_CURRENT": {"title": "Required consent is not current", "explanation": "The applicable consent is missing, expired or revoked."},
    "INVALID_POLICY_THRESHOLDS": {"title": "Policy configuration is invalid", "explanation": "The active policy contains inconsistent or out-of-range thresholds and the request was denied."},
    "AMOUNT_MUST_BE_POSITIVE": {"title": "Payment amount must be positive", "explanation": "The request amount is zero or negative."},
    "EVIDENCE_QUALITY_UNASSESSED": {"title": "Evidence quality could not be assessed", "explanation": "The policy engine could not calculate evidence quality and escalated the request."},
    "INVALID_EVIDENCE_QUALITY_SCORE": {"title": "Evidence quality score is invalid", "explanation": "The server-calculated evidence-quality score is outside its permitted range."},
    "EVIDENCE_QUALITY_BELOW_THRESHOLD": {"title": "Evidence quality is below policy threshold", "explanation": "The server-calculated evidence-quality score is below the configured minimum."},
    "RISK_DENY_THRESHOLD": {"title": "Risk score reached the denial threshold", "explanation": "The server-calculated risk score reached or exceeded the configured denial threshold."},
    "RISK_ESCALATION_THRESHOLD": {"title": "Risk score requires escalation", "explanation": "The server-calculated risk score reached the configured escalation threshold."},
    "RISK_OBSERVATION_THRESHOLD": {"title": "Risk score requires observation", "explanation": "The server-calculated risk score reached the configured observation threshold; monitoring is required."},
    "INVALID_RISK_SCORE": {"title": "Risk score is invalid", "explanation": "The server-calculated risk score is outside its permitted range."},
    "OTHER_GOVERNANCE_REVIEW_REQUIRED": {"title": "Additional governance review required", "explanation": "A non-institutional governance control requires a parent or reviewer decision before authorization."},
    "LEGACY_GOVERNANCE_DENIAL": {"title": "Legacy governance denied the request", "explanation": "A legacy governance check denied the request; inspect the attached policy evaluation evidence for the exact control."},
}


def describe_reason(code: str) -> dict[str, str]:
    item = REASON_CODES.get(code)
    if item:
        return {"reason_code": code, **item}
    return {
        "reason_code": code,
        "title": code.replace("_", " ").title(),
        "explanation": "See the recorded policy result and evidence context for the exact evaluation details.",
    }


def build_reason_evidence(*, reason_codes: list[str] | tuple[str, ...], intent, decision=None,
                          agent=None, policy_rules: dict | None = None) -> dict:
    """Record only server-known facts; missing facts remain explicitly unavailable."""
    rules = policy_rules or {}
    observed = {
        "amount_minor_units": getattr(intent, "amount_minor_units", None),
        "currency": getattr(intent, "currency", None),
        "agent_id": getattr(intent, "agent_id", None),
        "merchant": getattr(intent, "merchant", None),
        "risk_score_bps": getattr(decision, "risk_score_bps", None),
        "evidence_quality_bps": getattr(decision, "evidence_quality_bps", None),
        "agent_status": getattr(getattr(agent, "status", None), "value", getattr(agent, "status", None)),
        "delegated_limit_minor_units": getattr(agent, "payment_limit_minor_units", None),
    }
    return {
        "catalog_version": CATALOG_VERSION,
        "policy_name": getattr(decision, "policy_name", None),
        "policy_version": getattr(decision, "policy_version", None),
        "reason_items": [describe_reason(code) for code in reason_codes],
        "observed": observed,
        "configured": {
            "min_evidence_quality_bps": rules.get("min_evidence_quality_bps"),
            "observe_threshold_bps": rules.get("observe_threshold_bps"),
            "escalate_threshold_bps": rules.get("escalate_threshold_bps"),
            "deny_threshold_bps": rules.get("deny_threshold_bps"),
        },
        "evidence_source": "paari_server_records_and_active_policy",
    }


_POLICY_REASON_MAP = {
    "parent_check": "PARENT_AUTHORITY_INACTIVE",
    "delegation_expiry": "DELEGATION_EXPIRED",
    "amount_check": "INVALID_PAYMENT_AMOUNT",
    "capability_check": "CAPABILITY_NOT_DELEGATED",
    "limit_check": "FINANCIAL_LIMIT_EXCEEDED",
    "currency_check": "CURRENCY_NOT_AUTHORIZED",
    "user_mandate_check": "PARENT_MANDATE_NOT_ACTIVE",
    "user_mandate_review": "MANDATE_REQUIRES_HUMAN_REVIEW",
    "velocity_check": "AGENT_VELOCITY_LIMIT_EXCEEDED",
    "step_up_threshold": "STEP_UP_REQUIRED",
    "federated_policy_and_consent": "INSTITUTIONAL_POLICY_DENIED",
    "control_plane": "INSTITUTIONAL_POLICY_DENIED",
}


def derive_payment_reason_codes(*, decision: str, reasons: list[str] | None = None,
                                policy_results=None) -> list[str]:
    """Map server-produced policy evaluations to stable reason-code identifiers."""
    codes: list[str] = []
    for result in policy_results or ():
        if getattr(result, "passed", True):
            continue
        name = str(getattr(result, "name", ""))
        code = _POLICY_REASON_MAP.get(name)
        if name == "institutional_control_plane":
            detail = str(getattr(result, "detail", ""))
            disposition_and_reasons = detail.split(":", 1)
            if len(disposition_and_reasons) == 2:
                for candidate in disposition_and_reasons[1].split(";"):
                    candidate = candidate.strip()
                    if candidate and candidate.replace("_", "").isalnum():
                        codes.append(candidate)
            code = None
        if code:
            codes.append(code)
    reason_text = " ".join(str(item) for item in (reasons or [])).upper()
    for code in REASON_CODES:
        if code in reason_text:
            codes.append(code)
    if not codes:
        normalized = str(getattr(decision, "value", decision)).lower()
        codes = ["ALL_MANDATORY_CONTROLS_PASSED" if normalized in {"allow", "authorized"}
                 else "GOVERNANCE_REVIEW_REQUIRED" if normalized in {"review", "escalate"}
                 else "GOVERNANCE_DENIED"]
    # Preserve order while removing duplicates.
    return list(dict.fromkeys(codes))


def build_payment_intent_evidence(*, intent, agent, reason_codes: list[str],
                                  policy_results=None, evaluated_at=None) -> dict:
    """Decision evidence for all payment intents, including non-strict-CP flows."""
    observed = {
        "agent_id": getattr(intent, "agent_id", None),
        "agent_status": getattr(getattr(agent, "status", None), "value", getattr(agent, "status", None)),
        "parent_id": getattr(getattr(agent, "parent", None), "parent_id", None),
        "merchant": getattr(intent, "merchant", None),
        "amount_minor_units": getattr(intent, "amount_minor_units", None),
        "currency": getattr(intent, "currency", None),
        "action": getattr(intent, "action", None),
    }
    configured: dict = {}
    evaluations = []
    for result in policy_results or ():
        evidence = dict(getattr(result, "evidence", {}) or {})
        item = {"policy_name": getattr(result, "name", "unknown"),
                "passed": bool(getattr(result, "passed", False)),
                "detail": str(getattr(result, "detail", ""))}
        if evidence:
            item["evidence"] = evidence
            if "observed_count" in evidence:
                observed["agent_request_count_in_window"] = evidence.get("observed_count")
                observed["window_seconds"] = evidence.get("window_seconds")
            if "max_intents" in evidence:
                configured["agent_max_intents_per_window"] = evidence.get("max_intents")
                configured["agent_velocity_window_seconds"] = evidence.get("window_seconds")
        evaluations.append(item)
    return {
        "catalog_version": CATALOG_VERSION,
        "reason_items": [describe_reason(code) for code in reason_codes],
        "decision": str(getattr(getattr(intent, "decision", None), "value", getattr(intent, "decision", ""))),
        "observed": observed,
        "configured": configured,
        "policy_evaluations": evaluations,
        "evaluated_at": evaluated_at.isoformat() if evaluated_at else None,
        "evidence_source": "paari_server_records_and_policy_evaluations",
    }
