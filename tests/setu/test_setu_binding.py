from app import models


def test_setu_consent_mandate_binding_is_tenant_and_subject_bound():
    assert models.SetuConsent.__tablename__ == "setu_consents"
    assert models.SetuConsentMandateBinding.__tablename__ == "setu_consent_mandate_bindings"
    columns = models.SetuConsentMandateBinding.__table__.c
    assert {"org_id", "setu_consent_id", "mandate_id", "subject_user_id", "status"} <= set(columns.keys())
    assert any(
        constraint.name == "uq_setu_binding_org_consent_mandate"
        for constraint in models.SetuConsentMandateBinding.__table__.constraints
    )
