"""Deterministic identity-provider contract double for unit tests only.

This is not a vendor adapter and must never be used for live deployments.
"""
from datetime import datetime, timedelta, timezone
import hashlib

from app.identity_providers.contracts import (
    VerificationKind, VerificationRequest, VerificationResult, VerificationStatus,
    subject_reference_digest,
)


_CASES = {}


class TestTrustedIdentityProvider:
    provider_id = "test-reviewed-idp"

    def verify(self, request: VerificationRequest) -> VerificationResult:
        now = datetime.now(timezone.utc)
        case_ref = f"test-case-{request.verification_id}"
        result = VerificationResult(
            provider_id=self.provider_id,
            provider_case_reference=case_ref,
            status=VerificationStatus.VERIFIED,
            jurisdiction=request.jurisdiction,
            evidence_digest=hashlib.sha256((case_ref + "-evidence").encode()).hexdigest(),
            evidence_retrieved_at=now,
            expires_at=now + timedelta(hours=1),
            assurance_level="substantial",
            reason_codes=("TEST_FIXTURE_ONLY",),
            subject_reference_digest=subject_reference_digest(request.organization_id, request.subject_reference),
            verification_kind=request.kind,
        )
        _CASES[case_ref] = result
        return result

    def get_status(self, provider_case_reference: str) -> VerificationResult:
        return _CASES[provider_case_reference]

    def healthcheck(self) -> bool:
        return True


def create_provider():
    return TestTrustedIdentityProvider()
