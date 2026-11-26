# UAE Identity, KMS/HSM and Open Finance — Integration Decision Record v2.7

**Decision status:** evaluation plan, not vendor selection or regulatory opinion.

## Recommended control-plane ownership

Paari owns the onboarding workflow, organization and agent registry, parent delegation, Agent Card lifecycle, identity-evidence acceptance policy, authorization policy, audit and revocation. External sources provide evidence or upstream institutional capabilities. A KYC/KYB provider does not become Paari's authority engine, and a verified identity does not automatically permit financial activity.

### Individual / representative identity

Evaluate UAE PASS for the integration capabilities it contracts for: authentication, digital signature/eSeal, and data/document sharing. Do not assume UAE PASS alone supplies business registry/UBO verification, AML screening, or an organisation's financial mandate. Verify exact private-sector onboarding eligibility, scope, consent, assurance, signature format and service-level obligations with the UAE PASS integration programme.

Official docs: https://docs.uaepass.ae/

### Organisation KYB and ownership

Sumsub is a candidate to evaluate for business verification because its documented flows can include corporate registry checks, company document review, ownership/management structure and AML screening. Its own documentation states that country source coverage depends on the contracted Corporate Registry Sources pack. Obtain written confirmation for UAE mainland, each intended free-zone, legal form, UBO coverage, source freshness, data residency/retention, sanctions/PEP scope, evidence export, SLA, pricing and contractual roles before selection.

Official docs: https://docs.sumsub.com/docs/verify-businesses  
Coverage source: https://docs.sumsub.com/docs/business-verification-sources

### Evidence contract

Use `app/identity_providers/contracts.py` as the provider-neutral boundary. Production evidence must carry provider/case references, status, jurisdiction, evidence digest, retrieval time, expiry and reason codes. Callbacks need authentication/signature verification, event idempotency, replay protection and status refresh. Cache `VERIFIED` only until evidence expiry/revocation. The included sandbox provider always returns `REVIEW_REQUIRED`/`UNAVAILABLE`; it cannot establish legal identity.

### Signing / KMS/HSM

Keep the provider-neutral signing interface. The codebase's current protocol uses Ed25519, so any selected KMS/HSM must support compatible signing semantics and public-key retrieval; test exact signature format, canonical bytes, key IDs, rotation, revocation, rate limits, IAM separation, region availability, audit and disaster recovery before implementing the adapter.

AWS KMS documentation lists `ECC_NIST_EDWARDS25519` / Ed25519 for signing and verification. Evaluate it as a candidate after confirming target-region availability, security requirements, key protection and cost; this document does not claim an AWS KMS adapter exists in Paari.

Official docs: https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html  
Cryptography overview: https://docs.aws.amazon.com/kms/latest/developerguide/kms-cryptography.html

## UAE Open Finance boundary

The CBUAE Open Finance Regulation establishes the framework for licensed Open Finance Services, including data sharing and service initiation, with an API Hub and Trust Framework. Article 2 says a juridical person may not provide an Open Finance Service in the UAE unless it has the applicable Open Finance Licence or qualifies as a Person Deemed Licensed under the regulation. The regulation also states that technical service providers are not thereby licensed to perform the regulated activity; responsibility is not simply transferred to the technology provider.

Accordingly:

- Treat a licensed bank/Open Finance Provider as execution/data-service owner unless Paari's own legal role and permissions are confirmed.
- Design a partner integration to preserve explicit consent, authentication, participant/certificate validation, approved APIs, evidence retention and provider responsibilities.
- Obtain UAE legal/regulatory advice for Paari's specific business model before offering service initiation, handling financial data or marketing the product as an Open Finance provider.
- A payment provider adapter is a technical integration, not a regulatory permission.

Official sources:
- CBUAE Open Finance Regulation: https://rulebook.centralbank.ae/en/rulebook/open-finance-regulation
- CBUAE Introduction and Scope: https://rulebook.centralbank.ae/en/rulebook/introduction-and-scope-2
- CBUAE Article 2 (licensing): https://rulebook.centralbank.ae/en/rulebook/article-2-licensing-and-licensing-procedures-0

## Deferred decision

Do not lock a live KYB vendor or KMS vendor into domain models. First-party Paari contracts should remain stable; vendor selection is a deployment decision based on UAE coverage, security, contractual terms and partner requirements. No trusted identity/KYB or concrete managed KMS/HSM adapter is included in v2.7.
