# Paari v3.7.1 — Organization Portal & Parent Review Refinement

Date: 2026-11-03

## User-requested changes

- SAFR escalation / parent step-up payments now appear in the authenticated parent's Organization Portal Overview and Payment Tracker review queue.
- Parent approve/reject actions require fresh password re-authentication and a mandatory reviewer note.
- Approval uses the existing transaction-bound parent signature verifier and can mint only the existing single-use bounded authorization after revalidation.
- Rejection uses the existing distinct-purpose signed rejection verifier, transitions the payment intent to `DENY`, and creates no authorization.
- The parent-facing UI never receives the authorization JWT; the owning agent retrieves it with its own authenticated session and one-time request proof.
- Removed the Organization Portal Data permissions & portability page and Payment rail lab page, including their navigation links.
- Removed the Platform Console institution/provider application box from Approvals & applications.
- Removed the Capabilities top-header navigation button.
- Expanded the Organization page with parent/account registration information, masked PAN/GSTIN reference, representative contact, Paari tenant identity/status, provider-profile status and parent-scoped governance counts.

## Implementation files

- `paari_product_portal.html`
- `app/portal_extension.py`
- `app/routers/payments.py`
- `tests/test_parent_portal_reviews.py`
- `docs/ORGANIZATION_PORTAL_PARENT_REVIEW.md`

## Validation performed

- Python compile checks for the changed API modules and regression test module.
- Portal JavaScript syntax check using Node.js.
- Focused parent review / legacy payment review / MFA regression tests.
- Parent queue scoping, masked organization profile fields, successful parent rejection, no authorization on rejection, audit chain verification, successful step-up approval, and agent-only bounded authorization retrieval.

See `PARENT_PORTAL_REFINEMENT_TEST_REPORT.md` for the exact executed commands and results.

## Limitations

- SAFR escalation release remains fail-closed: it requires fresh current Paari checks and cannot override a current hard denial or unresolved mandatory control.
- Parent review's server-managed signing bridge is sandbox-gated by the existing v3.6 onboarding implementation. It is not a production key-custody architecture.
- Data-permission/portability and payment-rail backend modules are retained; only their Organization Portal UI sections have been removed.
- This refinement does not certify the full product for production use or replace the remaining KYC/KYB, KMS/HSM, PostgreSQL scale/concurrency, external payment-integration and independent security-audit gates.
