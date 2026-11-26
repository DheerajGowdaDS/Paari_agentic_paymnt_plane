# Organization Portal — Parent Payment Review Workflow

**Build:** Paari v3.7.1 portal refinement  
**Audience:** Organization owners, treasury approvers, and Paari integration operators  
**Scope:** Parent-scoped SAFR escalation and parent-authority step-up review

## What changed

The Organization Portal now has a parent review queue in two places:

- **Overview:** a visible attention panel appears when one or more payments await a parent decision.
- **Payment tracker:** the same parent-scoped queue appears above the transaction list so an approver can review a payment and then inspect its complete processing journey.

The queue includes payment requests whose persisted decision is `REVIEW` and which either require parent step-up (`mfa_required`) or have a persisted Paari control-plane decision with disposition `ESCALATE`. It is scoped to the authenticated parent's own agents. It does not expose another parent's or tenant's requests.

## What the parent sees on each review card

Each card displays:

- Agent identity and the payment's merchant, purpose, amount and currency.
- Transaction ID and Paari intent ID.
- Review class: `SAFR escalation` or `Parent-authority step-up`.
- SAFR policy name/version, risk score and evidence-quality score when returned by the control plane.
- The recorded policy / payment reasons and the review deadline.
- A required password re-authentication field and a reviewer note.

The UI does not show an authorization JWT or payment-provider secret to the parent.

## Parent actions

### Approve payment

1. Open the **Overview → Payments awaiting parent review** panel or **Payment tracker → Parent review queue**.
2. Expand **Why Paari escalated this payment** and inspect the amount, agent, merchant, purpose, risk score, policy and expiry.
3. Re-enter the parent account password and enter a review note of at least five characters.
4. Select **Approve payment**.
5. Paari validates the active parent session and password, creates a fresh transaction-bound one-time challenge, and verifies a parent-authority signature over the exact intent context.
6. The existing payment review release path performs its current checks before creating a bounded authorization. A successful result is shown in the portal without returning the authorization token to the parent browser.
7. The authenticated agent runtime retrieves the authorization from `GET /payments/intents/{intent_id}/authorization` using its own agent session and one-time `X-Paari-Proof`, then proceeds through the normal authorization-consumption/provider flow.

An approval is not an instruction to bypass Paari. A stale or revoked mandate, expired review, inactive parent or agent, hard denial, unresolved receiving-party control, policy drift, treasury risk failure or other mandatory control can still prevent authorization.

### Reject payment

1. Inspect the same payment and reasons.
2. Re-enter the parent password and enter a reviewer note.
3. Select **Reject payment**.
4. Paari verifies a distinct rejection-purpose signature bound to the intent, challenge, nonce and amount.
5. The challenge is consumed, the intent transitions to `DENY`, no bounded authorization is minted, and the rejection plus the review note are appended to the audit record.

An approval signature cannot be replayed as a rejection, and a rejection challenge cannot be reused for another payment.

## API contract

| Method | Route | Purpose | Authentication |
|---|---|---|---|
| `GET` | `/portal/v1/parent/reviews` | List only the signed-in parent's pending review items | Parent bearer token |
| `POST` | `/portal/v1/parent/reviews/{intent_id}/decision` | Parent approve/reject with password re-authentication and audit note | Parent bearer token + password in request body |
| `GET` | `/payments/intents/{intent_id}/authorization` | Retrieve the bounded authorization for the approved intent | Owning agent bearer session + one-time `X-Paari-Proof` |

The decision request body is:

```json
{
  "approve": true,
  "reviewer_password": "<parent account password>",
  "reviewer_note": "Invoice and supplier details were checked."
}
```

Never put the parent password in logs or scripts, and never return the agent authorization token to the Organization Portal. The approval route writes a separate `parent_portal_review_note` audit event; the existing payment verifier writes the approval/rejection and authorization events.

## Security boundary in this release

The current v3.6 onboarding package explicitly gates the managed parent-signing path to sandbox use. In this local build, the backend re-authenticates the parent password and signs the one-time challenge using the parent's encrypted managed key. This is a functional local demonstration of the parent review path, not the final production key-custody design.

Before production use, replace the server-managed signing bridge with an independently reviewed parent-held signing credential or HSM/KMS-backed signing workflow, named approver identities, MFA/step-up authentication, reviewer role separation, session security, password-attempt controls, and independent security testing. KYC/KYB and regulated authorization requirements remain separate integrations.

## Website navigation refinement

The Organization Portal is streamlined to these sections:

1. **Overview** — parent status, fleet/payment KPIs, recent activity and parent review queue.
2. **Agent registry** — register agents, inspect signed Agent Cards and manage bootstrap handling.
3. **Payment tracker** — view accepted payment intents, SAFR review queue and payment evidence timeline.
4. **Treasury & risk** — parent-level limits, fleet exposure and risk signals.
5. **Organization** — parent registration details, masked identity reference, representative contact, Paari tenant status and governance footprint.

The standalone **Data permissions & portability** and **Payment rail lab** portal pages have been removed from this UI build. Their backend modules and APIs are retained in the repository; this change removes the two navigation destinations and their page content, not the underlying backend code. The standalone **Capabilities** header navigation item has also been removed; the platform overview/landing content remains.

The Paari Platform Console **Approvals & applications** page now focuses only on parent applications. Institution/provider application review is no longer shown in that section.

## Demo walkthrough

1. Register and approve a synthetic parent using the Platform Console.
2. Provision the parent's tenant, then sign in to the Organization Portal.
3. Register a demo agent and issue its Agent Card/bootstrap to the local agent runtime.
4. Submit a request that enters `REVIEW` with an SAFR `ESCALATE` disposition.
5. Refresh the Organization Portal Overview and show the parent review card.
6. Expand the reasons and show the risk/policy details.
7. Demonstrate a rejection first: verify the intent becomes `DENY` and no authorization exists.
8. Submit a second reviewable request and demonstrate approval. The portal should show that approval was recorded, while the agent runtime—not the parent browser—retrieves the bounded authorization.
9. Open Payment tracker to show the changed decision and audit evidence.

Use a fresh disposable sandbox database and synthetic records. Do not describe an `ALLOW` or an authorization as a settled payment. Provider confirmation and settlement evidence are separate lifecycle states.
