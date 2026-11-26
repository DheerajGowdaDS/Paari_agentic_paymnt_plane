# Paari Payment Tracker — Backend-to-UI Mapping

## Core lifecycle

`POST /v1/agents/register` (signed registration envelope) → `POST /v1/auth/challenge` → `POST /v1/auth/verify` (agent session) → `POST /v1/payments/intent` (session + `X-Paari-Proof`) → policy / mandate / SAFR checks → `ALLOW` mints bounded authorization → `POST /v1/payments/authorizations/{authorization_id}/consume` (atomic single-use consumption and execution revalidation) → provider order / native execution → signature-verified webhook → independent provider read and reconciliation → confirmed `PAID` → hash-chained audit proof.

## What the tracker shows

- Parent-scoped PaymentIntent history and reasons.
- Paari-signed Agent Card lookup and bound facts.
- Authentication, delegation, mandate, treasury, organization, receiver, federation and SAFR evidence where the backend returns it.
- Bounded authorization ID and expiry, separate from the earlier agent session.
- Consume-time revalidation, provider state and provider environment.
- Webhook/reconciliation state, audit event timestamps, previous hashes, event hashes and chain verification.

## Evidence discipline

The tracker uses recorded facts. Where a policy is represented in `intent_decided.detail.policy_results`, it displays the result and reason. Where a distinct positive audit result is absent, the UI says the later pipeline progression indicates no block but does not claim there is a separate positive audit event. Deployment-configured controls without results remain informational. The tracker does not infer settlement from authorization or provider submission.

## Agent not registered

A non-registered agent must not continue directly to payment. It must first submit signed registration with a parent-signed delegation bound to the agent public key. Paari validates parent status, signature, capability, amount, currency, expiry and one-time delegation use before issuing an Agent Card and credential. Then the agent authenticates and obtains a session before proposing a payment.

Failed unauthenticated requests are currently rejected before a `PaymentIntent` row is created. The parent-scoped tracker cannot display those attempts until a separate security-ingress audit model/API is added.

## Run and integrate

See `INTEGRATION_GUIDE.md` for router mounting, serving the website from the same origin, sandbox configuration and validation steps.
