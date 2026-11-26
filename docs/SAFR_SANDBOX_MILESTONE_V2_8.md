# Paari v2.8 — SAFR sandbox milestone

**Purpose.** Demonstrate an independent agent moving through registration/authentication, intent submission, deterministic governance, a signed SAFR Governance Envelope, transaction-bound single-use authorization, sandbox settlement, and an evidence trail that can be retrieved and verified. This is an engineering sandbox, not a live-money or SAFR-certified release.

## End-to-end demonstration

Run from the repository root in the supported Python environment:

```bash
python scripts/llm_agent_e2e.py --with-server --rehearse --strict-control-plane --execute-stub --settle
```

This boots the local service against a test database, uses synthetic identities and a local stub provider, and exercises the actual strict control-plane payment path. The SAFR hook creates an agent-key-signed envelope bound to the canonical request digest, calls the envelope process endpoint, requires a permitted saved disposition and consumable authorization, and only then gives the payment result to the agent loop. The stub consumes the existing authorization exactly once; the `--settle` leg then simulates capture, submits a signed payment-captured webhook, checks webhook replay/forgery behavior, reconciles to `PAID`, and verifies the settlement provenance in the proof bundle. No external payment provider or real money is used.

The demo also checks negative paths: a missing mandate is denied, replayed authorization consumption is rejected, and an over-cap payment receives a denial without authorization. The proof bundle and hash-linked audit record can be retrieved with the existing payment proof/audit routes.

## Sandbox API sequence

1. Register the agent and parent delegation using the existing agent-management APIs; establish an active principal, a governed source resource, consent/grants, a versioned policy and a signed user mandate.
2. Authenticate the agent using the existing challenge/credential flow.
3. Submit the payment intent through the existing authenticated payment runtime. Paari resolves identity, mandate, grant, policy and risk inputs from persisted/server-trusted state.
4. Submit the agent-signed envelope to `POST /control/v1/governance/envelopes/process?transaction_id=<transaction-id>` with tenant-scoped `X-Paari-Control-Key` and `X-Paari-Org` headers. `payment.execute` processing requires exactly one persisted intent and policy decision and compares principal/resource, mandate, amount, currency, merchant/purpose, beneficiary-reference digest and canonical request digest.
5. Read the disposition and authorization status. `DENY` and `ESCALATE` never permit execution; `AUTO_EXECUTE` and `OBSERVE` can only report the existing runtime authorization, and only while that authorization is unexpired and unused. The envelope endpoint never consumes authorization or executes the payment itself.
6. Consume the existing bounded authorization through the authenticated payment runtime. In the demo, the local stub records one simulated provider submission.
7. Retrieve the evidence bundle with `GET /v1/proof/{transaction_id}` and the audit-chain view with `GET /v1/audit/{transaction_id}` using the normal owner/session proof controls.

A signed envelope is evidence of what the registered agent asserted; it is not a substitute for server-derived policy facts, a signed user mandate, destination identity proof, provider binding, or a bounded authorization.

## Treasury fleet operations

- `GET /control/v1/organizations/{org_id}/fleet/risk-summary` returns the tenant's agent count, latest disposition/risk state, decisions/denials/escalations in the last 24 hours, and outstanding authorization/provider-in-flight exposure grouped by currency in minor units.
- `POST /control/v1/organizations/{org_id}/agents/{agent_id}/revoke?reason=<reason>` performs emergency tenant-scoped revocation, revokes active credentials and agent resource grants, invalidates unconsumed bounded authorizations, and writes an audit event.

The exposure calculation is an operational indicator, not a substitute for bank ledger reconciliation, a credit/risk limit service, or multi-worker atomic reservation. Currency amounts are grouped rather than summed across currencies.

## Governed portability

Exports contain signed identity/delegation metadata only. Import staging uses `POST /control/v1/portability/import/validate` and a separately configured `PAARI_PORTABILITY_TRUSTED_ISSUERS_JSON` JSON map from issuer key IDs to PEM public keys. The source package's embedded public key is never accepted as its own trust anchor.

The destination must already have an active locally approved parent, an active attested principal with substantial/high assurance from a non-sandbox identity provider, an active local resource, and a current principal consent grant. A successful import is `STAGED` only. It transfers no authority, credentials, mandate, grants, provider tokens or bounded authorizations. The destination must register the agent locally and issue fresh credentials, grants, consent/mandates, and a new transaction-bound authorization.

Example environment shape (provide real PEM and securely configure this outside source control):

```bash
export PAARI_PORTABILITY_TRUSTED_ISSUERS_JSON='{"<pinned-key-id>":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"}'
```

## Fail-closed production boundary

This release intentionally does **not** claim that the production trust prerequisites are complete. The production startup guards must remain closed unless all real acceptance criteria pass:

- A trusted identity/KYB adapter resolves real identity/provider evidence, verifies signed callbacks or attestations, checks expiry/revocation, binds issuer/subject/jurisdiction, and fails closed on unavailable or malformed results.
- A managed KMS/HSM signer is configured and its health/algorithm/key-rotation tests pass. Local PEM signing is sandbox/test-only; no fake managed-key status is introduced.
- Live provider credentials, webhooks, settlement and reconciliation are independently configured and tested in the target jurisdiction. The included command uses only a local stub.
- Enterprise deployment still requires multi-worker concurrency/atomicity tests, independent/WORM audit retention and signed checkpoints, operational reviewer RBAC and escalation SLA/timeouts, destination-side portability approval operations, and penetration/load tests.

## Evidence and scope

The deterministic policy engine has automated unit coverage for all four dispositions. The strict sandbox E2E currently demonstrates `AUTO_EXECUTE`, denial, single-use authorization, stub settlement and proof retrieval; it is not a complete end-to-end integration test for every possible escalation/reviewer workflow. Refer to `docs/SAFR_CONFORMANCE_MATRIX_V2_7.md` for the remaining release gates. Do not describe this sandbox as a production-ready payment deployment, a live UAE payment connection, or official SAFR compliance.
