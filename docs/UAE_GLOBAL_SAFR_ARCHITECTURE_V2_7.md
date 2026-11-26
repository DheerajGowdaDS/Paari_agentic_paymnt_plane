# Paari v2.7 — UAE-First Global Agent Management & SAFR Control Plane

**Status:** Engineering target and implementation mapping, 24 October 2026  
**Jurisdiction metadata:** UAE (`AE`) by default. This metadata does not mean Paari is licensed or authorised to provide regulated services.

## 1. Product definition

Paari is an **agent management and runtime risk control plane for enterprise financial actions**, analogous to API management but designed for delegated AI agents. It registers agents and their parent organisations, preserves signed delegation, governs data and financial access, evaluates proposed actions before execution, issues bounded authorisation through the existing payment path, and records provider outcomes for audit and reconciliation.

Product rule: **The agent proposes. Paari governs. The provider executes. Reconciliation proves the outcome.**

Paari is not itself a bank, payment network, custodian or regulatory approval. It composes with providers and licensed institutions. The role-specific legal perimeter must be confirmed for each UAE integration and market.

## 2. Target users and use cases

- UAE treasury teams supervising a fleet of agents (including 100-agent deployments).
- Procurement and accounts-payable agents that propose supplier payments within mandate limits.
- Enterprise agents with scoped access to financial data, accounts, APIs and payment-provider capabilities.
- Multi-provider and cross-border payment orchestration where each provider adapter enforces its own documented authentication, execution and settlement contract.

## 3. SAFR runtime flow

1. **Ingress + Governance Envelope:** accept a strict, versioned action envelope; bind tenant, agent, parent, principal, resource, mandate, action context, trace/evidence references, freshness, signing key and canonical action digest.
2. **Agent Identity:** resolve the registered agent and parent in the authenticated tenant; validate active status, registered key, parent-signed delegation, signature, expiry and authority consistency.
3. **Principal, consent and authority:** verify current principal status, signed mandate/consent and delegation scope. Identity claims do not themselves grant spending authority.
4. **Resource and data governance:** resolve the tenant-scoped account/data/API resource and check current agent and principal grants for the specific action.
5. **Controls Repository:** retrieve the effective, versioned institutional, product, mandate and resource rules, including authorisation, validity, evidence quality, exposure and rate limits.
6. **Disposition Engine:** produce exactly one of `DENY`, `ESCALATE`, `AUTO_EXECUTE`, or `OBSERVE`, with versioned policy and reason/evidence record. `ESCALATE` blocks action until an authorised reviewer decides; `OBSERVE` permits an in-scope action with monitoring.
7. **Bounded authorization + review:** only the normal governance/payment path can mint an expiry-bound, single-use authorization for the exact action. Every changed action gets a new decision.
8. **Execution gateway:** consume the authorization atomically and route to a provider adapter with provider-side idempotency, authenticated transport/callbacks and explicit handling of unknown outcomes.
9. **Audit, evidence and reconciliation:** record every disposition; verify provider-side status and match amount/currency/transaction identifiers before a terminal success state is recorded.

## 4. What Paari controls and what it can retrieve

### Controls

- Organisation and agent registration, parent/child relationships, keys, capabilities, credential state, delegation validity and revocation.
- Principal identity evidence status, consent/mandate, resource/data/API access and intended purpose.
- Policy versions, financial and data-action scopes, per-transaction and aggregate exposure, rate limits, evidence thresholds, escalations and kill switches.
- Bounded authorization, provider route selection within configured policy, idempotency and permitted payment-state transitions.

### Governed evidence/records (tenant scoped and minimised)

- Agent/parent IDs, public-key thumbprints, delegation references and validity/revocation state.
- Verification provider, case reference, evidence digest, verification time, expiry, status and reason codes; collect/store raw identity documents only when justified and contractually/legal approved.
- Policy version, action digest, disposition, reason codes, approval evidence, authorization ID, execution events, provider references and reconciliation state.
- Data-access records and provider/API operation outcomes where those adapters are implemented.

The agent's own trace and evidence references are **claims**, not ground truth. Evidence needed for a control must be checked against an independent and authoritative source. This v2.7 envelope ingress stores a validation receipt; it explicitly does not independently verify all evidence or issue authorization.

## 5. Four SAFR dispositions

| Disposition | Required behavior |
|---|---|
| `DENY` | Reject before execution; no bounded authorization; persist reason and policy version. |
| `ESCALATE` | Put a hold on execution; require an authenticated and authorised reviewer, deadline/timeout and auditable approve/modify/decline. Modified actions must be re-evaluated. |
| `AUTO_EXECUTE` | Only after all mandatory identity, authority, policy, evidence, limit and resource checks pass; issue single-use transaction-bound authorization. |
| `OBSERVE` | Permit only within existing authority and scope; emit monitoring evidence. It must not broaden scope or carry authorization to later actions. |

## 6. Agent Card and delegation

Paari retains the v1 parent-registration model: the parent creates or registers the agent public key, signs a delegation binding agent key fingerprint, capabilities, payment limit, currency and validity, and Paari verifies that signature against the registered parent public key. Paari registers the agent and issues a signed Agent Card / Paari credential.

Private keys stay with their owner or an approved non-exportable key service. A public key, Agent Card or successful KYC/KYB check is not a payment mandate. Each payment still requires the relevant principal mandate, resource binding, policy decision and transaction-bound authorization.

## 7. Agent and data portability

The signed portability package can include the Agent Card, public keys/fingerprints, parent identity metadata and original parent-signed delegation. It must **not** export private keys, session/JWT tokens, user mandates, resource grants, provider credentials/tokens, bounded authorizations or tenant-private data. Import must verify Paari issuer trust out of band, verify both Paari and parent signatures, re-check status/revocation and establish destination-local principal consent, resources, policies and grants. Portability does not transfer spending authority.

Older agents whose persisted parent delegation predates v2.7 and does not preserve the original signature are not eligible for signed export; reissue/re-register a signed delegation rather than fabricate one.

## 8. UAE integration boundary

Potential integrations to evaluate—not integrations claimed to exist in this repository:

- **UAE PASS:** evaluate for supported user authentication, digital signing/eSeal and data/document-sharing flows. Treat it as an identity/authentication/signing source according to its contract; it is not by itself a complete enterprise KYB/UBO or AML programme.
- **Business KYC/KYB:** evaluate Sumsub's contracted corporate registry and ownership coverage for the exact UAE mainland and relevant free-zone entity types. A UAE-oriented alternative can be evaluated; provider selection depends on coverage, data residency, SLA, evidence provenance, cost and contract.
- **Open Finance:** evaluate how Paari fits as a technology provider, outsourced service, or potential Open Finance Provider with UAE counsel and a licensed participant. The CBUAE Open Finance Regulation contains licensing and participant requirements for services in its scope. Do not infer that Paari may initiate transactions just because a provider adapter exists.
- **KMS/HSM:** retain the provider-neutral signing interface; choose a concrete service only after validating supported Ed25519 operation, target-region availability, key protection, IAM separation, audit, rotation and recovery.

Official references reviewed:
- CBUAE Open Finance Regulation: https://rulebook.centralbank.ae/en/rulebook/open-finance-regulation
- CBUAE Introduction and Scope: https://rulebook.centralbank.ae/en/rulebook/introduction-and-scope-2
- UAE PASS documentation: https://docs.uaepass.ae/
- Sumsub business verification: https://docs.sumsub.com/docs/verify-businesses
- Sumsub business verification sources/coverage: https://docs.sumsub.com/docs/business-verification-sources
- AWS KMS CreateKey and key specifications: https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html

## 9. Current implementation vs target

Implemented in v2.7 source: strict Governance Envelope model and Ed25519 validation primitives; tenant-scoped envelope validation endpoint with anti-replay receipt; checks against registered agent/parent delegation, principal/resource state, grants and payment mandate/binding; signed Agent Card/parent delegation portability package; import-side validator requiring externally trusted issuer key; UAE home-jurisdiction metadata.

Not implemented/fully evidenced: the envelope validation route does not itself evaluate the complete versioned Controls Repository or issue a SAFR disposition/authorization. Its answer is `VALIDATED_ONLY`, with `policy_evaluated=false` and `execution_permitted=false`; the existing payment intent/governance/bounded-authorization path remains the path for payment execution. Full data/API execution interception for `data.read`, `data.write` and `api.invoke` is not yet delivered. Trusted KYC/KYB vendor adapter, managed KMS/HSM adapter, full human-review operations, independently protected audit storage, production PostgreSQL concurrency/soak tests, UAE regulatory opinion/licensing assessment, independent security review and partner sign-off are still outstanding.

Do not claim full SAFR conformance, UAE regulatory approval or live-money production readiness until the required behavior is enforced and independently tested end to end.
