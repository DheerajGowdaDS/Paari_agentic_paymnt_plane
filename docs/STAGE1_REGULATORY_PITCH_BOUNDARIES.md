# Paari Stage 1: regulator and institutional briefing boundaries

## Product statement

Paari is an agent identity, delegated-authority, policy-governance and payment-control layer. Its intended role is to authenticate agent workloads, validate the authority carried by an Agent Card, evaluate organization and user mandates, enforce SAFR and institutional policies, and produce traceable decision evidence. The agent proposes; Paari's control plane decides; a separately authorized bank, payment service provider or regulated payment institution executes and settles the movement of funds.

## Responsibilities (proposed operating model; not a legal opinion)

- **Parent organization:** responsible for the agents it registers, the authority and mandates it delegates, its configured limits and oversight of agent activity, subject to the applicable contract and law.
- **Agent:** acts only within its identity, parent delegation, user mandate and applicable control-plane decision. An agent does not obtain payment authority merely by being registered.
- **Paari:** operates the identity, governance and risk-control service. It must remain accountable for its own contractual, security, operational and regulatory duties. It is not designed to hold customer funds in the intended non-custodial deployment model.
- **Payment institution / bank / PSP:** performs only the regulated functions it has agreed and is legally authorized to perform, including payment execution, settlement, custody or safeguarding where applicable.

The allocation above must be reviewed by qualified counsel in each launch jurisdiction. It must not be represented as transferring or excluding any non-delegable statutory duty.

## Sandbox versus production evidence

The local KYB workflow (`PAARI_KYB_SIMULATION=1`) can simulate `SIMULATED_VERIFIED`, `REVIEW_REQUIRED`, `REJECTED` and `UNAVAILABLE` outcomes. A simulated approval is explicitly marked `sandbox_only=true` and `legal_identity_verified=false`. Its trust tier is `sandbox_kyb`; it is not provider-backed KYC/KYB and must never be described as regulatory evidence.

The local mTLS profile uses a developer-generated sandbox CA and local certificate files. The API checks CA signature, Agent Card subject/SAN binding, certificate validity, proxy origin, certificate registry status, agent status and parent status. This proves the reference workflow locally, not the suitability of the local CA for a regulated production deployment.

Payment-intent and strict institutional-control-plane decisions now persist a reason-code catalogue version, human explanations, server-side policy evaluations and observed/configured evidence fields. For example, the local velocity control records the observed number of requests, its configured maximum and time window. Only server-known fields are populated. A missing field remains null rather than being inferred. Some security rejection detail is deliberately hidden from the external caller to limit identity enumeration; the full reason is retained in the restricted audit trail.

## Production / regulator review blockers

The current build is **not production-ready, not certified and not regulator-approved**. Before live launch or claims of regulatory compliance, complete at minimum:

1. Jurisdiction-specific legal perimeter assessment, licensing/outsourcing analysis, customer terms, parent responsibility documents, data protection impact assessment and retention rules.
2. Production KYC/KYB provider contracts, due diligence, authorized access, UBO/director/representative checks, freshness/reverification policy and exception handling for each launch jurisdiction.
3. Enterprise CA lifecycle with managed HSM/KMS, key custody separation, certificate enrollment, rotation, short-lived issuance, revocation propagation, recovery and compromise drills.
4. Independent threat model, penetration test, secure SDLC review, SBOM/dependency scanning, secrets management, tenant-isolation review and vulnerability remediation.
5. PostgreSQL multi-worker concurrency/load/failover testing, backup restoration, disaster recovery, append-only/WORM external audit anchoring and independent audit verification.
6. Provider/bank integration certification, idempotency and reconciliation evidence, settlement failure handling, safeguarding/custody boundaries and written operating procedures.
7. Operational controls: incident response, emergency agent/tenant kill switch, access reviews, maker-checker for privileged changes, monitoring, alerting, service availability and change management.
8. Formal regulator/bank engagement and evidence submission under the applicable jurisdiction and activity perimeter.

## Accurate pitch wording

Use: **"Paari Stage 1 is a locally runnable control-plane security and governance demonstrator. It demonstrates sandbox mTLS ingress, certificate-to-Agent-Card binding and revocation, simulated KYB exception journeys, structured SAFR decision evidence and a full local acceptance-test path. Production integrations and independent assurance remain explicit launch gates."**

Do not use: "production-ready", "regulator-approved", "fully automated production KYB", "certified zero-trust gateway", or "Paari has no regulatory liability" based on this build.
