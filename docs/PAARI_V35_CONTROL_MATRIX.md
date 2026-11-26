# Paari v3.5 — Infrastructure Control Matrix

| Risk | Control surface | Current evidence | Full production requirement |
|---|---|---|---|
| Spoofed agents | Authenticated agent session, per-request proof, signed Agent Card | Session and verified key references | Institutional identity validation, hardware-bound client keys |
| Portable-agent privilege escalation | Identity-only Agent Card and staging import; no authority transfer | Pinned issuer/card/parent signature | Destination provisioning, cross-org revocation notification |
| Missing user consent | Signed user mandate and v3.5 signed USER agreement | Signature and document/policy hash | Verified user identity, consent UX, legal basis and revocation handling |
| Unauthorized sending institution | SENDER_ORG agreement and active policy digest | Signed policy receipt, signer status | Institutional SSO, maker-checker policy activation |
| Unauthorized recipient | Receiver registry, beneficiary check, receiver-signed agreement | Approved pinned key, exact beneficiary reference | Independent KYB, beneficiary account ownership, sanctions checks |
| Policy version drift | Active policy digest bound to signed agreement | Digest, policy name/version, execution re-evaluation | Distributed policy signed delivery, trust rotation |
| Replay / double-spend | Existing sender-constrained request proof and atomic bounded usage | JTI/usage count, payment audit events | Cross-region concurrency/failure and DR testing |
| Altered payment context | Signed payment-context envelope with hash chained audit reference | Server-side signature and immutable bound fields | Issuer key rotation/history, external audit anchoring |
| Pretended settlement | CAPTURED nonterminal; provider corroboration before PAID | Payment and provider evidence separated from receiver attestation | Independent verified receiving-side credit or chain finality |
| Counterparty network compromise | Independent receiver signature on an agreement; no private key on server | Receiver signature vs pinned key | mTLS, FAPI profiles where applicable, transport replay checks |
| Data leakage | Context references and policy hashes; no bank details or conversations | Stored field minimization | Jurisdictional privacy assessment and retention controls |
| Human escalation | Existing hold/preview flows | Held decision; no fabricated execution | Separate reviewer identity, bound approval, full revalidation to execution |

## Regulatory demo acceptance gate

An empty database, fresh actors, unique signatures, actual request origin, multiple organizations, real policies, a full sender-to-receiver execution simulator, authenticated reviews and directly retrieved PostgreSQL/audit evidence must all be demonstrated together. This complete gate is **not yet passed** by this development increment.
