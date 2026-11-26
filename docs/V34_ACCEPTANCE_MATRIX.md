# Paari v3.4 acceptance matrix

| Control | In this development build | What remains |
|---|---|---|
| Sender identity/parent delegation | Preserved original Paari modules | Live KYB/identity-provider validation and independent security review |
| Receiver institution registry | Tenant-bound, admin-approved, audit logged | Trusted external registry/KYB evidence and renewal |
| Receiving institution key | Ed25519 public-key pinned and checked on signed claim | HSM-backed receiver signing, key rotation and authenticated institutions |
| Beneficiary controls | Alias, currency, max, block, HMAC fingerprint | Ownership/beneficiary name validation; sanctions/AML provider |
| Receiver at payment intent | Fail closed if flag enabled | Full integration with institutional policy risk scoring |
| Receiver at authorization consume | Recheck before atomic reservation | Multi-worker PostgreSQL race/fault testing |
| Signed receiver acknowledgement | Bound to allowed intent, fresh signature, replay guard | Independent receiving bank API corroboration |
| Payment settlement | Existing PAID requires provider reconciliation | Beneficiary-credit finality as distinct end state / evidence |
| Open Finance, treasury, stablecoin | Rail types supported as registry labels | Actual provider adapters, liquidity controls and chain finality |
| SAFR | Preserved v3.x enforcement path | External conformance review, full staffed human review |
| UI/UX | Professional local operator portal, real API calls, proof viewer | Production SSO, role permissions, secure web session handling |
| PostgreSQL | Alembic migration supplied | Production-version PostgreSQL migration/failure testing |
| Security | Local unit and API tests, revocation, replay, cross tenant | SAST/DAST, external pen test, CI and regulatory approval |

**No claim is made that a signed receiver assertion alone proves final beneficiary credit.** This distinction must remain visible in Paari's UI and reports.
