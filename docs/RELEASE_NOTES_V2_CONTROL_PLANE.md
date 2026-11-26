# Release notes — institutional control plane upgrade

## Added

- Nine-layer architecture mapping for organization/agent management, identity, principal consent, resource/data governance, financial authority, policy/risk, bounded authorization, execution, reconciliation and audit.
- Organization-scoped control keys with SHA-256-only persistence, explicit read/write scopes, key expiry/revocation and audit events.
- Root-admin organization suspension/reactivation; suspension revokes all organization control keys.
- Principal registration starts in `PENDING` at `low` assurance; organization attestation is explicit but does not imply external identity verification or elevate assurance. Client-supplied assurance elevation is rejected; a trusted identity/KYB adapter is required before high-assurance auto-execution.
- Governed resource registry with opaque resource references and rejection of obvious secret-like metadata; resource grants are time-bounded and action-scoped.
- Versioned tenant policies with ordered risk thresholds and one active version per policy name.
- Deterministic SAFR-style dispositions (`DENY`, `ESCALATE`, `AUTO_EXECUTE`, `OBSERVE`) with mandatory hard-deny precedence, server-derived risk/evidence facts and fail-closed behavior for missing/ambiguous authority.
- Durable per-intent control-plane decision with policy version, reason codes, risk/evidence scores, transaction digest and hash-chain audit record.
- Strict institutional payment-path integration enabled by `PAARI_CONTROL_PLANE_ENFORCEMENT=1`; production startup requires strict mode and signed mandates.
- Migration `da7e4a2b91c0_institutional_control_plane.py`.

## Preserved

- Existing parent-signed agent delegation, agent credential/card and proof-of-possession authentication.
- Signed user mandate, financial limits, single-use bounded authorization and provider idempotency contract.
- Provider state machine, webhook verification, reconciliation, multi-tenancy and hash-chained audit trail.

## Compatibility / rollout

- Development/sandbox can continue to use the legacy path when strict mode is off. Production modes cannot start without strict institutional enforcement and signed-mandate requirements.
- Apply `alembic upgrade head` before enabling strict mode.
- Open banking and stablecoin resource types can be governed, but certified live execution adapters for these rails are not included in this release. Do not configure a rail as live until its adapter, settlement lifecycle, authenticated callbacks, idempotency and reconciliation are implemented and certified.
