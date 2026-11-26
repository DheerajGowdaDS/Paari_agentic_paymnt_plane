# Paari v3.8.2 — Mastercard Open Finance Sandbox Adapter

Added a sandbox-only Mastercard Open Finance US adapter with server-side authentication/token renewal, Test Drive customer creation, Connect URL generation, account refresh/listing, transaction retrieval, normalized account-context output, status route and admin-key protected endpoints. Added docs and two adapter-normalizer tests.

Validated: compileall; 2 adapter tests; Stage 1 checks 17/17 and local demo checks 17/17. Full repository pytest was started but timed out in this environment; no full-suite pass is claimed. External Mastercard API calls were not run because the user's credentials have not been supplied.

This is an integration scaffold that requires validating exact API schema/version and sandbox credentials in the user's developer project. Consent and tenant ownership enforcement, audited revocation lifecycle, production secrets management and live execution are not implemented by this connector. Mastercard Open Finance data retrieval does not initiate or execute payments.
