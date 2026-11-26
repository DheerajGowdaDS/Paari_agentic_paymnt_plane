# Paari v2.5 — Secret Rotation and Clean Baseline Runbook

This runbook is required before sharing the v2.5 archive or continuing the prior test-mode trial. The session summary file shared for engineering hand-off contained test-mode key material and a webhook secret. Treat those values as exposed; do not copy them into a ticket, chat, source file, screenshot, or subsequent report.

## Operator actions — perform in provider/control dashboards

1. **Razorpay test key pair:** rotate/regenerate the test API secret in the Razorpay dashboard where supported, update `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET` in the local ignored `.env`, then verify Paari readiness and one test-mode order creation. If the dashboard's key lifecycle requires creating a new key pair, retire the old pair after the new pair is confirmed.
2. **Webhook secret:** create a fresh high-entropy webhook secret, update `RAZORPAY_WEBHOOK_SECRET` in Paari and the exact same secret in the Razorpay webhook configuration. Deliver a genuine test-mode capture event and verify signature validation. Old-secret and tampered payloads must return 401.
3. **Paari admin key:** generate a new high-entropy secret of at least 32 characters, update `PAARI_ADMIN_API_KEY` in the ignored `.env` and all authorized operator clients, restart, and verify the old key fails. Do not use the value printed in the session report.
4. **Temporary ingress:** stop the quick tunnel and webhook listener when not required; delete `docker-compose.override.yml` if no longer required. Do not expose a database port in a shared/deployed environment without an explicit network/security requirement.
5. **Signing key:** the test PEM used locally is not a production secret-management approach. For sandbox hygiene, stop the app before retiring the local key and regenerate a new development key if exposure is suspected. For production, use a real managed KMS/HSM adapter; never put its credentials or a private key in the repo or ZIP.

## Clean baseline and release hygiene

- Keep `.env`, all real `.env.*` files, PEM/private keys, local DBs, runtime logs, temporary databases, and override compose files out of source-control commits and ZIPs. `.env.example` may contain placeholders only.
- Run the suite with `.env` absent and with a privately configured `.env`; the results should be the same. Never publish environment dumps.
- Run compile, complete pytest, PostgreSQL migrations/`alembic check`, Docker build and health/readiness checks on CI or a Docker-enabled host.
- Archive the exact commit/tree that passed these checks; calculate and verify SHA-256 for the distributed ZIP.
- Keep the production boot blocks in place until managed signing, trusted identity, concurrency/soak testing and independent review have evidence of completion.

## This repository does not perform remote rotation

No secrets are rotated by this runbook automatically. The operator must perform rotation in Razorpay and Paari deployment-secret management, then verify old credentials stop working. The v2.5 source archive must never contain real credentials.
