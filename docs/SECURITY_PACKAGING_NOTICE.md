# Security packaging notice — Paari v4.0.0

The uploaded v3.8.1/v3.8.2 input archive included local development secrets and runtime artifacts that must never be distributed: a populated `.env` (including sandbox credentials), the local unencrypted Ed25519 issuer signing key, generated local CA/server private keys and SQLite databases. Treat all credentials and private keys in the input archive as exposed.

Before using any environment that relied on those artifacts:

1. Rotate the Setu AA client secret and any other provider credentials found in the input `.env`.
2. Rotate Paari admin/control credentials and all application encryption secrets; update the corresponding local/deployment secret stores.
3. Replace the Paari issuer signing key and local CA/server keys. Revoke/reissue affected Agent Cards, certificates or credentials wherever the old key material may have been trusted.
4. Re-encrypt or intentionally discard any local data that was protected with a rotated encryption key. Do not simply replace a key if encrypted records must remain readable; use a controlled migration with old/new key versions and verified backups.
5. Review access logs and any external locations where the input archive was copied.

The v4.0.0 distributable excludes populated `.env` files, `.pem`/`.key`/`.p12` private-key material, generated CA/server certificates, SQLite databases and journals, Python caches, pytest caches and local agent/tool state. It includes a placeholder-only `.env.example`; replace every placeholder with independently generated values. Do not copy the old `.env` or any old private key into the new release.

Setu financial-context snapshots use AES-256-GCM with a dedicated `PAARI_FINANCIAL_CONTEXT_ENCRYPTION_SECRET`. A legacy `PAARI_V37_DATA_ENCRYPTION_SECRET` fallback remains for local sandbox compatibility only. Production must replace application-managed environment secrets with managed KMS/HSM key custody and an approved key versioning, rotation, backup and recovery design. The current environment-secret implementation is not a production key-management solution.

A new local signing key may be generated for a fresh sandbox when absent. Production must provision its durable signing identity through an approved managed KMS/HSM adapter. This v4.0.0 package remains a local development / sandbox integration release and is not a production-certified or regulator-approved financial service.
