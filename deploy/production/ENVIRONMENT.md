# Paari v4.0 production deployment environment

The compose topology in `deploy/production/docker-compose.yml` is a self-hosted
reference deployment, not a certification that a given cloud account or payment
provider is production-approved. Public TLS/WAF should terminate at a managed
ingress or load balancer; the API is bound to host loopback by default. The
Compose example also expects the trusted agent CA certificate at
`deploy/production/secrets/paari_agent_ca.crt`; provision this file through a
secret-management/deployment process before starting the profile. Do not commit
the certificate or its private key.

Create `.env.production` at the repository root from `.env.production.example`
and inject real values from a secret manager. Never commit the populated file.
The production profile requires PostgreSQL, control-plane enforcement, signed
mandates, SAFR envelope enforcement, receiver/federation enforcement, mTLS,
managed KMS/HSM signing, trusted identity-provider evidence, and a treasury
budget policy per tenant/currency before authorizations are issued.

The migration service is a one-off job. API replicas must not run Alembic on
startup. The reconciliation worker runs as a separate process so increasing API
replicas does not multiply reconciliation loops. Scale the worker only after
validating the deployment's database locking, provider rate limits and lease
settings against the intended workload.

Before enabling live payment execution, complete PostgreSQL concurrency tests,
provider-specific autonomous settlement tests, disaster recovery and restore
tests, KMS/HSM key lifecycle checks, external penetration testing, privacy/legal
review, and applicable licensing/regulatory assessments. Paari does not itself
become a bank, Account Aggregator, payment aggregator, or payment system operator
merely by deploying this software.
