import logging
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse
from sqlalchemy import text

from app.routers import agents, auth, parents, payments, v1
from app.integrations.mastercard.router import router as mastercard_router
from app.integrations.setu.router import router as setu_aa_router
from app.control_plane.router import router as control_plane_router
from app.treasury_router import router as treasury_router
from app.receivers.router import router as receiver_router
from app.protocol.discovery import document as protocol_discovery
from app.protocol.errors import paari_exception_handler, PaariHTTPException
from app.config import load_config, PaariEnv
from app.database import resolve_database_url
from app.mtls_gateway import (GatewayMTLSMiddleware, router as mtls_gateway_router,
                              trusted_proxy_cidrs_valid, mtls_ca_certificate_valid)

# Phase 6: tables are created by Alembic migrations (`alembic upgrade head`),
# never implicitly at import - importing the app must not touch the database.

logger = logging.getLogger("paari")

# The only Razorpay API base that moves real money.
PRODUCTION_API_BASE = "https://api.razorpay.com/v1"
PAYPAL_LIVE_API_BASE = "https://api-m.paypal.com"
PAYPAL_SANDBOX_API_BASE = "https://api-m.sandbox.paypal.com"
_PLACEHOLDER_TOKENS = {
    "replace", "placeholder", "changeme", "example", "dummy", "todo",
    "your", "sample", "insert", "fillme", "setme", "xxxx", "xxx",
}


def _is_placeholder(value: str | None) -> bool:
    """Detect template secrets without rejecting ordinary values by substring."""
    candidate = str(value or "").strip()
    if not candidate:
        return True
    if re.search(r"<[^>]*>|\{[^}]*\}", candidate):
        return True
    tokens = {token for token in re.split(r"[^a-z0-9]+", candidate.casefold()) if token}
    return bool(tokens & _PLACEHOLDER_TOKENS)


def startup_guards(config: dict) -> list[str]:
    """Cross-check the deployment's own configuration and return reasons to refuse.

    These exist because the failure mode is silent and one-directional: a
    simulator pointed at a production database produces genuine-looking
    `PAID` evidence, and a development SQLite file pointed at a production
    posture makes an operator believe they are live. Neither announces itself,
    so both are refused at boot rather than discovered during an audit.
    """
    reasons: list[str] = []
    env = config.get("env")
    url = config.get("database_url") or resolve_database_url()
    is_live = config.get("is_live")
    wants_postgres = is_live or env in (PaariEnv.PROD, PaariEnv.PROD_LIVE)

    if wants_postgres and not url.startswith(("postgresql://", "postgresql+psycopg://")):
        scheme = url.split("://", 1)[0] if "://" in url else url
        reasons.append(
            f"PAARI_ENV={env} / PAARI_LIVE=1 requires a PostgreSQL DATABASE_URL, "
            f"got a {scheme!r} target. A SQLite file is a development database and "
            "must not back a live deployment."
        )

    provider_name = os.environ.get("PAARI_DEFAULT_PROVIDER", "razorpay").strip().lower()
    if env in (PaariEnv.PROD, PaariEnv.PROD_LIVE) or is_live:
        if provider_name == "razorpay":
            api_base = os.environ.get("RAZORPAY_API_BASE", "")
            if api_base != PRODUCTION_API_BASE:
                reasons.append(
                    f"PAARI_ENV={env} requires RAZORPAY_API_BASE={PRODUCTION_API_BASE}, "
                    f"got {api_base or '(unset)'}. Pointing a production deployment at a "
                    "local simulator would let simulated captures mint real, durable "
                    "PAID evidence."
                )
        elif provider_name == "paypal":
            paypal_env = os.environ.get("PAYPAL_ENV", "sandbox").strip().lower()
            paypal_api_base = os.environ.get(
                "PAYPAL_API_BASE",
                PAYPAL_LIVE_API_BASE if paypal_env == "live" else PAYPAL_SANDBOX_API_BASE,
            ).rstrip("/")
            if paypal_env != "live" or paypal_api_base != PAYPAL_LIVE_API_BASE:
                reasons.append(
                    f"PAARI_ENV={env} with PayPal requires PAYPAL_ENV=live and "
                    f"PAYPAL_API_BASE={PAYPAL_LIVE_API_BASE}; got {paypal_api_base!r}."
                )
        else:
            reasons.append(f"Unsupported PAARI_DEFAULT_PROVIDER={provider_name!r} for production")
        if os.environ.get("PAARI_RECEIVER_ENFORCEMENT") != "1":
            reasons.append("Production requires PAARI_RECEIVER_ENFORCEMENT=1 for beneficiary and receiving-institution enforcement")
        if len(os.environ.get("PAARI_BENEFICIARY_HASH_SECRET", "")) < 32:
            reasons.append("Production requires a separately provisioned PAARI_BENEFICIARY_HASH_SECRET (minimum 32 characters)")
        if not config.get("mandate_required"):
            reasons.append(
                f"PAARI_ENV={env} must run with the autonomous posture "
                "(PAARI_MODE=autonomous): a live deployment that treats a user "
                "mandate as optional can authorize payments the user never granted."
            )
        if os.environ.get("PAARI_CONTROL_PLANE_ENFORCEMENT") != "1":
            reasons.append(
                f"PAARI_ENV={env} requires PAARI_CONTROL_PLANE_ENFORCEMENT=1; "
                "legacy authorization must not bypass principal/resource/policy governance."
            )
        if os.environ.get("PAARI_REQUIRE_SIGNED_MANDATE") != "1":
            reasons.append(
                f"PAARI_ENV={env} requires PAARI_REQUIRE_SIGNED_MANDATE=1; "
                "unsigned user mandates must never authorize production payments."
            )
        admin_key = os.environ.get("PAARI_ADMIN_API_KEY", "")
        if len(admin_key) < 32:
            reasons.append("Production requires PAARI_ADMIN_API_KEY to be at least 32 characters of high-entropy secret material")
        if env == PaariEnv.PROD_LIVE or is_live:
            if provider_name == "razorpay":
                key_id = os.environ.get("RAZORPAY_KEY_ID", "")
                if not key_id.startswith("rzp_live_"):
                    reasons.append("PAARI_ENV=prod-live requires a Razorpay live-mode key ID (rzp_live_*); test keys cannot authorize live deployment")
            elif provider_name == "paypal":
                for name in ("PAYPAL_CLIENT_ID", "PAYPAL_CLIENT_SECRET", "PAYPAL_WEBHOOK_ID"):
                    if not os.environ.get(name):
                        reasons.append(f"PAARI_ENV=prod-live with PayPal requires {name}")
        # These gates inspect the adapter actually loaded by the process; an
        # environment variable alone must never assert that a managed key exists.
        try:
            from app.security import signing_backend_status
            signer_status = signing_backend_status()
        except Exception:
            signer_status = {"backend": "unavailable", "managed": False, "healthy": False}
        if not signer_status.get("managed"):
            reasons.append(
                "Live production is blocked: no managed KMS/HSM signing adapter is active; "
                "local PEM signing is permitted only for sandbox/test use."
            )
        elif not signer_status.get("healthy"):
            reasons.append("Live production is blocked: configured managed KMS/HSM signer health check failed.")
        # A module path is not sufficient evidence of trust: the loaded provider
        # must implement the contract, be explicitly pinned by provider ID, and pass
        # an active healthcheck. Principal results are refreshed at payment decision
        # and strict production execution time.
        try:
            from app.identity_providers.runtime import identity_provider_status
            identity_status = identity_provider_status()
        except Exception:
            identity_status = {"configured": False, "trusted_evidence": False, "healthy": False}
        if not identity_status.get("configured"):
            reasons.append("Live production is blocked: no trusted KYC/KYB identity-provider adapter is configured; synthetic principal assurance is not production identity proof.")
        elif not identity_status.get("trusted_evidence"):
            reasons.append("Live production is blocked: identity-provider ID is not explicitly trusted or its contract check failed.")
        elif not identity_status.get("healthy"):
            reasons.append("Live production is blocked: trusted KYC/KYB identity-provider healthcheck failed.")
        if os.environ.get("PAARI_REQUIRE_SAFR_ENVELOPE") != "1":
            reasons.append("Live production is blocked: PAARI_REQUIRE_SAFR_ENVELOPE=1 is required so each provider consume is bound to a processed SAFR envelope.")
        if os.environ.get("PAARI_REQUIRE_MTLS_INGRESS") != "1":
            reasons.append("Live production is blocked: PAARI_REQUIRE_MTLS_INGRESS=1 is required for external-agent payment ingress.")
        if not os.environ.get("PAARI_MTLS_CA_CERT"):
            reasons.append("Live production is blocked: PAARI_MTLS_CA_CERT must identify the trusted agent client-certificate CA.")
        if not trusted_proxy_cidrs_valid():
            reasons.append("Live production is blocked: PAARI_MTLS_TRUSTED_PROXY_CIDRS must contain valid CIDR network(s) for the dedicated ingress proxy.")
        if not mtls_ca_certificate_valid():
            reasons.append("Live production is blocked: PAARI_MTLS_CA_CERT must point to a valid PEM CA certificate with CA signing constraints.")
    return reasons


@asynccontextmanager
async def lifespan(app: FastAPI):
    config = load_config()
    app.state.paari_config = config
    refusals = startup_guards(config)
    if refusals:
        raise RuntimeError(
            "Paari refuses to start:\n  - " + "\n  - ".join(refusals)
        )
    if os.environ.get("PAARI_LIVE") == "1":
        provider_name = os.environ.get("PAARI_DEFAULT_PROVIDER", "razorpay").strip().lower()
        if provider_name == "razorpay":
            required_live_vars = ["RAZORPAY_KEY_ID", "RAZORPAY_KEY_SECRET", "RAZORPAY_WEBHOOK_SECRET", "PAARI_ADMIN_API_KEY"]
        elif provider_name == "paypal":
            required_live_vars = ["PAYPAL_CLIENT_ID", "PAYPAL_CLIENT_SECRET", "PAYPAL_WEBHOOK_ID", "PAARI_ADMIN_API_KEY"]
        else:
            raise RuntimeError(f"PAARI_LIVE=1 does not support provider {provider_name!r}")
        signing_backend = os.environ.get("PAARI_SIGNING_BACKEND", "local_pem").strip().lower()
        if signing_backend in {"kms", "hsm", "kms_hsm"}:
            required_live_vars.extend(["PAARI_SIGNING_ADAPTER", "PAARI_SIGNING_KEY_ID"])
        else:
            required_live_vars.append("PAARI_SIGNING_KEY_PATH")
        for name in required_live_vars:
            if not os.environ.get(name):
                raise RuntimeError(f"PAARI_LIVE=1 requires {name} to be set")
    if not os.environ.get("PAARI_ADMIN_API_KEY"):
        logger.warning("PAARI_ADMIN_API_KEY unset - running with an ephemeral admin key")
    worker = None
    if os.environ.get("PAARI_RECONCILE_EMBEDDED_WORKER", "1") != "0":
        from app.reconcile_worker import ReconciliationWorker, ReconciliationAlertSink
        worker = ReconciliationWorker(
            interval_seconds=int(os.environ.get("PAARI_RECONCILE_INTERVAL", "60")),
            dead_letter_after=int(os.environ.get("PAARI_RECONCILE_DEAD_LETTER_AFTER", "5")),
            alert_sink=ReconciliationAlertSink(webhook_url=os.environ.get("PAARI_RECONCILE_ALERT_WEBHOOK", "")),
        )
        worker.start()
        logger.info("Embedded reconciliation worker started (interval=%ds, dead_letter_after=%d)",
                    worker.interval_seconds, worker.dead_letter_after)
    else:
        logger.info("Embedded reconciliation worker disabled; run the dedicated worker process")
    try:
        yield
    finally:
        if worker is not None:
            worker.stop()
            logger.info("Reconciliation worker stopped")

app = FastAPI(
    title="Paari v4.0 Federated Agentic Financial Control Plane",
    description=(
        "Agentic Payment Protocol v1.0 + user-payment-authority extension — trust, delegation, authentication, "
        "payment governance, bounded provider authorization, verified settlement, "
        "reconciliation, audit, and multi-tenancy. Legacy Phase 1-5 routes remain "
        "for compatibility; external agents should use /v1 and /.well-known/paari."
    ),
    version="4.0.0",
    lifespan=lifespan,
)

app.add_exception_handler(PaariHTTPException, paari_exception_handler)

app.include_router(parents.router)
app.include_router(agents.router)
app.include_router(auth.router)
app.include_router(mastercard_router)
app.include_router(setu_aa_router)
app.include_router(payments.router)
app.include_router(v1.router)
app.include_router(control_plane_router)
app.include_router(treasury_router)
app.include_router(mtls_gateway_router)
app.include_router(receiver_router)
from app.v36.router import router as onboarding_v36_router
app.include_router(onboarding_v36_router)
from app.v37.router import router as enterprise_v37_router
app.include_router(enterprise_v37_router)
from app.federation.router import router as federation_router
app.include_router(federation_router)
from app.portal_extension import router as product_portal_router
app.include_router(product_portal_router)


class _SecurityResponseHeaders:
    """Pure-ASGI middleware that sets baseline security response headers.

    v3.7.1 shipped this as a Starlette ``BaseHTTPMiddleware``
    (``@app.middleware("http") security_response_headers``). ``BaseHTTPMiddleware``
    wraps every request in an anyio ``BlockingPortal`` and awaits an internal
    ``asyncio.Event`` to hand the response back. Under pytest-asyncio's per-test
    event-loop lifecycle that Event rebinds across loops and raises
    ``RuntimeError: ... bound to a different event loop`` - which surfaced as an
    ``ExceptionGroup`` and broke 34 TestClient-based tests in the combined suite.
    A pure ASGI middleware creates no anyio portal and no asyncio primitives, so it
    is safe under any event-loop lifecycle while emitting byte-identical headers.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        # Same setdefault semantics as the old BaseHTTPMiddleware version: only
        # add a header the route did not already set. No CSP, so Swagger UI still works.
        baseline = [
            (b"x-content-type-options", b"nosniff"),
            (b"cross-origin-resource-policy", b"same-origin"),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"no-referrer"),
        ]

        async def send_with_headers(message):
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers") or [])
                existing = {name.lower() for name, _ in headers}
                headers.extend(item for item in baseline if item[0] not in existing)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


app.add_middleware(GatewayMTLSMiddleware)
app.add_middleware(_SecurityResponseHeaders)


@app.get("/.well-known/paari")
def paari_discovery(request: Request):
    return protocol_discovery(str(request.base_url).rstrip("/"))


# Separate first-party front ends. Both use the same-origin Paari API by
# default; administrators and organization users enter through different UI
# documents and retain distinct authentication boundaries.
_WEB_ROOT = Path(__file__).resolve().parent.parent / "web"
_ORGANIZATION_PORTAL_HTML = _WEB_ROOT / "organization" / "index.html"
_INTERNAL_CONSOLE_HTML = _WEB_ROOT / "internal" / "index.html"


@app.get("/portal", include_in_schema=False)
@app.get("/organization", include_in_schema=False)
def organization_portal():
    return FileResponse(_ORGANIZATION_PORTAL_HTML, media_type="text/html")


@app.get("/console", include_in_schema=False)
def internal_paari_console():
    return FileResponse(_INTERNAL_CONSOLE_HTML, media_type="text/html")


def _signing_backend_health_metadata() -> dict:
    try:
        from app.security import signing_backend_status
        return signing_backend_status()
    except Exception:
        return {"backend": "unavailable", "key_id": None, "managed": False, "healthy": False}


def _principal_identity_provider_status() -> dict:
    # Parent admin approval is not a substitute for principal KYC/KYB. Report
    # the active, explicitly pinned adapter rather than an environment claim.
    from app.identity_providers.runtime import identity_provider_status
    return identity_provider_status()


@app.get("/health")
def health():
    db_ok = False
    try:
        from app.database import engine
        with engine.connect() as c:
            c.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        pass
    config = getattr(app.state, "paari_config", {})
    from app.config import mandate_policy
    active_mandate_policy = mandate_policy()
    from app.providers.agentic import autonomous_settlement_configured, get_agentic_provider
    from app.providers.agentic import AdapterStatus
    _agentic = get_agentic_provider()
    _configured = _agentic.status() == AdapterStatus.CONFIGURED
    agentic_name = _agentic.__class__.__name__
    agentic_provenance = {}
    provenance = getattr(_agentic, "provenance", None)
    if callable(provenance):
        try:
            agentic_provenance = provenance() or {}
        except Exception:
            agentic_provenance = {}
    return {
        "status": "ok" if db_ok else "degraded",
        "service": "paari",
        "env": config.get("env", "unknown"),
        "home_jurisdiction": config.get("home_jurisdiction", os.environ.get("PAARI_HOME_JURISDICTION", "AE").strip().upper()),
        "jurisdiction_metadata_only": True,
        "database": "up" if db_ok else "down",
        # Governance posture is operator-visible, not an environment guess.
        "mandate_mode": active_mandate_policy.mode.value,
        "mandate_required": active_mandate_policy.mandate_required,
        "require_signed_mandate": active_mandate_policy.require_signed_mandate,
        # Report the actual active security posture for operators and E2E probes.
        "control_plane_enforcement": os.environ.get("PAARI_CONTROL_PLANE_ENFORCEMENT") == "1",
        "receiver_enforcement": os.environ.get("PAARI_RECEIVER_ENFORCEMENT") == "1"
            or os.environ.get("PAARI_LIVE") == "1"
            or os.environ.get("PAARI_ENV", "").lower() in {"prod", "prod-live"},
        "federation_enforcement": os.environ.get("PAARI_FEDERATION_ENFORCEMENT") == "1"
            or os.environ.get("PAARI_LIVE") == "1"
            or os.environ.get("PAARI_ENV", "").lower() in {"prod", "prod-live"},
        "safr_envelope_required": os.environ.get("PAARI_REQUIRE_SAFR_ENVELOPE") == "1",
        "treasury_budget_required": os.environ.get("PAARI_REQUIRE_TREASURY_BUDGET") == "1",
        "receiver_precheck_required": (os.environ.get("PAARI_REQUIRE_RECEIVER_PRECHECK") == "1"
            or os.environ.get("PAARI_LIVE") == "1"
            or os.environ.get("PAARI_ENV", "sandbox").lower() in {"prod", "prod-live"}),
        "mtls_ingress_required": os.environ.get("PAARI_REQUIRE_MTLS_INGRESS") == "1"
            or os.environ.get("PAARI_LIVE") == "1"
            or os.environ.get("PAARI_ENV", "sandbox").lower() in {"prod", "prod-live"},
        "mtls_trusted_proxy_configured": trusted_proxy_cidrs_valid(),
        "mtls_ca_certificate_valid": mtls_ca_certificate_valid(),
        "kyb_simulation_enabled": (os.environ.get("PAARI_KYB_SIMULATION") == "1"
            and os.environ.get("PAARI_ENV", "sandbox").strip().lower() in {"sandbox", "test", "local"}
            and os.environ.get("PAARI_LIVE") != "1"),
        "signing_backend": _signing_backend_health_metadata(),
        # Parent administrative trust is not a substitute for a trusted
        # principal KYC/KYB identity provider. Report this separately.
        "principal_identity_provider": _principal_identity_provider_status(),
        # Honest capability flags: configured means an adapter is bound;
        # autonomous_settlement means it claims to support no-human-checkout.
        # Neither implies a real-money payment has actually settled.
        "agentic_adapter_configured": _configured,
        "agentic_provider": agentic_name,
        "autonomous_settlement": autonomous_settlement_configured(),
        "agentic_provider_environment": agentic_provenance.get("provider_environment", "unknown"),
        "agentic_provider_api_base": agentic_provenance.get("provider_api_base"),
        # Provider identity, reported by the process that actually talks to the
        # provider. Proof harnesses must READ this instead of inferring a mode
        # from their own os.environ.
        **provider_identity(),
    }


@app.get("/health/ready")
def readiness(response: Response):
    """Readiness is stricter than liveness and fails closed on key governance gates.

    /health answers whether the process and database are alive. Load balancers and
    deployers should use /health/ready before admitting payment traffic. The endpoint
    intentionally does not expose secret values or key material.
    """
    live = health()
    env = str(live.get("env", "unknown"))
    signer_status = _signing_backend_health_metadata()
    key_path = os.environ.get("PAARI_SIGNING_KEY_PATH", "").strip()
    if not key_path:
        try:
            from app.security import _KEY_PATH
            key_path = _KEY_PATH
        except Exception:
            key_path = ""
    local_key_present = bool(key_path and os.path.isfile(key_path) and not _is_placeholder(key_path))
    signer_configured = bool(signer_status.get("managed") and signer_status.get("key_id")) or local_key_present
    provider_name = os.environ.get("PAARI_DEFAULT_PROVIDER", "razorpay").strip().lower()
    if provider_name == "razorpay":
        provider_credentials_present = (
            os.environ.get("RAZORPAY_KEY_ID", "").startswith(("rzp_test_", "rzp_live_"))
            and not _is_placeholder(os.environ.get("RAZORPAY_KEY_ID"))
            and not _is_placeholder(os.environ.get("RAZORPAY_KEY_SECRET"))
        )
        provider_webhook_present = not _is_placeholder(os.environ.get("RAZORPAY_WEBHOOK_SECRET"))
    elif provider_name == "paypal":
        provider_credentials_present = (
            not _is_placeholder(os.environ.get("PAYPAL_CLIENT_ID"))
            and not _is_placeholder(os.environ.get("PAYPAL_CLIENT_SECRET"))
        )
        provider_webhook_present = not _is_placeholder(os.environ.get("PAYPAL_WEBHOOK_ID"))
    else:
        provider_credentials_present = False
        provider_webhook_present = False

    checks = {
        "database": live.get("database") == "up",
        "control_plane_enforcement": live.get("control_plane_enforcement") is True,
        "receiver_enforcement": live.get("receiver_enforcement") is True,
        "federation_enforcement": live.get("federation_enforcement") is True,
        "signed_mandates_required": live.get("require_signed_mandate") is True,
        "safr_envelope_required": live.get("safr_envelope_required") is True,
        "treasury_budget_required": (os.environ.get("PAARI_ENV", "sandbox").lower() not in {"prod", "prod-live"}
            and os.environ.get("PAARI_LIVE") != "1") or os.environ.get("PAARI_REQUIRE_TREASURY_BUDGET") == "1",
        "receiver_precheck_required": (os.environ.get("PAARI_ENV", "sandbox").lower() not in {"prod", "prod-live"}
            and os.environ.get("PAARI_LIVE") != "1") or os.environ.get("PAARI_REQUIRE_RECEIVER_PRECHECK") == "1",
        "mtls_ingress_configured": (not live.get("mtls_ingress_required") or
            (live.get("mtls_trusted_proxy_configured") is True and live.get("mtls_ca_certificate_valid") is True)),
        "strong_admin_key_present": (len(os.environ.get("PAARI_ADMIN_API_KEY", "")) >= 32
            and not _is_placeholder(os.environ.get("PAARI_ADMIN_API_KEY"))),
        "payment_provider_credentials_present": provider_credentials_present,
        "provider_webhook_configured": provider_webhook_present,
        "signing_backend_configured": signer_configured,
        "signing_backend_healthy": bool(signer_status.get("healthy")),
    }
    if provider_name == "razorpay":
        checks["razorpay_test_or_live_key_present"] = provider_credentials_present
        checks["webhook_secret_present"] = provider_webhook_present
    launch_blockers = []
    if env in (PaariEnv.PROD, PaariEnv.PROD_LIVE, "prod", "prod-live") or os.environ.get("PAARI_LIVE") == "1":
        if not signer_status.get("managed"):
            launch_blockers.append("managed KMS/HSM signing adapter is not active; local PEM signing is sandbox/test only")
        if not signer_status.get("healthy"):
            launch_blockers.append("configured signing backend health check failed")
        identity_status = _principal_identity_provider_status()
        if not identity_status.get("configured"):
            launch_blockers.append("trusted KYC/KYB identity-provider adapter is not configured")
        elif not identity_status.get("trusted_evidence"):
            launch_blockers.append("identity-provider ID is not explicitly trusted or its contract check failed")
        elif not identity_status.get("healthy"):
            launch_blockers.append("trusted identity-provider healthcheck failed")
        if os.environ.get("PAARI_REQUIRE_SAFR_ENVELOPE") != "1":
            launch_blockers.append("PAARI_REQUIRE_SAFR_ENVELOPE=1 is required for transaction-bound provider execution")
        if os.environ.get("PAARI_REQUIRE_TREASURY_BUDGET") != "1":
            launch_blockers.append("PAARI_REQUIRE_TREASURY_BUDGET=1 is required so every payment authorization reserves shared tenant exposure")
        if os.environ.get("PAARI_REQUIRE_RECEIVER_PRECHECK") != "1":
            launch_blockers.append("PAARI_REQUIRE_RECEIVER_PRECHECK=1 is required for signed receiver acceptance before payment execution")
        if os.environ.get("PAARI_REQUIRE_MTLS_INGRESS") != "1":
            launch_blockers.append("PAARI_REQUIRE_MTLS_INGRESS=1 is required for agent payment ingress")
        if not os.environ.get("PAARI_MTLS_CA_CERT") or not os.path.isfile(os.environ.get("PAARI_MTLS_CA_CERT", "")):
            launch_blockers.append("trusted mTLS agent CA certificate is unavailable")
        if not os.environ.get("PAARI_MTLS_TRUSTED_PROXY_CIDRS", "").strip():
            launch_blockers.append("trusted mTLS proxy CIDRs are not configured")
        launch_blockers.append("PostgreSQL concurrency and provider settlement certification must be completed before live launch")
    blocking_checks = [name for name, passed in checks.items() if not passed]
    ready = not blocking_checks and not launch_blockers
    response.status_code = 200 if ready else 503
    return {
        "status": "ready" if ready else "not_ready",
        "service": "paari",
        "environment": env,
        "checks": checks,
        "blocking_checks": blocking_checks,
        "production_launch_blockers": launch_blockers,
        "note": "A ready sandbox is not a certification for live-money use.",
    }


def provider_identity() -> dict:
    """Non-secret description of where provider calls would actually go.

    Never raises: /health must stay answerable while a deployment is still
    wiring credentials, and an unreadable provider is exactly the state an
    operator needs to see.
    """
    unknown = {
        "provider": "unknown",
        "provider_environment": "unknown",
        "provider_api_base": None,
        "provider_key_id_prefix": None,
    }
    try:
        from app.providers.base import get_provider
        prov = get_provider().provenance()
    except Exception:
        return unknown
    environment = prov.get("provider_environment") or "unknown"
    provider_name = prov.get("provider_name") or "unknown"
    label = {
        ("razorpay", "live"): "real-razorpay(live)",
        ("razorpay", "test"): "real-razorpay(test-mode)",
        ("razorpay", "simulated"): "local-simulator",
        ("paypal", "live"): "real-paypal(live)",
        ("paypal", "test"): "real-paypal(sandbox)",
        ("paypal", "simulated"): "local-paypal-simulator",
    }.get((provider_name, environment), "unconfigured")
    configured = bool(prov.get("provider_key_id_prefix"))
    return {
        "provider": label if configured else "unconfigured",
        "provider_name": provider_name,
        "provider_environment": environment,
        "provider_api_base": prov.get("provider_api_base"),
        "provider_key_id_prefix": prov.get("provider_key_id_prefix"),
    }
