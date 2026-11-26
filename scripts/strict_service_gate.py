"""Non-mutating acceptance gate for the actual persistent Paari sandbox service.

Checks the posture reported by the service itself. It creates no agents, intents,
authorizations, provider orders, webhook registrations, or test identities.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import httpx


def evaluate_gate(health: dict, readiness_status: int, readiness: dict, *,
                  require_trusted_identity_provider: bool = False) -> list[tuple[str, bool, str]]:
    signer = health.get("signing_backend") or {}
    idp = health.get("principal_identity_provider") or {"configured": False, "trusted_evidence": False}
    checks = [
        ("service healthy", health.get("service") == "paari" and health.get("status") == "ok", str(health.get("status"))),
        ("database connected", health.get("database") == "up", str(health.get("database"))),
        ("strict institutional control plane enabled", health.get("control_plane_enforcement") is True,
         str(health.get("control_plane_enforcement"))),
        ("signed mandates required", health.get("require_signed_mandate") is True,
         str(health.get("require_signed_mandate"))),
        ("mandates required by runtime posture", health.get("mandate_required") is True,
         str(health.get("mandate_required"))),
        ("test environment", health.get("env") == "sandbox" and health.get("provider_environment") == "test",
         f"app_env={health.get('env')} provider_env={health.get('provider_environment')}"),
        ("real Razorpay test adapter", health.get("provider") == "real-razorpay(test-mode)", str(health.get("provider"))),
        ("signer healthy", signer.get("healthy") is True, f"backend={signer.get('backend')} managed={signer.get('managed')} healthy={signer.get('healthy')}"),
        ("readiness green", readiness_status == 200 and readiness.get("status") == "ready",
         f"http={readiness_status} status={readiness.get('status')}"),
    ]
    idp_ok = idp.get("configured") is True and idp.get("trusted_evidence") is True
    checks.append(("trusted principal identity provider", idp_ok,
                   f"provider={idp.get('provider')} configured={idp.get('configured')} trusted_evidence={idp.get('trusted_evidence')}"))
    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.environ.get("PAARI_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--require-trusted-identity-provider", action="store_true",
                        help="fail unless a trusted principal KYC/KYB adapter reports configured and trusted evidence")
    args = parser.parse_args(argv)
    base = args.base_url.rstrip("/")
    try:
        health_response = httpx.get(f"{base}/health", timeout=5.0)
        health_response.raise_for_status()
        ready_response = httpx.get(f"{base}/health/ready", timeout=5.0)
        try:
            readiness = ready_response.json()
            health = health_response.json()
        except ValueError as exc:
            raise RuntimeError("health endpoint returned invalid JSON") from exc
    except Exception as exc:
        print(f"[FAIL] unable to inspect {base}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    # Output only non-secret posture fields.
    print(json.dumps({
        "service_url": base,
        "environment": health.get("env"),
        "database": health.get("database"),
        "mandate_mode": health.get("mandate_mode"),
        "mandate_required": health.get("mandate_required"),
        "signed_mandates_required": health.get("require_signed_mandate"),
        "control_plane_enforcement": health.get("control_plane_enforcement"),
        "provider": health.get("provider"),
        "provider_environment": health.get("provider_environment"),
        "signing_backend": health.get("signing_backend"),
        "principal_identity_provider": health.get("principal_identity_provider"),
        "readiness_status": ready_response.status_code,
        "blocking_checks": readiness.get("blocking_checks", []),
    }, indent=2))

    checks = evaluate_gate(health, ready_response.status_code, readiness,
                           require_trusted_identity_provider=args.require_trusted_identity_provider)
    failures = []
    for name, passed, detail in checks:
        # Identity is a warning for service-posture checks, but blocks any strict
        # positive-payment gate unless the caller explicitly requires the adapter.
        if name == "trusted principal identity provider" and not args.require_trusted_identity_provider and not passed:
            print(f"[NOTE] {name}: {detail}; positive strict payment E2E remains blocked")
            continue
        print(f"[{'PASS' if passed else 'FAIL'}] {name}: {detail}")
        if not passed:
            failures.append(name)
    if failures:
        print("STRICT SERVICE GATE FAILED: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("STRICT SERVICE GATE GREEN" if args.require_trusted_identity_provider else
          "STRICT SERVICE POSTURE GREEN; positive strict live payment remains blocked until trusted identity is integrated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
