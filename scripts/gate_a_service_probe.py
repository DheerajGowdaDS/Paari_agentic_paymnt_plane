"""Non-mutating service/readiness probe for a running Paari sandbox.

This small probe checks HTTP liveness, database state, strict governance, signed
mandate posture, signer health, and readiness. It is supplemental; it does not
replace the five behavioral Gate A scenarios in the v2.4 session report or the
strict E2E harness.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE_URL = os.environ.get("PAARI_SERVICE_URL", "http://127.0.0.1:8000").rstrip("/")


def get(path: str) -> tuple[int, dict]:
    request = urllib.request.Request(f"{BASE_URL}{path}", headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status = response.status
            body = response.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read()
    except Exception as exc:
        raise RuntimeError(f"GET {path} failed: {type(exc).__name__}: {exc}") from exc
    try:
        parsed = json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError(f"GET {path} returned non-JSON body") from exc
    return status, parsed


def main() -> int:
    failures: list[str] = []
    try:
        status, health = get("/health")
        checks = [
            ("liveness endpoint", status == 200 and health.get("service") == "paari"),
            ("database connected", health.get("database") == "up"),
            ("strict control plane enabled", health.get("control_plane_enforcement") is True),
            ("signed mandates required", health.get("require_signed_mandate") is True),
            ("signer healthy", bool((health.get("signing_backend") or {}).get("healthy"))),
        ]
        ready_status, readiness = get("/health/ready")
        checks.append(("readiness endpoint", ready_status == 200 and readiness.get("status") == "ready"))
    except Exception as exc:
        print(f"[FAIL] service probe: {exc}", file=sys.stderr)
        return 1

    for name, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}")
        if not passed:
            failures.append(name)
    print(f"service={BASE_URL} environment={health.get('env')} provider={health.get('provider')} "
          f"provider_environment={health.get('provider_environment')}")
    if failures:
        print("SERVICE PROBE FAILED: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("SERVICE PROBE GREEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
