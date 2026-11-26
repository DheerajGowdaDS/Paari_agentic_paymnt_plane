"""Setu Account Aggregator FIU sandbox client.

This client retrieves consented financial data only. It never initiates payments
or uses Setu data as payment authority.
"""
from __future__ import annotations

import os
import time
from typing import Any

import httpx


DEFAULT_AUTH_BASE_URL = "https://uat.setu.co/api/v2"
DEFAULT_AA_BASE_URL = "https://fiu-sandbox.setu.co/v2"


class SetuAAConfigError(RuntimeError):
    """Raised when the required Setu AA sandbox settings are absent."""


class SetuAAUpstreamError(RuntimeError):
    """Raised when Setu rejects or cannot process a request."""


class SetuAAClient:
    def __init__(self, *, auth_base_url: str | None = None, aa_base_url: str | None = None):
        self.auth_base_url = (auth_base_url or os.getenv("SETU_AA_AUTH_BASE_URL", DEFAULT_AUTH_BASE_URL)).rstrip("/")
        self.aa_base_url = (aa_base_url or os.getenv("SETU_AA_BASE_URL", DEFAULT_AA_BASE_URL)).rstrip("/")
        self.client_id = os.getenv("SETU_AA_CLIENT_ID", "")
        self.client_secret = os.getenv("SETU_AA_CLIENT_SECRET", "")
        self.product_instance_id = os.getenv("SETU_AA_PRODUCT_INSTANCE_ID", "")
        if not all((self.client_id, self.client_secret, self.product_instance_id)):
            raise SetuAAConfigError(
                "Set SETU_AA_CLIENT_ID, SETU_AA_CLIENT_SECRET and SETU_AA_PRODUCT_INSTANCE_ID"
            )
        self._token: str | None = None
        self._token_expires_at = 0.0

    def _access_token(self) -> str:
        if self._token and time.monotonic() < self._token_expires_at:
            return self._token
        try:
            with httpx.Client(timeout=30) as client:
                response = client.post(
                    f"{self.auth_base_url}/auth/token",
                    headers={"Content-Type": "application/json"},
                    json={"clientID": self.client_id, "secret": self.client_secret},
                )
                response.raise_for_status()
                payload = response.json()
        except httpx.HTTPError as exc:
            raise SetuAAUpstreamError("Setu AA token request failed") from exc
        token_data = payload.get("data") if isinstance(payload, dict) else None
        token = token_data.get("token") if isinstance(token_data, dict) else None
        expires_in = token_data.get("expiresIn", 1800) if isinstance(token_data, dict) else 1800
        if not payload.get("success") or not isinstance(token, str) or not token:
            raise SetuAAUpstreamError("Setu AA token response did not contain a valid access token")
        try:
            ttl = max(1, int(expires_in) - 60)
        except (TypeError, ValueError):
            ttl = 1740
        self._token = token
        self._token_expires_at = time.monotonic() + ttl
        return token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._access_token()}",
            "Content-Type": "application/json",
            "x-product-instance-id": self.product_instance_id,
        }

    def request(self, method: str, path: str, payload: dict | None = None) -> Any:
        try:
            with httpx.Client(timeout=30) as client:
                response = client.request(method, f"{self.aa_base_url}{path}", headers=self._headers(), json=payload)
                response.raise_for_status()
                return response.json() if response.content else {}
        except httpx.HTTPError as exc:
            raise SetuAAUpstreamError(f"Setu AA request failed for {path}") from exc

    def account_availability(self, mobile_number: str) -> Any:
        return self.request("POST", "/account-availability", {"mobileNumber": mobile_number})

    def create_consent(self, consent: dict) -> Any:
        return self.request("POST", "/consents", consent)

    def get_consent(self, consent_id: str) -> Any:
        return self.request("GET", f"/consents/{consent_id}")

    def revoke_consent(self, consent_id: str) -> Any:
        return self.request("POST", f"/consents/{consent_id}/revoke")

    def create_data_session(self, consent_id: str, data_range: dict, data_format: str = "json") -> Any:
        return self.request(
            "POST",
            "/sessions",
            {"consentId": consent_id, "dataRange": data_range, "format": data_format},
        )

    def get_data_session(self, session_id: str) -> Any:
        return self.request("GET", f"/sessions/{session_id}")
