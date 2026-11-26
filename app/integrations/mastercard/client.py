"""Mastercard Open Finance US sandbox adapter. Credentials stay server-side.

Endpoints and payloads follow the Open Finance US API family; validate against the
version enabled for your developer project before using beyond sandbox.
"""
from __future__ import annotations
import os, time
from typing import Any
import httpx

BASE_URL = os.getenv("MASTERCARD_API_BASE_URL", "https://api.finicity.com").rstrip("/")
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

class MastercardConfigError(RuntimeError): pass

class MastercardClient:
    def __init__(self, base_url: str | None = None):
        self.base_url = (base_url or BASE_URL).rstrip("/")
        self.partner_id = os.getenv("MASTERCARD_PARTNER_ID", "")
        self.partner_secret = os.getenv("MASTERCARD_PARTNER_SECRET", "")
        self.app_key = os.getenv("MASTERCARD_APP_KEY", "")
        if not (self.partner_id and self.partner_secret and self.app_key):
            raise MastercardConfigError("Set MASTERCARD_PARTNER_ID, MASTERCARD_PARTNER_SECRET and MASTERCARD_APP_KEY")
        self._token: str | None = None
        self._token_at = 0

    def _headers(self) -> dict[str, str]:
        if not self._token or time.time() - self._token_at > 90 * 60:
            with httpx.Client(timeout=25) as c:
                r = c.post(self.base_url + "/aggregation/v2/partners/authentication",
                    headers={"Finicity-App-Key": self.app_key, "User-Agent": USER_AGENT, "Content-Type":"application/json"},
                    json={"partnerId": self.partner_id, "partnerSecret": self.partner_secret})
                r.raise_for_status(); data = r.json()
            self._token = data.get("token") or data.get("accessToken")
            if not self._token: raise RuntimeError("Mastercard auth response missing token")
            self._token_at = time.time()
        return {"Finicity-App-Key": self.app_key, "Finicity-Partner-ID": self.partner_id,
                "Finicity-Timestamp": str(int(time.time())), "Authorization": f"Bearer {self._token}",
                "Content-Type":"application/json", "User-Agent": USER_AGENT}

    def request(self, method: str, path: str, payload: dict | None = None) -> Any:
        with httpx.Client(timeout=30) as c:
            r = c.request(method, self.base_url + path, headers=self._headers(), json=payload)
            r.raise_for_status()
            return r.json() if r.content else {}

    def create_test_customer(self, username: str, first_name: str, last_name: str) -> Any:
        return self.request("POST", "/aggregation/v2/customers/testing", {"username":username,"firstName":first_name,"lastName":last_name})
    def generate_connect_url(self, customer_id: str, redirect_uri: str | None = None) -> Any:
        payload = {"customerId": customer_id}
        if redirect_uri: payload["redirectUri"] = redirect_uri
        return self.request("POST", "/connect/v2/generate", payload)
    def refresh_accounts(self, customer_id: str) -> Any:
        return self.request("POST", f"/aggregation/v1/customers/{customer_id}/accounts", {})
    def accounts(self, customer_id: str) -> Any:
        return self.request("GET", f"/aggregation/v1/customers/{customer_id}/accounts")
    def transactions(self, customer_id: str, account_id: str, from_date: int, to_date: int) -> Any:
        return self.request("GET", f"/aggregation/v3/customers/{customer_id}/accounts/{account_id}/transactions?start={from_date}&end={to_date}")
