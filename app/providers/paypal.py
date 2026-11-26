"""PayPal Orders v2 adapter for Paari's regular checkout provider contract."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx

from app.providers.base import PaymentProvider, ProviderConfigError


PAYPAL_LIVE_API_BASE = "https://api-m.paypal.com"
PAYPAL_SANDBOX_API_BASE = "https://api-m.sandbox.paypal.com"
_ZERO_DECIMAL_CURRENCIES = {
    "BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "MGA", "PYG",
    "RWF", "UGX", "VND", "VUV", "XAF", "XOF", "XPF",
}
_THREE_DECIMAL_CURRENCIES = {"BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"}


def currency_exponent(currency: str) -> int:
    normalized = currency.upper()
    if normalized in _ZERO_DECIMAL_CURRENCIES:
        return 0
    if normalized in _THREE_DECIMAL_CURRENCIES:
        return 3
    return 2


def paypal_amount_to_minor_units(value: str | int | Decimal, currency: str) -> int:
    try:
        scaled = Decimal(str(value)) * (10 ** currency_exponent(currency))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("PayPal returned an invalid currency amount") from exc
    if not scaled.is_finite() or scaled != scaled.to_integral_value():
        raise ValueError("PayPal amount cannot be represented in currency minor units")
    return int(scaled)


def minor_units_to_paypal_amount(amount_minor_units: int, currency: str) -> str:
    if type(amount_minor_units) is not int or amount_minor_units <= 0:
        raise ValueError("amount must be a positive integer in minor units")
    exponent = currency_exponent(currency)
    amount = Decimal(amount_minor_units).scaleb(-exponent)
    return f"{amount:.{exponent}f}"


def paypal_request_id(operation: str, stable_key: str) -> str:
    """Produce a deterministic UUID per PayPal operation and Paari object."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"paari:paypal:{operation}:{stable_key}"))


class PayPalConfigError(ProviderConfigError):
    pass


class PayPalAdapter(PaymentProvider):
    """PayPal REST Orders v2 adapter.

    Pass an ``httpx.Client`` in tests. Production credentials and environment
    are read from PayPal-specific configuration; no Razorpay assumptions leak
    into this adapter.
    """

    provider_name = "paypal"

    def __init__(
        self,
        client: httpx.Client | None = None,
        client_id: str = "",
        client_secret: str = "",
        webhook_id: str = "",
        api_base: str = "",
    ):
        self._client = client
        self._client_id = client_id
        self._client_secret = client_secret
        self._webhook_id = webhook_id
        self._api_base_override = api_base
        self._access_token: str | None = None

    @property
    def client_id(self) -> str:
        return self._client_id or os.environ.get("PAYPAL_CLIENT_ID", "")

    @property
    def client_secret(self) -> str:
        return self._client_secret or os.environ.get("PAYPAL_CLIENT_SECRET", "")

    @property
    def webhook_id(self) -> str:
        return self._webhook_id or os.environ.get("PAYPAL_WEBHOOK_ID", "")

    @property
    def api_base(self) -> str:
        if self._api_base_override:
            return self._api_base_override.rstrip("/")
        environment = os.environ.get("PAYPAL_ENV", "sandbox").strip().lower()
        if environment == "live":
            return PAYPAL_LIVE_API_BASE
        if environment == "sandbox":
            return PAYPAL_SANDBOX_API_BASE
        return os.environ.get("PAYPAL_API_BASE", PAYPAL_SANDBOX_API_BASE).rstrip("/")

    def provenance(self) -> dict:
        base = self.api_base
        environment = (
            "live" if base == PAYPAL_LIVE_API_BASE else
            "test" if base == PAYPAL_SANDBOX_API_BASE else
            "simulated" if base else "unknown"
        )
        return {
            "provider_name": self.provider_name,
            "provider_environment": environment,
            "provider_key_id_prefix": self.client_id[:12] or None,
            "provider_api_base": base,
        }

    def _request_client(self) -> tuple[httpx.Client, bool]:
        if self._client is not None:
            return self._client, False
        if not self.client_id or not self.client_secret:
            raise PayPalConfigError("PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET must be configured")
        return httpx.Client(base_url=self.api_base, timeout=15.0), True

    def _access_token_for(self, client: httpx.Client) -> str:
        if self._access_token:
            return self._access_token
        if not self.client_id or not self.client_secret:
            raise PayPalConfigError("PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET must be configured")
        response = client.post(
            "/v1/oauth2/token",
            data={"grant_type": "client_credentials"},
            auth=(self.client_id, self.client_secret),
            headers={"Accept": "application/json", "Accept-Language": "en_US"},
        )
        response.raise_for_status()
        token = response.json().get("access_token")
        if not token:
            raise RuntimeError("PayPal OAuth response is missing access_token")
        self._access_token = str(token)
        return self._access_token

    def _request(self, method: str, path: str, *, json_body: dict | None = None,
                 headers: dict[str, str] | None = None) -> dict:
        client, close = self._request_client()
        try:
            request_headers = {"Authorization": f"Bearer {self._access_token_for(client)}"}
            if headers:
                request_headers.update(headers)
            response = client.request(
                method,
                path,
                json=json_body,
                headers=request_headers,
            )
            response.raise_for_status()
            if not response.content:
                return {}
            return response.json()
        finally:
            if close:
                client.close()

    @staticmethod
    def _normalize_capture(capture: dict) -> dict:
        amount = capture.get("amount") or {}
        currency = amount.get("currency_code")
        value = amount.get("value")
        normalized_status = {
            "COMPLETED": "captured",
            "PENDING": "pending",
            "DECLINED": "failed",
            "REFUNDED": "refunded",
        }.get(str(capture.get("status", "")).upper(), str(capture.get("status", "")).lower())
        return {
            "id": capture.get("id"),
            "status": normalized_status,
            "amount": paypal_amount_to_minor_units(value, currency) if value is not None and currency else None,
            "currency": currency,
            "order_id": ((capture.get("supplementary_data") or {}).get("related_ids") or {}).get("order_id"),
            "raw": capture,
        }

    @staticmethod
    def _normalize_order(order: dict) -> dict:
        purchase_units = order.get("purchase_units") or []
        unit = purchase_units[0] if purchase_units else {}
        amount = unit.get("amount") or {}
        currency = amount.get("currency_code")
        value = amount.get("value")
        links = order.get("links") or []
        approval = next((link.get("href") for link in links
                         if link.get("rel") in {"payer-action", "approve"}), None)
        return {
            "id": order.get("id"),
            "receipt": unit.get("custom_id") or unit.get("invoice_id"),
            "amount": paypal_amount_to_minor_units(value, currency) if value is not None and currency else None,
            "currency": currency,
            "status": str(order.get("status", "")).lower(),
            "approval_url": approval,
            "raw": order,
        }

    def create_payment(self, authorization_id: str, amount_minor_units: int,
                       currency: str, notes: dict | None) -> dict:
        payload = {
            "intent": "CAPTURE",
            "purchase_units": [{
                "reference_id": authorization_id,
                "custom_id": authorization_id,
                "invoice_id": authorization_id,
                "amount": {
                    "currency_code": currency.upper(),
                    "value": minor_units_to_paypal_amount(amount_minor_units, currency),
                },
                "description": str((notes or {}).get("paari_transaction_id", "Paari authorized payment"))[:127],
            }],
        }
        request_headers = {
            "PayPal-Request-Id": paypal_request_id("order", authorization_id),
            "Prefer": "return=representation",
        }
        for attempt in range(2):
            try:
                order = self._request(
                    "POST", "/v2/checkout/orders", json_body=payload, headers=request_headers,
                )
                normalized = self._normalize_order(order)
                if (not normalized["id"] or normalized["receipt"] != authorization_id
                        or normalized["amount"] != amount_minor_units
                        or normalized["currency"] != currency.upper()):
                    raise RuntimeError("PayPal order did not match Paari authorization bounds")
                return normalized
            except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                is_ambiguous = isinstance(exc, httpx.TransportError) or (
                    isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code >= 500
                )
                if is_ambiguous and attempt == 0:
                    continue
                if is_ambiguous:
                    raise httpx.TransportError("PayPal order submission outcome is unknown") from exc
                raise
        raise httpx.TransportError("PayPal order submission outcome is unknown")

    def get_order(self, order_id: str) -> dict:
        return self._normalize_order(self._request("GET", f"/v2/checkout/orders/{order_id}"))

    def capture_order(self, order_id: str, authorization_id: str) -> dict:
        order = self._request(
            "POST",
            f"/v2/checkout/orders/{order_id}/capture",
            headers={
                "PayPal-Request-Id": paypal_request_id("capture", authorization_id),
                "Prefer": "return=representation",
            },
        )
        return self._normalize_order(order)

    def get_payment(self, payment_id: str) -> dict:
        capture = self._request("GET", f"/v2/payments/captures/{payment_id}")
        return self._normalize_capture(capture)

    def fetch_payments(self, order_id: str) -> list[dict]:
        order = self._request("GET", f"/v2/checkout/orders/{order_id}")
        captures = []
        for unit in order.get("purchase_units") or []:
            captures.extend(((unit.get("payments") or {}).get("captures") or []))
        return [self._normalize_capture(capture) for capture in captures]

    def fetch_order_by_receipt(self, receipt: str) -> dict | None:
        """PayPal Orders v2 has no lookup-by-custom_id endpoint; never guess."""
        return None

    def verify_webhook(self, raw_body: bytes, signature: str = "", *,
                       headers: dict[str, str] | None = None) -> bool:
        if not self.webhook_id or not headers:
            return False
        try:
            event = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        normalized_headers = {key.lower(): value for key, value in headers.items()}
        required = {
            "auth_algo": normalized_headers.get("paypal-auth-algo"),
            "cert_url": normalized_headers.get("paypal-cert-url"),
            "transmission_id": normalized_headers.get("paypal-transmission-id"),
            "transmission_sig": normalized_headers.get("paypal-transmission-sig"),
            "transmission_time": normalized_headers.get("paypal-transmission-time"),
        }
        if not all(required.values()):
            return False
        result = self._request(
            "POST",
            "/v1/notifications/verify-webhook-signature",
            json_body={**required, "webhook_id": self.webhook_id, "webhook_event": event},
        )
        return result.get("verification_status") == "SUCCESS"

    @classmethod
    def normalize_webhook(cls, event: dict) -> dict:
        resource = event.get("resource") or {}
        event_type = str(event.get("event_type") or "")
        event_mapping = {
            "CHECKOUT.ORDER.APPROVED": "payment.approved",
            "PAYMENT.CAPTURE.COMPLETED": "payment.captured",
            "PAYMENT.CAPTURE.DENIED": "payment.failed",
        }
        if event_type == "CHECKOUT.ORDER.APPROVED":
            purchase_units = resource.get("purchase_units") or []
            first_unit = purchase_units[0] if purchase_units else {}
            amount = first_unit.get("amount") or {}
            order_id = resource.get("id")
            payment_id = None
        else:
            amount = resource.get("amount") or {}
            related_ids = ((resource.get("supplementary_data") or {}).get("related_ids") or {})
            order_id = related_ids.get("order_id")
            payment_id = resource.get("id")
        return {
            "event_id": event.get("id") or hashlib.sha256(
                json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            "event_type": event_mapping.get(event_type),
            "order_id": order_id,
            "payment_id": payment_id,
            "amount": paypal_amount_to_minor_units(amount["value"], amount["currency_code"])
            if amount.get("value") is not None and amount.get("currency_code") else None,
            "currency": amount.get("currency_code"),
            "status": str(resource.get("status", "")).lower(),
            "raw": event,
        }

    def refund(self, payment_id: str, amount_minor_units: int) -> dict:
        capture = self.get_payment(payment_id)
        if not capture.get("currency") or amount_minor_units <= 0:
            raise ValueError("PayPal refund requires a positive amount and a known capture currency")
        result = self._request(
            "POST",
            f"/v2/payments/captures/{payment_id}/refund",
            json_body={
                "amount": {
                    "currency_code": capture["currency"],
                    "value": minor_units_to_paypal_amount(amount_minor_units, capture["currency"]),
                },
                "custom_id": payment_id,
            },
            headers={
                "PayPal-Request-Id": paypal_request_id("refund", f"{payment_id}:{amount_minor_units}"),
                "Prefer": "return=representation",
            },
        )
        return result

    def reconcile(self, authorization_id: str) -> dict:
        order = self.fetch_order_by_receipt(authorization_id)
        return {"found": order is not None, "order": order}
