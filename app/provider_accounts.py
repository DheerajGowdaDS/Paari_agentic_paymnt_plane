"""Strict per-organization provider routing with isolated credentials."""
import os
import re
from sqlalchemy.orm import Session
from app import models
from app.providers.razorpay import RazorpayAdapter, RazorpayConfigError
from app.providers.paypal import PayPalAdapter, PayPalConfigError, PAYPAL_LIVE_API_BASE, PAYPAL_SANDBOX_API_BASE


def _env_tag(org_id: str) -> str:
    return re.sub(r"\W", "", org_id).upper()


def get_provider_for_org(db: Session, org_id: str | None):
    resolved = org_id or "default"
    if resolved == "default":
        # The default organization follows PAARI_DEFAULT_PROVIDER. Hardcoding
        # Razorpay here contradicted the documented provider selection and
        # silently ignored a configured PayPal default.
        from app.providers.base import get_provider
        return get_provider()
    acct = db.query(models.ProviderAccount).filter_by(org_id=resolved).first()
    if acct is None:
        raise RazorpayConfigError(f"No payment provider account is configured for organization {resolved}")
    tag = _env_tag(resolved)
    provider_name = (acct.provider_name or "razorpay").strip().lower()
    if provider_name == "razorpay":
        key_id = os.environ.get(f"RAZORPAY_KEY_ID__{tag}", "")
        key_secret = os.environ.get(f"RAZORPAY_KEY_SECRET__{tag}", "")
        webhook_secret = os.environ.get(f"RAZORPAY_WEBHOOK_SECRET__{tag}", "")
        if not key_id or not key_secret:
            raise RazorpayConfigError(f"Razorpay credentials are missing for organization {resolved}")
        if not webhook_secret:
            raise RazorpayConfigError(f"Razorpay webhook secret is missing for organization {resolved}")
        return RazorpayAdapter(key_id=key_id, key_secret=key_secret, webhook_secret=webhook_secret)
    if provider_name == "paypal":
        client_id = os.environ.get(f"PAYPAL_CLIENT_ID__{tag}", "")
        client_secret = os.environ.get(f"PAYPAL_CLIENT_SECRET__{tag}", "")
        webhook_id = os.environ.get(f"PAYPAL_WEBHOOK_ID__{tag}", "")
        if not client_id or not client_secret or not webhook_id:
            raise PayPalConfigError(f"PayPal client credentials and webhook ID are required for organization {resolved}")
        environment = os.environ.get(f"PAYPAL_ENV__{tag}", "sandbox").strip().lower()
        api_base = os.environ.get(f"PAYPAL_API_BASE__{tag}", "")
        if not api_base:
            api_base = PAYPAL_LIVE_API_BASE if environment == "live" else PAYPAL_SANDBOX_API_BASE
        return PayPalAdapter(
            client_id=client_id,
            client_secret=client_secret,
            webhook_id=webhook_id,
            api_base=api_base,
        )
    raise RazorpayConfigError(f"Unsupported payment provider {provider_name!r} for organization {resolved}")
