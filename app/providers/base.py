"""Provider abstraction. Exactly one method per provider capability; the
routers call get_provider(), never a concrete adapter module directly."""
from abc import ABC, abstractmethod


class ProviderConfigError(RuntimeError):
    """Provider credentials or routing configuration is unavailable."""


class PaymentProvider(ABC):
    @abstractmethod
    def create_payment(
        self,
        authorization_id: str,
        amount_minor_units: int,
        currency: str,
        notes: dict | None,
    ) -> dict:
        """Create or recover the object for authorization_id after ambiguity.

        Adapters must use the provider's documented duplicate-submission
        contract and validate any recovered object against the request bounds.
        """

    @abstractmethod
    def get_payment(self, payment_id: str) -> dict:
        """Fetch one provider payment by its id."""

    @abstractmethod
    def fetch_payments(self, order_id: str) -> list:
        """All payment attempts on one order, oldest first (empty when none)."""

    @abstractmethod
    def fetch_order_by_receipt(self, receipt: str) -> dict | None:
        """Find an order the adapter never learned the id of (recovery path
        for PROVIDER_UNKNOWN). Returns None when nothing matches or when the
        provider exposes no lookup-by-receipt contract; never guess."""

    @abstractmethod
    def verify_webhook(self, raw_body: bytes, signature: str = "", *,
                       headers: dict[str, str] | None = None) -> bool:
        """Verify a webhook using provider-specific headers and configuration."""

    @abstractmethod
    def normalize_webhook(self, event: dict) -> dict:
        """Normalize provider event identity, order/payment ids, status and values."""

    @abstractmethod
    def refund(self, payment_id: str, amount_minor_units: int) -> dict:
        """Full or partial refund of a captured payment."""

    def cancel(self, order_id: str) -> dict:
        """Cancel an uncaptured order. Not every provider supports this -
        adapters without a provider-side cancel leave this raising."""
        raise NotImplementedError(f"{type(self).__name__} has no order cancel")

    @abstractmethod
    def reconcile(self, authorization_id: str) -> dict:
        """Answer 'what does the provider actually hold for this
        authorization?' as {"found": bool, "order": dict | None}.

        `found: False` means "not found or this provider exposes no
        lookup-by-authorization contract". Adapters must not fabricate an
        order to make it True."""


def get_provider() -> PaymentProvider:
    """Construct the configured default-org provider adapter."""
    import os

    provider_name = os.environ.get("PAARI_DEFAULT_PROVIDER", "razorpay").strip().lower()
    if provider_name == "razorpay":
        from app.providers.razorpay import RazorpayAdapter
        return RazorpayAdapter()
    if provider_name == "paypal":
        from app.providers.paypal import PayPalAdapter
        return PayPalAdapter()
    raise ProviderConfigError(f"Unsupported default payment provider {provider_name!r}")
