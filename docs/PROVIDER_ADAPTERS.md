# Payment Provider Adapters

Paari supports Razorpay Orders and PayPal Orders v2 for standard, payer-approved checkout. Provider selection is server-side; clients cannot choose the provider on a payment request. Apply database changes with `alembic upgrade head` before deploying this version.

## Default Organization

Set `PAARI_DEFAULT_PROVIDER` to `razorpay` (default) or `paypal`.

For Razorpay, configure `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, and `RAZORPAY_WEBHOOK_SECRET` as before.

For PayPal, configure `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `PAYPAL_WEBHOOK_ID`, and `PAYPAL_ENV=sandbox|live`. The API base defaults to the matching PayPal endpoint; `PAYPAL_API_BASE` is available for controlled test environments. Production guards require `PAYPAL_ENV=live` and `https://api-m.paypal.com`.

## Tenant Providers

Create a `ProviderAccount` row with the tenant's `org_id` and `provider_name` (`razorpay` or `paypal`). Credentials are read from environment variables using the tenant tag (the organization ID with non-alphanumeric characters removed and uppercased), for example `PAYPAL_CLIENT_ID__ORGB`. PayPal requires `PAYPAL_CLIENT_ID__{TAG}`, `PAYPAL_CLIENT_SECRET__{TAG}`, `PAYPAL_WEBHOOK_ID__{TAG}`, and optionally `PAYPAL_ENV__{TAG}` / `PAYPAL_API_BASE__{TAG}`. Tenant credentials never fall back to another tenant or the default organization.

Configure the tenant's PayPal webhook URL as `/v1/payments/webhooks/paypal/{org_id}` so an event can be verified with that tenant's webhook ID even when no local order row is found. The default organization uses `/v1/payments/webhooks/paypal`. Subscribe to `CHECKOUT.ORDER.APPROVED` and capture-completed/denied events. PayPal signatures are verified by calling PayPal's `verify-webhook-signature` API with the transmission headers, raw event, and configured webhook ID. A verified buyer-approval event causes Paari to capture the already-bounded order server-side.

## Recovery And Settlement

Razorpay order creation uses a unique receipt and recovers a duplicate by fetching that receipt, then checking receipt, amount, and currency. PayPal Orders v2 supports `PayPal-Request-Id` for order creation; Paari uses a deterministic operation-specific request ID and retries an ambiguous create once with the same ID. PayPal does not expose an Orders v2 lookup-by-`custom_id` endpoint, so an order whose ID was never received and whose same-ID retry remains unresolved stays `PROVIDER_UNKNOWN`; reconciliation does not guess or create a new order under a different key.

PayPal amounts are converted through explicit currency minor-unit exponents before Paari's exact amount/currency checks. The provider order response includes `approval_url` for checkout clients. Neither a PayPal order nor payer approval alone means settlement: the approval webhook triggers capture, and only the resulting matching capture plus a direct capture read can transition to `PAID`.

These adapters implement the regular payment interface. PayPal is not configured as an agentic/provider-native settlement adapter. Shared adapter contract and operation tests live in `tests/test_provider_contract.py`; PayPal webhook state tests live in `tests/test_paypal_integration.py`.

## Shared Adapter Contract

Both concrete adapters are driven through the same behavioural matrix in
`tests/test_provider_contract.py` (`_assert_shared_adapter_contract`): create,
duplicate-submission recovery, direct payment lookup, payment-attempt listing,
refund, reconcile result shape, and webhook rejection. The idempotency mechanism
remains provider-specific and is asserted separately (Razorpay receipt recovery,
PayPal deterministic `PayPal-Request-Id`).

Known provider limits are explicit rather than emulated:

- PayPal Orders v2 has no lookup-by-`custom_id`, so `fetch_order_by_receipt`
  returns `None` and `reconcile()` reports `found: false`. It never invents an
  order ID.
- Neither adapter implements order cancellation; the base
  `PaymentProvider.cancel` raises `NotImplementedError` instead of calling an
  unverified endpoint.


## Provider References

- [PayPal Orders v2 create order](https://developer.paypal.com/api/orders/v2/orders-create)
- [PayPal Orders v2 show order](https://developer.paypal.com/api/orders/v2/orders-get)
- [PayPal Orders v2 capture order](https://developer.paypal.com/api/orders/v2/orders-capture)
- [PayPal idempotency](https://developer.paypal.com/api/rest/reference/idempotency)
- [PayPal webhook signature verification](https://developer.paypal.com/api/webhooks/v1/verify-webhook-signature-post)