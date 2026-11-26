# LLM gateway and E2E operations

## Configure Kilo.ai

Create a local `.env` from `.env.example` and set:

```dotenv
PAARI_LLM_PROVIDER=kilo
KILO_API_BASE=https://ai-gateway.kilo.ai/api/v1
KILO_API_KEY=<your-kilo-jwt-api-key>
KILO_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free
```

Do not commit `.env`, paste API keys into logs, or distribute provider secrets in a ZIP. The free-model ID is a runtime choice, not an availability guarantee. `GET /models` catalog inclusion is necessary but not sufficient; the smoke script also sends a tool-calling request.

```bash
python scripts/llm_smoke.py
```

The model client sends `Authorization: Bearer <key>` to `/models` and `/chat/completions` under the configured API root. It expects OpenAI-compatible chat completion payloads and function tool calls whose `arguments` are JSON objects or JSON-encoded strings.

## E2E levels

### 1. Fast deterministic protocol rehearsal

```bash
python scripts/llm_agent_e2e.py --with-server --rehearse
```

Uses a throwaway SQLite DB and local provider stub; checks the protocol path without a remote model call. By default it skips provider submission.

### 2. Strict institutional control-plane + local provider stub

```bash
python scripts/llm_agent_e2e.py --with-server --rehearse --strict-control-plane --execute-stub
```

This is the repeatable security regression command for the nine-layer control plane. It checks server-reported strict enforcement, signed mandate enforcement, principal/source resource binding, both grants, versioned policy activation, an `AUTO_EXECUTE` disposition, audit evidence, a server-side over-limit refusal at 20x the delegation cap, and duplicate bounded-authorization rejection. `--execute-stub` does not talk to Razorpay: it uses the local simulator and is always test-only.

The current code does not ship a trusted OIDC/FAPI/KYB assurance adapter. In this specific local E2E mode only, the script sets synthetic assurance into a throwaway SQLite database so the positive authorization branch is exercised. This seeded test assertion is not valid KYC/KYB evidence and is not permitted against external servers.

### 3. Real model + Razorpay test order + strict control plane

Configure Kilo in `.env`, plus genuine **Razorpay test-mode** values for `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, and `RAZORPAY_WEBHOOK_SECRET`, then run:

```bash
python scripts/llm_agent_e2e.py --with-server --strict-control-plane
```

The harness queries the model catalog before creating agents, prints the provider/model identity without printing the API key, asks the LLM to use the authority/tool loop, records the strict disposition and causal audit, and tries a 20x over-cap adversarial request. On success the provider operation stops at creation of a **test-mode checkout order** (`PROVIDER_SUBMITTED`). It does not capture that order and does not prove provider settlement. A real provider order needs a payer/checkout and provider webhook; settlement claims must be based on verified callbacks and reconciliation.

## Never overstate a green result

- A `:free` model is not a production-grade model service-level guarantee; timeouts, model changes and rate limits are possible.
- A successful tool-call smoke probe is not a statistical reliability study. Run repeated probes and monitor failure rates before relying on a model operationally.
- An order created in Razorpay test mode is not a captured payment.
- A locally seeded identity-assurance fixture proves the control flow only; it is not evidence of identity proofing.
- `AUTO_EXECUTE` is Paari's governance disposition. Provider execution and final settlement are separate states.
