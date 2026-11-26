"""The agent loop: model proposes, broker decides what may be signed."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from typing import Any

from .tools import TOOL_SCHEMAS

SYSTEM_PROMPT = """You are a shopping agent that can pay through Paari, a governance layer.

You do not hold a signing key and you cannot pay by asking directly. You propose; Paari
authorizes a single-use ticket; a broker you cannot touch executes it.

Rules:
- Call get_delegation before proposing a payment and stay inside the cap it reports.
- Use only ids that a tool returned to you. Invented ids never reach the server.
- A denial is a decision about these values, not an obstacle. Do not retry the same
  proposal, do not split it into smaller repeated payments, and do not ask again for a
  higher limit. Report the denial instead.
- Confirm at most the payment the user asked for, then verify it with read_proof.
- When you are done, or blocked, answer in plain prose and stop calling tools.
"""


@dataclass
class Outcome:
    ok: bool
    turns: int = 0
    tool_calls: int = 0
    usage: dict[str, int] = field(default_factory=dict)
    messages: list[dict[str, Any]] = field(default_factory=list)
    transcript: list[dict[str, Any]] = field(default_factory=list)
    final_text: str | None = None
    payment_executed: bool = False
    settled_state: str | None = None
    transaction_id: str | None = None
    provider_order_id: str | None = None
    proof_final_state: str | None = None
    proof_verified: bool = False
    proof_terminal: bool = False
    proof_webhook_verified: bool = False
    proof_settlement_source: str | None = None
    proof_provider_environment: str | None = None
    error: str | None = None

    @property
    def tool_log(self) -> list[str]:
        return [entry["tool"] for entry in self.transcript]

    def billed(self, key: str) -> int:
        return self.usage.get(key, 0)


def _assistant_message(reply, call_ids: list[str]) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": reply.text,
        "tool_calls": [
            {"id": call_ids[i], "type": "function",
             "function": {"name": call.name, "arguments": json.dumps(call.arguments)}}
            for i, call in enumerate(reply.tool_calls)
        ],
    }


_COMPLETION_CLAIM = re.compile(
    r"\b(?:payment|transaction|order)\b.{0,80}\b(?:completed|complete|paid|settled|successful|succeeded)\b"
    r"|\b(?:completed|paid|settled|successfully paid)\b.{0,80}\b(?:payment|transaction|order)\b",
    flags=re.IGNORECASE,
)


def _authoritative_final_text(outcome: Outcome, model_text: str | None) -> str:
    """Never let model prose outrank Paari's execution and proof state.

    The model is not a source of truth for settlement. This helper replaces
    completion claims with deterministic status unless a verified proof bundle
    contains PAID, a valid audit chain, a verified webhook and provider evidence.
    """
    text = (model_text or "").strip()
    if outcome.payment_executed:
        state = (outcome.proof_final_state or outcome.settled_state or "UNKNOWN").upper()
        order = outcome.provider_order_id
        order_ref = f" Provider order: {order}." if order else ""
        verified_provider_paid = (
            outcome.proof_verified
            and state == "PAID"
            and outcome.proof_terminal
            and outcome.proof_webhook_verified
            and outcome.proof_settlement_source == "provider"
            and outcome.proof_provider_environment in {"test", "live"}
        )
        if verified_provider_paid:
            if outcome.proof_provider_environment == "test":
                return (
                    "Razorpay test-mode evidence and reconciliation report PAID. This is sandbox evidence; "
                    "no real money moved."
                    + order_ref
                )
            return (
                "Paari's proof bundle reports PAID after provider evidence and reconciliation were verified."
                + order_ref
            )
        if state == "PAID" and outcome.proof_settlement_source == "simulator":
            return (
                "The local simulator reports PAID, but this is not evidence of a real provider settlement."
                + order_ref
            )
        return (
            f"Paari authorized and submitted the payment request, but settlement is not verified. "
            f"Current evidence state: {state}. Do not treat this as a completed payment."
            + order_ref
        )

    # A model can produce confident prose even if it never completed a provider
    # execution. Only rewrite explicit payment-completion claims; preserve useful
    # denials, reviews and ordinary conversational replies.
    if text and _COMPLETION_CLAIM.search(text):
        return "Paari did not confirm a payment execution in this run. No completed or settled payment is verified."
    return text or "The agent run ended without a final status message. Check Paari's transaction proof before acting."


def run_goal(model, broker, goal: str, *, max_turns: int = 6, max_tool_calls: int = 12,
             max_tokens: int = 1200) -> Outcome:
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": goal},
    ]
    outcome = Outcome(ok=False, messages=messages)

    for turn in range(1, max_turns + 1):
        outcome.turns = turn
        reply = model.complete(messages, tools=TOOL_SCHEMAS, max_tokens=max_tokens)
        for key, value in (reply.usage or {}).items():
            if isinstance(value, int) and not isinstance(value, bool):
                outcome.usage[key] = outcome.usage.get(key, 0) + value

        if not reply.wants_tools:
            outcome.final_text = _authoritative_final_text(outcome, reply.text)
            if reply.text is None:
                outcome.error = f"EMPTY_REPLY:{reply.finish_reason or 'unknown'}"
            else:
                outcome.ok = True
            return outcome

        if outcome.tool_calls + len(reply.tool_calls) > max_tool_calls:
            outcome.error = "MAX_TOOL_CALLS"
            return outcome

        call_ids = [call.id or f"call_{turn}_{i}" for i, call in enumerate(reply.tool_calls, 1)]
        messages.append(_assistant_message(reply, call_ids))

        for call_id, call in zip(call_ids, reply.tool_calls):
            outcome.tool_calls += 1
            # Sprint 7: stamp the model's own tool-call id onto the broker so
            # the payment intent carries the causal link back to this exact
            # model invocation (identifier only - never conversation content).
            if getattr(broker, "causal", None) is not None:
                broker.causal = replace(broker.causal, tool_call_id=call_id, tool_name=call.name)
            result = broker.execute(call.name, call.arguments)
            outcome.transcript.append({"turn": turn, "tool": call.name,
                                       "arguments": call.arguments, "result": result})
            if result.get("ok") and call.name == "confirm_payment":
                outcome.payment_executed = True
                outcome.settled_state = result.get("state")
                outcome.transaction_id = result.get("transaction_id")
                outcome.provider_order_id = result.get("provider_order_id")
            if result.get("ok") and call.name == "read_proof":
                outcome.proof_final_state = result.get("final_state")
                outcome.proof_verified = bool(result.get("chain_verified"))
                outcome.proof_terminal = bool(result.get("terminal"))
                outcome.proof_webhook_verified = bool(result.get("webhook_verified"))
                outcome.proof_settlement_source = result.get("settlement_source")
                outcome.proof_provider_environment = result.get("provider_environment")
            messages.append({"role": "tool", "tool_call_id": call_id,
                             "content": json.dumps(result, default=str)})

    outcome.error = "MAX_TURNS"
    return outcome
