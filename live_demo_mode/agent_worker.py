"""Separate, real SDK-based agent process. Secret material is read from stdin only.

No scripted disposition or fixture is used. The parent/user's human-supplied action
becomes an authenticated, proof-of-possession Paari API request from this process.
This is a programmable SDK agent, NOT a claim of an LLM deciding to spend.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'sdk'))
from paari_agent import PaariAgentClient


def submit(params: dict) -> dict:
    c = PaariAgentClient(params['backend'], params['agent_private_key'], params['agent_public_key'])
    try:
        c.agent_id = params['agent_id']
        c.session_token = params['session_token']
        return c.payment_intent(transaction_id=params['transaction_id'],
                                idempotency_key=params['idempotency_key'],
                                merchant=params['merchant'],
                                amount_minor_units=int(params['amount_minor_units']),
                                currency=params['currency'],
                                purpose=params['purpose'],
                                merchant_category=params.get('merchant_category'),
                                llm_tool_name='live_demo_sdk_agent')
    finally:
        c.http.close()


if __name__ == '__main__':
    try:
        arguments = json.loads(sys.stdin.read())
        print(json.dumps({'ok': True, 'result': submit(arguments)}))
    except Exception as exc:
        # Error only, never echo private keys, credential bearer tokens, or input.
        print(json.dumps({'ok': False, 'error': f'{type(exc).__name__}: {exc}'}))
        sys.exit(1)
