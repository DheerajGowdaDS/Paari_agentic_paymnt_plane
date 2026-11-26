"""Offline parent-side signer for a Paari human-review decision.

The parent secret never enters the operator portal or Paari API. The input
context MUST be copied unchanged from /payments/reviews/{intent}/challenge;
choose the exact context matching your intended APPROVE or REJECT decision.
"""
import argparse
import json
from pathlib import Path
from app.crypto_utils import sign_with_private_key


def main():
    parser = argparse.ArgumentParser(description='Sign a single Paari human-review challenge locally')
    parser.add_argument('--private-key', required=True, help='Registered parent Ed25519 PEM private-key file')
    parser.add_argument('--context-file', required=True, help='Exact canonical context to sign (UTF-8 text)')
    parser.add_argument('--out', required=True, help='JSON signature response file')
    args = parser.parse_args()
    context = Path(args.context_file).read_text(encoding='utf-8').strip()
    parsed = json.loads(context)
    if parsed.get('purpose') not in {'paari_mfa_step_up', 'paari_mfa_step_up_reject'}:
        parser.error('Context purpose must be signed Paari approve or reject')
    if not all(parsed.get(k) for k in ('challenge_id','intent_id','agent_id','transaction_id','nonce')):
        parser.error('Incomplete challenge; do not sign')
    sig = sign_with_private_key(Path(args.private_key).read_text(encoding='utf-8'), context)
    body = {'intent_id': parsed['intent_id'], 'challenge_id': parsed['challenge_id'],
            'parent_signature_b64': sig,
            'decision': 'APPROVE' if parsed['purpose']=='paari_mfa_step_up' else 'REJECT'}
    target = Path(args.out)
    if target.exists():
        parser.error('Refusing to overwrite an existing signed reviewer response')
    target.write_text(json.dumps(body, indent=2), encoding='utf-8')
    try:
        target.chmod(0o600)
    except OSError:
        pass
    print('Signed response saved. Send intent_id, challenge_id and parent_signature_b64 only; never upload the private key.')


if __name__ == '__main__':
    main()
