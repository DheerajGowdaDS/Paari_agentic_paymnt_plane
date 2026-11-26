"""Local HTTP bridge: sender Paari runtime ↔ independent receiver sandbox.

This DOES NOT initiate payment, mark PAID, or claim beneficiary credit. It
consumes only a preexisting real sender intent whose provider state has already
reached a submission milestone. All receiving signatures are produced by a
separate receiver service and verified again by Paari's receiver endpoint.
"""
import argparse
import json
import os
from urllib.parse import urlsplit
import httpx


def _loopback_url(raw):
    p=urlsplit(raw)
    if p.scheme!='http' or p.hostname not in {'127.0.0.1','localhost','::1'} or p.username or p.password:
        raise ValueError('Only loopback HTTP is allowed for local simulator bridge')
    return raw.rstrip('/')


def run(base, partner, org_id, control_key, intent_id):
    headers={'X-Paari-Org':org_id,'X-Paari-Control-Key':control_key}
    with httpx.Client(timeout=15, follow_redirects=False) as client:
        evidence_response=client.get(f'{base}/control/v1/receivers/payment-evidence/{intent_id}',headers=headers)
        evidence_response.raise_for_status(); evidence=evidence_response.json()
        state=(evidence.get('provider') or {}).get('state')
        if state not in {'PROVIDER_SUBMITTED','PROVIDER_UNKNOWN','CAPTURED','PAID','REFUNDED'}:
            raise ValueError('Provider has not actually been submitted; receiver attestation not permitted')
        context_resp=client.get(f'{base}/control/v1/federation/contexts/{intent_id}',headers=headers)
        context_resp.raise_for_status(); context=context_resp.json()
        if not context.get('signature_valid') or context.get('payload',{}).get('execution_authority') is not False:
            raise ValueError('Paari-signed context invalid or incorrectly authority bearing')
        if context['payload']['org_id']!=org_id or context['payload']['beneficiary_id']!=evidence.get('beneficiary_id'):
            raise ValueError('Sender/receiver context binding mismatch')
        receiver=(evidence.get('receiver') or {}).get('receiver_id')
        if not receiver:
            raise ValueError('Missing approved receiving institution')
        reference=((evidence.get('provider') or {}).get('provider_payment_id') or
                   (evidence.get('provider') or {}).get('order_id') or
                   'submitted-'+evidence['transaction_id'])
        ack=client.post(f'{partner}/v1/acknowledge', json={
            'context':context,'receiver_id':receiver,'provider_reference':reference,'result':'ACCEPTED'})
        ack.raise_for_status(); signed=ack.json()
        if signed.get('settlement_confirmed') is not False or signed.get('sandbox_only') is not True:
            raise ValueError('Receiver response falsely asserts payment settlement')
        # The receiver already generated and signed exact ReceiverClaim fields.
        receipt=client.post(f'{base}/control/v1/receivers/attestations',json={
            'claim':signed['claim'],'signature_b64':signed['signature_b64']})
        receipt.raise_for_status()
        proof=client.get(f'{base}/control/v1/receivers/payment-evidence/{intent_id}',headers=headers)
        proof.raise_for_status(); final=proof.json()
        if not final['audit_chain_valid'] or not any(a['attestation_id']==receipt.json()['attestation_id'] for a in final['receiver_attestations']):
            raise ValueError('Independent receiver attestation not persisted or audit invalid')
        return {'intent_id':intent_id,'receiving_signature_verified':receipt.json()['receiver_signature_verified'],
                'audit_chain_valid':final['audit_chain_valid'],
                'provider_settlement_status':final['provider_settlement_status'],
                'receiver_credit_independently_verified':False,
                'simulated_external_rail':True,'attestation_id':receipt.json()['attestation_id']}


def main():
    p=argparse.ArgumentParser(description='Bridge real Paari sender with sandbox receiving institution')
    p.add_argument('--intent-id',required=True)
    p.add_argument('--paari-url',default='http://127.0.0.1:8000')
    p.add_argument('--receiver-url',default='http://127.0.0.1:8811')
    p.add_argument('--org',default=os.getenv('PAARI_ORG_ID',''))
    args=p.parse_args()
    key=os.getenv('PAARI_ORG_CONTROL_KEY','')
    if not args.org or not key:p.error('PAARI_ORG_ID or --org plus PAARI_ORG_CONTROL_KEY required')
    result=run(_loopback_url(args.paari_url),_loopback_url(args.receiver_url),args.org,key,args.intent_id)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
