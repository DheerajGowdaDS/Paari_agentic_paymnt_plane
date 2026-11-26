"""Demonstrate onboarding a fleet of 100 treasury agents through live HTTP APIs.

Prerequisite: run the v3.7 backend and manually approve the parent via
/v36/admin/parents/{parent_id}/review. Uses only synthetic identities.

Example:
  PAARI_PARENT_ID=<id> PAARI_PARENT_PASSWORD=<password> \
    python scripts/v37_treasury_100_agents_demo.py --count 100

Generated agent private keys are intentionally discarded: this demo enrolls
and inventories identities, but does not initiate payments. Do not run it on
shared/production installations or for agents that will need to transact.
"""
import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urlparse
import httpx
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.crypto_utils import generate_agent_keypair


FLEET=[('SupplierPaymentBot','payments',40),('ReconciliationBot','reconciliation',25),
       ('AnalyticsBot','analytics',20),('TreasuryControlsBot','treasury',15)]


def fleet_at(i):
    for name,kind,n in FLEET:
        if i<n: return name,kind
        i-=n
    return 'TreasuryBot','treasury'


def main():
    parser=argparse.ArgumentParser(description='Paari v3.7 synthetic treasury agent fleet demo')
    parser.add_argument('--count',type=int,default=100)
    parser.add_argument('--base-url',default='http://127.0.0.1:8000')
    args=parser.parse_args()
    if not 1<=args.count<=100:parser.error('--count must be 1..100')
    parsed=urlparse(args.base_url)
    if parsed.scheme!='http' or parsed.hostname not in ('localhost','127.0.0.1','::1'):
        parser.error('Demo supports local HTTP loopback only')
    pid=os.environ.get('PAARI_PARENT_ID')
    password=os.environ.get('PAARI_PARENT_PASSWORD')
    if not pid or not password:parser.error('Set PAARI_PARENT_ID and PAARI_PARENT_PASSWORD')
    with httpx.Client(base_url=args.base_url,timeout=30) as client:
        login=client.post('/v36/parents/login',json={'parent_id':pid,'password':password})
        login.raise_for_status()
        headers={'Authorization':'Bearer '+login.json()['access_token']}
        policy=client.put('/v37/enterprise/treasury/policy',headers=headers,
             json={'currency':'INR','daily_limit_minor_units':1000000})
        policy.raise_for_status()
        print('Treasury parent:',pid,'shared daily ceiling: INR 10,000 (minor units=1,000,000)')
        ids=[]
        for i in range(args.count):
            name,kind=fleet_at(i)
            _private,public=generate_agent_keypair()
            req={
               'basics':{'name':f'{name}-{i+1:03d}','agent_type':kind,
                  'purpose':'Synthetic internal treasury governance demonstration'},
               'agent_public_key_pem':public,
               'delegation':{'capabilities':['make_payment'] if kind in ('payments','treasury')
                             else ['data:read'], 'limit_minor_units':50000,'currency':'INR','valid_days':3},
               'escalation_contact':{'name':'Test Escalation Operator',
                        'email':'treasury-demo@example.invalid','phone':'9000000000'},
               'accept_agent_security':True,
            }
            response=client.post('/v36/agents/register',headers=headers,json=req)
            response.raise_for_status()
            agent_id=response.json()['agent_card']['agent_id']
            risk=client.put(f'/v37/enterprise/treasury/agents/{agent_id}/risk',headers=headers,
                    json={'daily_limit_minor_units':50000,'hourly_request_limit':5,'suspended':False})
            risk.raise_for_status()
            ids.append(agent_id)
            if (i+1)%10==0 or i+1==args.count:
                print(f'Registered {i+1}/{args.count} (identity & policy only)')
        snapshot=client.get('/v37/enterprise/treasury/exposure',headers=headers)
        snapshot.raise_for_status()
        signals=client.get('/v37/enterprise/treasury/signals',headers=headers)
        signals.raise_for_status()
        print('Portfolio inventory:',snapshot.json()['agent_count'])
        print('Initial reserved exposure:',snapshot.json()['reserved_total_minor_units'])
        print('Risk observations:',len(signals.json()['signals']))
        print('Agent keys discarded; no mandates/payment authorizations or real settlement created.')


if __name__=='__main__':main()
