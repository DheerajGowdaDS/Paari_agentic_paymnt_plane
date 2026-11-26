"""100 real HTTP agent enrollments with tenant-owned fleet governance.

May take longer than functional tests. No payments or external providers are used.
"""
from app import security as platform_security
from tests.test_v37_enterprise import agent_setup


def test_enroll_and_govern_100_treasury_agents(paari_client,monkeypatch):
    c=paari_client.client
    # Organizational parent workflow, manual sandbox approval only.
    # Use the organization registration path explicitly.
    from tests.test_v36_onboarding import parent_data, approve, secrets_setup
    secrets_setup(monkeypatch)
    req=parent_data(name='Example Treasury Private Limited',parent_type='organization',
                    identifier='29ABCDE1234F1Z5')
    r=c.post('/v36/parents/register',json=req)
    assert r.status_code==201,r.text
    pid=r.json()['parent_id']
    assert approve(c,pid).status_code==200
    login=c.post('/v36/parents/login',json={'parent_id':pid,'password':req['password']})
    assert login.status_code==200,login.text
    auth={'Authorization':'Bearer '+login.json()['access_token']}
    policy=c.put('/v37/enterprise/treasury/policy',headers=auth,
                 json={'currency':'INR','daily_limit_minor_units':1000000})
    assert policy.status_code==200,policy.text
    agents=[]
    for i in range(100):
        agent_id, private, response=agent_setup(c,auth,name=f'TreasuryAgent{i+1:03d}')
        assert response['agent_card']['card_signature_b64']
        agents.append(agent_id)
        setting=c.put(f'/v37/enterprise/treasury/agents/{agent_id}/risk',headers=auth,
                  json={'daily_limit_minor_units':50000,'hourly_request_limit':5,'suspended':i>=95})
        assert setting.status_code==200,setting.text
    assert len(set(agents))==100
    report=c.get('/v37/enterprise/treasury/exposure',headers=auth)
    assert report.status_code==200,report.text
    summary=report.json()
    assert summary['agent_count']==100
    assert summary['reserved_total_minor_units']==0
    assert set(summary['agents'])==set(agents)
    signals=c.get('/v37/enterprise/treasury/signals',headers=auth)
    assert signals.status_code==200 and signals.json()['signals']==[]
