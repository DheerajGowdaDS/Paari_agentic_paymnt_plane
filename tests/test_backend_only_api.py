"""Primary app packaging: protocol + the two first-party workspaces.

v3.7.1 ships a two-workspace product portal served by the same backend:
`/organization` (with `/portal` as an alias) and `/console`. The earlier
"no console" assertion described the backend-only packaging and contradicted
the shipped front ends.
"""
from fastapi.testclient import TestClient
from app.main import app as main_app
from live_demo_mode.app import build_app
from local_demo.portal import create_app


def test_primary_app_serves_protocol_and_two_workspaces():
    paths = {route.path for route in main_app.routes}
    assert '/health' in paths
    assert '/.well-known/paari' in paths
    assert '/v1/payments/intent' in paths
    assert '/organization' in paths
    assert '/portal' in paths
    assert '/console' in paths


def test_headless_safr_service_has_no_browser_page_and_requires_token(tmp_path):
    api = create_app(tmp_path, demo_api_token='locally-provisioned')
    with TestClient(api, base_url='http://127.0.0.1:8765') as client:
        assert client.get('/').status_code == 404
        assert client.get('/api/catalog').status_code == 200
        assert client.post('/api/policy/auto_execute').status_code == 403
        assert client.post('/api/policy/auto_execute',
                           headers={'x-paari-demo-token': 'locally-provisioned'}).status_code == 200


def test_headless_orchestrator_has_no_browser_page_and_requires_token():
    api = build_app(backend_url='http://127.0.0.1:8120',
                    stub_base='http://127.0.0.1:9911/v1',
                    admin_api_key='local-test-admin', demo_api_token='locally-provisioned')
    with TestClient(api) as client:
        assert client.get('/').status_code == 404
        assert client.get('/api/agent/card').status_code == 200
        assert client.post('/api/parent', json={
            'name': 'Test Parent', 'contact': 'test@example.org', 'parent_type': 'developer',
        }).status_code == 403
