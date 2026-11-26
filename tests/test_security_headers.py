def test_api_responses_include_baseline_security_headers(paari_client):
    response = paari_client.client.get("/health")
    assert response.status_code == 200, response.text
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cross-origin-resource-policy"] == "same-origin"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_health_reports_actual_enforcement_posture(paari_client, monkeypatch):
    monkeypatch.setenv("PAARI_CONTROL_PLANE_ENFORCEMENT", "1")
    monkeypatch.setenv("PAARI_RECEIVER_ENFORCEMENT", "1")
    monkeypatch.setenv("PAARI_FEDERATION_ENFORCEMENT", "1")
    monkeypatch.setenv("PAARI_REQUIRE_SAFR_ENVELOPE", "1")
    response = paari_client.client.get("/health")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["control_plane_enforcement"] is True
    assert body["receiver_enforcement"] is True
    assert body["federation_enforcement"] is True
    assert body["safr_envelope_required"] is True
