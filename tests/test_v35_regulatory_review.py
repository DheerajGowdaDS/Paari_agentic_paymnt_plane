"""Real Paari payment-review endpoints: signed human approval/rejection and fail closed."""
from app import crypto_utils, models, security
from app.audit import verify_chain
from tests.conftest import make_intent


def review_intent(ctx):
    # The parent delegates a ₹5,000 ceiling; ₹4,500 requires signed step-up.
    result = make_intent(ctx, amount=450000)
    assert result['decision'] == 'review' and result['authorization'] is None, result
    assert result['mfa_required']
    return result


def challenge(ctx, intent_id):
    res = ctx.client.post('/payments/mfa/challenge', json={
        'intent_id': intent_id, 'session_token': ctx.session_token,
    })
    assert res.status_code == 200, res.text
    return res.json()


def reject_context(ctx, intent, challenge):
    return crypto_utils.canonical_json({
        'purpose': 'paari_mfa_step_up_reject', 'challenge_id': challenge['challenge_id'],
        'intent_id': intent['intent_id'], 'agent_id': ctx.agent_id,
        'transaction_id': intent['transaction_id'], 'merchant': 'TestMerchant',
        'amount_minor_units': 450000, 'currency': 'INR', 'nonce': challenge['nonce'],
    })


def test_real_reviewer_queue_is_tenant_scoped_and_requires_admin(paari_client):
    ctx = paari_client
    intent = review_intent(ctx)
    no_key = ctx.client.get('/payments/reviews?org_id=default')
    assert no_key.status_code == 401
    found = ctx.client.get('/payments/reviews?org_id=default',
                           headers={'X-Admin-Api-Key': security._ADMIN_API_KEY})
    assert found.status_code == 200, found.text
    match = next(row for row in found.json()['reviews'] if row['intent_id'] == intent['intent_id'])
    assert match['review_type'] == 'PARENT_SIGNED_STEP_UP'
    assert 'authorization' not in str(match).lower()


def test_real_parent_signed_rejection_stops_execution_and_audits(paari_client):
    ctx = paari_client
    intent = review_intent(ctx)
    ch = challenge(ctx, intent['intent_id'])
    sign = crypto_utils.sign_with_private_key(ctx.parent_private, reject_context(ctx, intent, ch))
    res = ctx.client.post('/payments/mfa/reject', json={
        'intent_id': intent['intent_id'], 'challenge_id': ch['challenge_id'],
        'parent_signature_b64': sign,
    })
    assert res.status_code == 200, res.text
    assert res.json()['authorization'] is None
    assert res.json()['decision'] == 'deny'
    replay = ctx.client.post('/payments/mfa/verify', json={
        'intent_id': intent['intent_id'], 'challenge_id': ch['challenge_id'],
        'parent_signature_b64': crypto_utils.sign_with_private_key(ctx.parent_private, ch['context_to_sign']),
    })
    assert replay.status_code in (400, 409)
    db = ctx.Session()
    try:
        record = db.query(models.PaymentIntent).filter_by(intent_id=intent['intent_id']).one()
        assert record.decision == models.GovernanceDecision.DENY
        assert db.query(models.BoundedAuthorization).filter_by(intent_id=intent['intent_id']).count() == 0
        events = db.query(models.AuditEvent).filter_by(transaction_id=intent['transaction_id']).all()
        assert any(e.kind == 'human_review_rejected' for e in events)
        assert verify_chain(db, intent['transaction_id'])
    finally:
        db.close()


def test_approval_signature_cannot_be_used_as_rejection(paari_client):
    ctx = paari_client
    intent = review_intent(ctx)
    ch = challenge(ctx, intent['intent_id'])
    approval_sig = crypto_utils.sign_with_private_key(ctx.parent_private, ch['context_to_sign'])
    response = ctx.client.post('/payments/mfa/reject', json={
        'intent_id': intent['intent_id'], 'challenge_id': ch['challenge_id'],
        'parent_signature_b64': approval_sig,
    })
    assert response.status_code == 401
    db = ctx.Session()
    try:
        assert db.query(models.PaymentIntent).filter_by(intent_id=intent['intent_id']).one().decision == models.GovernanceDecision.REVIEW
    finally:
        db.close()


def test_review_approval_has_real_signature_and_single_use_auth(paari_client):
    ctx = paari_client
    intent = review_intent(ctx)
    ch = challenge(ctx, intent['intent_id'])
    approval_sig = crypto_utils.sign_with_private_key(ctx.parent_private, ch['context_to_sign'])
    response = ctx.client.post('/payments/mfa/verify', json={
        'intent_id': intent['intent_id'], 'challenge_id': ch['challenge_id'],
        'parent_signature_b64': approval_sig,
    })
    assert response.status_code == 200, response.text
    assert response.json()['decision'] == 'allow'
    auth = response.json()['authorization']
    assert auth is not None and auth['max_usage'] == 1
    repeat = ctx.client.post('/payments/mfa/verify', json={
        'intent_id': intent['intent_id'], 'challenge_id': ch['challenge_id'],
        'parent_signature_b64': approval_sig,
    })
    assert repeat.status_code in (400, 401)
    db = ctx.Session()
    try:
        events = db.query(models.AuditEvent).filter_by(transaction_id=intent['transaction_id']).all()
        assert any(e.kind == 'human_review_approved' for e in events)
        assert verify_chain(db, intent['transaction_id'])
    finally:
        db.close()


def test_strict_mode_blocks_review_approval_without_persisted_governance(paari_client, monkeypatch):
    ctx = paari_client
    intent = review_intent(ctx)
    ch = challenge(ctx, intent['intent_id'])
    approval_sig = crypto_utils.sign_with_private_key(ctx.parent_private, ch['context_to_sign'])
    monkeypatch.setenv('PAARI_CONTROL_PLANE_ENFORCEMENT', '1')
    response = ctx.client.post('/payments/mfa/verify', json={
        'intent_id': intent['intent_id'], 'challenge_id': ch['challenge_id'],
        'parent_signature_b64': approval_sig,
    })
    assert response.status_code in (403, 409)
    db = ctx.Session()
    try:
        assert db.query(models.BoundedAuthorization).filter_by(intent_id=intent['intent_id']).count() == 0
        assert db.query(models.PaymentIntent).filter_by(intent_id=intent['intent_id']).one().decision == models.GovernanceDecision.REVIEW
    finally:
        db.close()


def test_operator_challenge_issued_only_to_active_tenant_and_signed_rejected(paari_client, monkeypatch):
    from tests.test_v34_receivers import _create
    ctx = paari_client
    headers, _receiver_id, _receiver_key = _create(ctx, monkeypatch)
    intent = review_intent(ctx)
    wrong = ctx.client.post(f"/payments/reviews/{intent['intent_id']}/challenge", headers={
        **headers, 'X-Paari-Org': 'other-organization'})
    assert wrong.status_code in (401, 403, 404)
    response = ctx.client.post(f"/payments/reviews/{intent['intent_id']}/challenge", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload['approve_context_to_sign'] != payload['reject_context_to_sign']
    signed = crypto_utils.sign_with_private_key(ctx.parent_private, payload['reject_context_to_sign'])
    rejected = ctx.client.post('/payments/mfa/reject',json={
        'intent_id': intent['intent_id'], 'challenge_id':payload['challenge_id'],
        'parent_signature_b64':signed})
    assert rejected.status_code == 200,rejected.text
    # Unverified payment cannot fabricate receiver credit or authorization.
    r=ctx.client.get(f"/control/v1/receivers/payment-evidence/{intent['intent_id']}", headers=headers)
    assert r.status_code == 200, r.text
    proof=r.json()
    assert proof['human_review']['status'] == 'REJECTED'
    assert proof['authorization'] is None and proof['provider'] is None
    assert proof['audit_chain_valid'] is True
    assert proof['receiver_credit_independently_verified'] is False
