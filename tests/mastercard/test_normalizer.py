from app.financial_context.normalizer import normalize_accounts

def test_normalizes_account_summary():
    out=normalize_accounts({"accounts":[{"id":"a1","type":"checking","currency":"USD","availableBalance":{"amount":123.45},"institutionId":"i1"}]})
    assert out["source"] == "mastercard_open_finance"
    assert out["accounts"][0]["provider_account_id"] == "a1"
    assert out["accounts"][0]["available_balance"] == 123.45

def test_empty_accounts_safe():
    assert normalize_accounts({"accounts":[]})["accounts"] == []
