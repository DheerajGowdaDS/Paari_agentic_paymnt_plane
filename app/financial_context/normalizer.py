"""Provider-neutral financial-context normalization; not payment authorization."""
from datetime import datetime, timezone

def normalize_accounts(payload: dict, source="mastercard_open_finance") -> dict:
    items = payload.get("accounts", []) if isinstance(payload, dict) else []
    return {"source":source,"retrieved_at":datetime.now(timezone.utc).isoformat(),"accounts":[{
        "provider_account_id":a.get("id"), "account_type":a.get("type"), "currency":a.get("currency"),
        "available_balance":(a.get("availableBalance") or {}).get("amount") if isinstance(a.get("availableBalance"),dict) else a.get("availableBalance"),
        "balance":(a.get("balance") or {}).get("amount") if isinstance(a.get("balance"),dict) else a.get("balance"),
        "institution_id":a.get("institutionId"), "status":a.get("status")
    } for a in items]}


def normalize_setu_data_session(payload: dict) -> dict:
    """Return only safe, provider-neutral account summaries from Setu FI data."""
    session = payload if isinstance(payload, dict) else {}
    data = session.get("data")
    financial_information = data.get("FinancialInformation") if isinstance(data, dict) else None
    if not isinstance(financial_information, list) and isinstance(data, dict):
        nested_data = data.get("data")
        financial_information = nested_data.get("FinancialInformation") if isinstance(nested_data, dict) else None
    if not isinstance(financial_information, list):
        financial_information = session.get("FinancialInformation")
    if not isinstance(financial_information, list):
        financial_information = []

    nested_data = data.get("data") if isinstance(data, dict) and isinstance(data.get("data"), dict) else {}
    session_id = session.get("id") if isinstance(session.get("id"), str) else session.get("sessionId")
    if not isinstance(session_id, str):
        session_id = data.get("id") if isinstance(data, dict) else None
    if not isinstance(session_id, str):
        session_id = data.get("sessionId") if isinstance(data, dict) else None
    consent_id = session.get("consentId") or (data.get("consentId") if isinstance(data, dict) else None)
    accounts = []
    for fip_information in financial_information:
        if not isinstance(fip_information, dict):
            continue
        fip_id = fip_information.get("fipId")
        fip_accounts = fip_information.get("data")
        if not isinstance(fip_accounts, list):
            continue
        for account in fip_accounts:
            if not isinstance(account, dict):
                continue
            summary = account.get("Summary")
            summary = summary if isinstance(summary, dict) else {}
            transactions = account.get("Transactions")
            transactions = transactions if isinstance(transactions, dict) else {}
            transaction_items = transactions.get("Transaction")
            transaction_count = len(transaction_items) if isinstance(transaction_items, list) else None
            accounts.append({
                "masked_reference": account.get("maskedAccNumber"),
                "account_type": account.get("type") or account.get("accountType"),
                "currency": summary.get("currency") or account.get("currency"),
                "balance": summary.get("currentBalance") if "currentBalance" in summary else account.get("currentBalance"),
                "balance_timestamp": summary.get("balanceDateTime") if "balanceDateTime" in summary else account.get("balanceDateTime"),
                "transaction_window": {"from": transactions.get("startDate"), "to": transactions.get("endDate")},
                "transaction_count": transaction_count,
                "fip_id": fip_id,
                "session_id": session_id,
            })
    return {
        "source": "setu_account_aggregator",
        "session_id": session_id,
        "consent_id": consent_id,
        "accounts": accounts,
    }
