from app.financial_context.normalizer import normalize_setu_data_session


def test_normalizes_setu_session_to_whitelisted_account_summaries():
    """Fails if a Setu FI data field is mapped incorrectly or private data leaks."""
    payload = {
        "id": "session-123",
        "consentId": "consent-456",
        "data": {
            "FinancialInformation": [
                {
                    "fipId": "FIP-AXIS",
                    "data": [
                        {
                            "maskedAccNumber": "XXXX1234",
                            "type": "SAVINGS",
                            "Summary": {
                                "currentBalance": "1250.75",
                                "currency": "INR",
                                "balanceDateTime": "2026-11-21T09:30:00+05:30",
                            },
                            "Transactions": {
                                "startDate": "2026-11-01",
                                "endDate": "2026-11-21",
                                "Transaction": [{"amount": "50"}, {"amount": "75"}],
                            },
                            "Profile": {"FullName": "Asha Sharma", "PAN": "ABCDE1234F"},
                            "address": "1 Private Street",
                        }
                    ],
                }
            ]
        },
    }

    assert normalize_setu_data_session(payload) == {
        "source": "setu_account_aggregator",
        "session_id": "session-123",
        "consent_id": "consent-456",
        "accounts": [
            {
                "masked_reference": "XXXX1234",
                "account_type": "SAVINGS",
                "currency": "INR",
                "balance": "1250.75",
                "balance_timestamp": "2026-11-21T09:30:00+05:30",
                "transaction_window": {"from": "2026-11-01", "to": "2026-11-21"},
                "transaction_count": 2,
                "fip_id": "FIP-AXIS",
                "session_id": "session-123",
            }
        ],
    }


def test_normalizer_preserves_unknowns_as_none_and_does_not_return_raw_fi_data():
    """Fails if absent summary data is invented or unapproved FI fields are copied."""
    payload = {
        "data": {
            "FinancialInformation": [
                {
                    "data": [
                        {
                            "Profile": {"PAN": "ABCDE1234F", "Email": "private@example.test"},
                            "Transactions": {"Transaction": {"amount": "999"}},
                        }
                    ]
                }
            ]
        }
    }

    assert normalize_setu_data_session(payload) == {
        "source": "setu_account_aggregator",
        "session_id": None,
        "consent_id": None,
        "accounts": [
            {
                "masked_reference": None,
                "account_type": None,
                "currency": None,
                "balance": None,
                "balance_timestamp": None,
                "transaction_window": {"from": None, "to": None},
                "transaction_count": None,
                "fip_id": None,
                "session_id": None,
            }
        ],
    }
