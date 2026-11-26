# Paari v3.5.2 | honest regulatory demo status

## Verified implementation increments

- An authenticated agent with an active mandate can produce a `REVIEW` intent in development mode; the parent signs the exact one-time approval challenge; an authorization is minted and consumed once, an HMAC-authenticated capture is received, a separate provider read corroborates the captured amount/currency, and the local provider state becomes `PAID` with a reconciliation timestamp. No money moves. [tests/test_e2e_mvp_acceptance.py::test_c06_escalate_approve_settle]
- The same held state can be rejected with a **different**, transaction-bound Ed25519 signature, and the backend persists a `DENY` and audit evidence with no provider order. [C07]
- The audit verifier recomputes the hash chain and rejects temporary modified content, then the test rolls the modification back. [C14]
- The strict SAFR consumption path still requires an actually processed matching envelope and a current allowable institution policy. A reviewer signature alone is not a provider capability.

## Evidence classification

- `PAID` = corroborated *simulator* provider payment state. Not real money or proof of beneficiary credit.
- `Receiver ACCEPTED` = signed receiving-side acknowledgement, not a bank credit.
- A portable Agent Card proves an identity, not transferable spending permissions.
- UI events/labels are *not* acceptance evidence; the backend database and signatures are.

## Release gate

Run `python scripts/regulatory_mvp_gate_v352.py --quick` for the limited local diagnostic. The full Gate requires PostgreSQL and a real runtime payment evidence record from a strictly reviewed payment. The gate refuses to claim full end-to-end release acceptance on missing evidence or on pytest XFAIL.

**Release verdict on 2026-10-29: LOCAL_MVP_NOT_YET_VERIFIED.** Do not present it as a finished regulator-certified or production-ready end-to-end payment infrastructure.
