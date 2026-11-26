# Paari separated websites

Paari now has two distinct website entry points backed by the same API and database.

## 1. External Organization Portal

- Same-origin URL: `http://127.0.0.1:8000/organization`
- Compatibility URL: `http://127.0.0.1:8000/portal`
- Static source: `web/organization/index.html`
- Intended users: external parent organizations and individual parent accounts.
- Includes public Paari landing page, parent onboarding, parent sign-in, tenant-scoped organization workspace, Agent Registry, SAFR parent payment-review queue, Payment Tracker, Treasury & Risk, Organization profile and public Agent Card verification.
- Does not include Paari internal administrator controls or cross-tenant operations UI.

## 2. Internal Paari Console

- Same-origin URL: `http://127.0.0.1:8000/console`
- Static source: `web/internal/index.html`
- Intended users: authorized Paari operations / platform administrators only.
- Includes root administrator sign-in, global overview, parent approvals, tenant management, agent fleet, platform payment tracker, read-only control-plane governance view and platform audit.
- Does not include parent onboarding, parent login, agent registration or tenant-scoped parent dashboard.

## 3. Run locally

From the project root, after creating the environment and configuring `.env`:

```powershell
python -m alembic upgrade head
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Open the two URLs above in separate browser tabs. The sites use the same-origin API automatically. For deployments where the static HTML is hosted on a different origin, configure the backend API base URL in the external portal's API settings and configure an explicit CORS allowlist. Never use wildcard CORS with credentials.

## 4. Authentication and trust boundaries

- Organization users authenticate with their parent account. Parent data endpoints remain scoped by the authenticated parent token.
- Paari administrators authenticate through `/portal/v1/platform/*` using the root Paari administrator key. The key is held in browser memory and cleared on disconnect; this remains a controlled sandbox/internal-operations mechanism, not the final production staff identity model.
- Hiding a screen is not authorization. Backend endpoint authentication remains authoritative. `/platform/*` endpoints must continue requiring root administrator credentials, and parent routes must continue requiring the parent token.
- Do not expose the internal console publicly without HTTPS, named staff accounts, MFA, RBAC, short-lived server-side sessions, reviewer attribution and privileged-action audit controls.

## 5. Container deployment

The Dockerfile now copies `web/` into the runtime image. Rebuild the image after updating the project. Both UI URLs are served by the same API origin.

## 6. UI/API separation checks

- The Organization Portal HTML must not contain the internal platform console shell or global operations navigation.
- The Internal Console HTML must not contain parent onboarding or organization workspace pages.
- The external `/portal` compatibility URL serves the Organization Portal.
- UI separation is not a substitute for server-side authorization.
