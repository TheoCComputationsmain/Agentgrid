# AgentGrid on Vercel Hobby (ACTIVE)

This is the **active public deployment path**. AgentGrid runs as a Vercel Python
function backed by the same Neon Postgres database used in development. No
application code changes were needed: the existing FastAPI app is served as-is.

- Production URL: `https://agentgrid-pied.vercel.app`
- Vercel project: `agentgrid` (Hobby plan, no card required)
- Database: Neon Postgres (pooled async connection), unchanged
- Runtime: Python 3.13, FastAPI, async SQLAlchemy + asyncpg

There is no wallet, escrow, auto top-up, in-app checkout, or server-side payment
key. Payments are recorded externally; see `EXTERNAL_PAYMENTS.md`.

## Why Vercel

- Hobby plan is free and does not require a card to sign up or deploy.
- Python functions run on standard CPython, so the normal async stack works
  without compatibility shims.
- Free HTTPS, no VM, domain, or certificate management.
- Deploy directly from the local folder; no Git repository is required.
- Cold starts are acceptable here: all state lives in Neon, not in the function.

## Files that enable the Vercel deployment

- `pyproject.toml` — runtime dependencies and `[tool.vercel] entrypoint = "main:app"`.
- `.python-version` — pins Python `3.13`.
- `vercel.json` — sets `maxDuration = 60` for `main.py`.
- `.vercelignore` — excludes secrets, tests, venvs, and inactive deployment paths.
- `.vercel/project.json` — links the folder to the Vercel project.

## Deploy from the local folder

```bash
# One-time
npm install -g vercel
vercel login
vercel link --yes --project agentgrid

# Every deploy
vercel deploy --prod --yes
```

`AGENTGRID_SKIP_SCHEMA_ON_STARTUP=1` is set in production. Schema and trigger
creation are applied once with `python migrate.py`, not on every cold start.

## Environment variables

Values are set in the Vercel dashboard (or with `vercel env add`) and are never
committed or printed. The production project has these names configured:

| Name | Purpose |
|---|---|
| `AGENTGRID_APP_ENV` | `production` — enables fail-closed checks |
| `AGENTGRID_DATABASE_URL` | Neon pooled async connection string |
| `AGENTGRID_SIGNING_KEY_B64` | Ed25519 platform signing key |
| `AGENTGRID_ADMIN_KEY` | Admin endpoint key |
| `AGENTGRID_ADMIN_MFA_SECRET` | Admin TOTP secret |
| `AGENTGRID_RATE_LIMIT_PER_MIN` | Shared request limit (120) |
| `AGENTGRID_SKIP_SCHEMA_ON_STARTUP` | `1` — skip DDL on cold start |

Optional: `AGENTGRID_PREVIOUS_SIGNING_KEY_B64` for key rotation,
`AGENTGRID_CORS_ORIGINS` if a browser client is added, and the two welcome-email
variables below.

Production fails closed if the signing key, admin key, or admin MFA
configuration is missing. Registration is open self-service; there is no
registration token.

## Welcome email (optional)

On every successful registration AgentGrid sends a three-step welcome message.
Configure exactly ONE delivery mode in the Vercel dashboard. All timeouts are
10 seconds and any failure is logged by exception type only — registration never
fails because email failed.

1. **Your own webhook (recommended if you already run the operator bridge):**
   `AGENTGRID_WELCOME_EMAIL_WEBHOOK_URL` receives
   `{to, client_id, type, subject, text, html}`. Optionally set
   `AGENTGRID_WELCOME_EMAIL_WEBHOOK_TOKEN` for a bearer token.
2. **Resend directly:** `AGENTGRID_WELCOME_EMAIL_API_KEY` and
   `AGENTGRID_WELCOME_FROM_EMAIL`. Resend may require a verified sending domain
   before it will deliver to arbitrary recipients.
3. **SMTP:** `AGENTGRID_WELCOME_EMAIL_SMTP_HOST`, `..._PORT` (default 465),
   `..._USER`, `..._PASSWORD`, and `AGENTGRID_WELCOME_FROM_EMAIL`. A Gmail app
   password works here and needs no domain verification.

AgentGrid stores no email-provider credentials in code or the repo, and never
sees payment details. With none of these set, no email is sent and nothing
breaks.

## Verify a deployment

Health checks:

```bash
curl https://agentgrid-pied.vercel.app/health/live
curl https://agentgrid-pied.vercel.app/health/ready
curl https://agentgrid-pied.vercel.app/
```

Expected: `alive`, `ready` with `database: connected`, and the dashboard page.

Full public smoke test (reads the registration token from the local file without
printing it):

```bash
python scripts/smoke_test_vercel.py
```

Live database immutability check:

```bash
python scripts/verify_immutability.py
```

Local suite before any deploy:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q    # expected: 36 passed
```

## Account and usage guardrails

The owner account must have two-factor authentication enabled. On Hobby, set
usage alerts so an unexpected traffic spike cannot produce a surprise bill:

- Function duration: 4 CPU-hours / month
- Provisioned memory: 360 GB-hours
- Function invocations: 1,000,000
- Fast data transfer: 100 GB
- Fast origin transfer: 10 GB
- CDN requests: 1,000,000

Configure these under the Vercel account/project usage settings.

## Onboarding

`POST /v1/clients/register` is open self-service and needs no invite token.
Operators can still call `POST /v1/admin/clients/register` with the admin key and
a valid TOTP code for assisted onboarding; it returns the same one-time API key.
Both paths trigger the optional welcome email when a webhook is configured.

## Inactive alternatives

`DEPLOYMENT_GCP.md`, `DEPLOYMENT_AWS_LAMBDA.md`, `DEPLOYMENT_ORACLE.md`, and
`DEPLOYMENT_RENDER.md` are kept for reference only and are not active paths.
Cloudflare Workers was also evaluated and abandoned: async SQLAlchemy depends on
greenlet, which is not available in that runtime.
