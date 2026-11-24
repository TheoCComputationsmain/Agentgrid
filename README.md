# AgentGrid

[![PyPI version](https://img.shields.io/pypi/v/theoc-agentgrid-protocol.svg)](https://pypi.org/project/theoc-agentgrid-protocol/)
[![Python versions](https://img.shields.io/pypi/pyversions/theoc-agentgrid-protocol.svg)](https://pypi.org/project/theoc-agentgrid-protocol/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/TheoCComputationsmain/Agentgrid/blob/main/LICENSE)

Signed identity, discovery, and handoff receipts for AI agents.

AgentGrid is infrastructure for agents, not another chatbot. Developers register
agents, publish signed capability cards, and record signed handoffs between
agents. Anyone can verify a card with AgentGrid's published Ed25519 public key.

There is **no money inside the platform**: no wallet, no escrow, no auto top-up,
no in-app checkout, and no automatic deduction. Usage is metered in an immutable
ledger; the base subscription and overage are paid externally at cycle end.

**Write-up:** [I built a signed handoff layer for AI agents (and you can verify it offline)](https://dev.to/theoc_computations_21b3c7/i-built-a-signed-handoff-layer-for-ai-agents-and-you-can-verify-it-offline-5alh)

## Tiers

| Tier | Base | Included agents | Included handoffs / cycle |
|---|---:|---:|---:|
| Free | $0 | 5 | 100 |
| Plus | $20/cycle | 100 | 10,000 |
| Pro | $150/cycle | 1,000 | 100,000 |
| Enterprise | Custom $2,500-$5,000/cycle | 10,000 | 1,000,000 |

A cycle is one rolling month anchored to the signup day: registering on **Nov 18**
ends the first cycle on **Dec 18**, the next on **Jan 18**, and so on. Day-end
dates clamp for short months (Jan 31 → Feb 28/29). There is no calendar-month
reset and no background job.

All tiers, including Free, allow overage until the hard cap of **3× included
limits**. Beyond that, new agents and handoffs return HTTP 402 until the next
cycle or a higher tier is granted.

## Quick start

**No-code option:** open https://agentgrid-pied.vercel.app/quickstart in your
browser. Enter a real email, confirm the 6-digit code, and AgentGrid creates two
demo agents, signs a scoped handoff, and shows the immutable receipt. No CLI,
API key, wallet, or card is needed. Demo keys are generated on the server and
discarded; use the CLI/SDK below when private keys must stay on your machine.

The hosted CLI path is open self-service, no invite token:

```bash
pip install theoc-agentgrid-protocol
agrid register --email you@example.com
agrid verify 123456          # code from your inbox; first handoff runs automatically
```

Or run it locally:

```bash
pip install -r requirements-dev.txt
cp .env.example .env
pytest
uvicorn main:app --reload
```

Register a client (works in production too):

```bash
curl -X POST http://localhost:8000/v1/clients/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com"}'
```

The registration response contains no key. Confirm the emailed 6-digit code with
`POST /v1/clients/verify-email` (or `agrid verify <code>`); the API key is returned
only then. The CLI immediately runs a real signed handoff after verification, so
you see a receipt without a fourth command. Use `agrid verify <code> --no-quickstart`
to skip it, or `agrid quickstart` any time to run another demo. Use the key as
`X-AgentGrid-API-Key` for all authenticated calls.

## Python SDK

For a one-command integration, use the published SDK:

```bash
pip install theoc-agentgrid-protocol
agrid register --email you@example.com
agrid verify 123456          # code from your inbox; first handoff runs automatically
```

Signed up before email verification? If your client has a key but no email on
file, `agrid doctor` (and normal commands such as `agrid quickstart`,
`agrid statement`, or `agrid receipts`) prints the upgrade command automatically.
You can also go straight to `agrid update --email you@example.com`, then
`agrid verify <code>`. Your current key stops working while the code is pending
and is replaced at verification; if you lost the old key, register a new free client.

`agrid quickstart` registers two agents, verifies a signed card online and
offline, records a signed handoff, and reads the immutable receipt. Import it as
`agentgrid_protocol`. For a real framework drop-in, copy
`examples/langgraph_handoff.py` into your LangGraph, CrewAI, or OpenAI Agents SDK
project and adapt the single `handoff_node`. Full source and API details are in
`sdk/README.md`; the hosted guide is at `https://agentgrid-pied.vercel.app/guide`.

## Search discovery

Public pages carry canonical URLs, Open Graph/Twitter metadata, and JSON-LD
structured data. Crawlers can start at `/robots.txt` and `/sitemap.xml`; the
sitemap includes the landing page, guide, API docs, OpenAPI document, and active
public agent cards. `/ops`, admin routes, and health routes are disallowed and
`noindex`. Submit the stable sitemap URL to Google Search Console and Bing Webmaster
Tools with your own accounts.

## Operator snapshot

There are two operator views:

- `/ops` — full protected console; signs in once with admin key + TOTP.
- `/ops-lite` — simple read-only counts and recent client details; signs in with
  one read key and a catch phrase, with no TOTP.

The lite view is configured with `AGENTGRID_OPS_LITE_KEY` and
`AGENTGRID_OPS_LITE_CATCH`. It sets a 30-day HttpOnly read-only cookie and cannot
change accounts, tiers, payments, or keys. For embedding in another origin, set
`AGENTGRID_OPS_LITE_FRAME_ANCESTORS` to that origin, for example
`https://dashboard.example.com`; it defaults to `'self'`. Both `/ops` paths are
`noindex` and disallowed in `robots.txt`.

Self-service registration is open to everyone; there is no invite token to
distribute. A real email is required and its 6-digit code must be confirmed before
a key exists; the same address also helps recover a mistyped payment Client ID.
An operator can still register a client directly with the admin key and a TOTP
code when assisting someone:

```bash
curl -X POST http://localhost:8000/v1/admin/clients/register \
  -H 'X-AgentGrid-Admin-Key: ...' -H 'X-AgentGrid-Admin-MFA: 123456' \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"cli_partner_01","email":"partner@example.com"}'
```

This returns a one-time API key just like public registration. In production,
missing admin MFA configuration fails closed.

Create an agent (the public key is the agent's own Ed25519 public key, not
AgentGrid's):

```bash
curl -X POST http://localhost:8000/v1/agents \
  -H 'X-AgentGrid-API-Key: agk_...' -H 'Content-Type: application/json' \
  -d '{"name":"Research Agent","capabilities":["web_search","summarize"],"public_key":"<base64url-32-byte-key>"}'
```

The response is a signed Agent Card. Share `/a/<agent_id>` or the JSON card at
`/v1/agents/<agent_id>.json`.

## Verification

- `GET /v1/agents/public-key` — AgentGrid's Ed25519 public key. During rotation the
  response also includes `previous_public_key`; old signatures stay verifiable.
- `GET /v1/agents/{agent_id}/verify` — online signature/status check.
- Cards are canonical JSON signed with Ed25519, so they can also be verified
  offline with the published key.

## Handoffs

A handoff is signed by the **from-agent** over this exact canonical payload:

```json
{
  "v": 1,
  "handoff_id": "h_<32 hex>",
  "from_agent_id": "ag_...",
  "to_agent_id": "ag_...",
  "task_hash": "<64 hex SHA-256>",
  "scope": {"allowed": ["read"], "max_actions": 3},
  "created_at": "<ISO-8601 Z>",
  "parent_handoff_id": ""
}
```

Post it to `/v1/agents/{from_agent_id}/handoffs`. AgentGrid verifies the
signature against the registered from-agent public key, rejects timestamps older
than 300 seconds, caps scope at 8 KB of canonical JSON, rejects non-finite
numbers, enforces that nested delegations do not widen scope, and stores an
immutable receipt. `GET /v1/agents/{agent_id}/receipts` returns the work history.

## Ledger-backed overage and statements

Usage above the included limits is written to `overage_ledger` as usage units,
not money balances:

- `$1 per 1,000 extra handoffs` — one ledger row per overage handoff.
- `$0.10 per extra agent per day` — one ledger row when an agent crosses the
  included limit; days are prorated from creation to cycle end.

`GET /v1/billing/statement` returns the current or closed-cycle statement with
`base_fee_usd`, overage counts/rates, `total_due_usd`, hard caps, and an
`invoice_id`. For a closed cycle it returns `final: true`, `payment_status:
unpaid`, and no Cashfree order ID until payment is recorded. The `overage` flag
in agent/handoff responses is metadata only; Agent Card signatures still cover
the original unsigned card payload.

Amounts are integer microdollars internally. Enterprise has no stored base
amount; the statement shows a custom amount agreed manually. Nothing in the
service can charge, deduct, hold, or transfer funds.

The operator creates the external Cashfree/invoice link and quotes the
`invoice_id`. After verifying the external payment, the operator records it:

```bash
curl -X POST \
  http://localhost:8000/v1/admin/clients/cli_.../statements/2026-11-18/record-payment \
  -H 'X-AgentGrid-Admin-Key: ...' -H 'X-AgentGrid-Admin-MFA: 123456' \
  -H 'Content-Type: application/json' \
  -d '{"cashfree_order_id":"order_123","cashfree_payment_id":"pay_123"}'
```

This is idempotent by Cashfree order ID. Reusing the same order returns
`duplicate: true`; using it for another client/cycle returns 409. Only the
statement's `payment_status` and an immutable `billing_history` row change.

See `EXTERNAL_PAYMENTS.md` for tier prices, the operator workflow, and the
external-link requirements. No money moves inside AgentGrid.

## Admin grant

```bash
curl -X POST http://localhost:8000/v1/admin/clients/cli_.../grant-access \
  -H 'X-AgentGrid-Admin-Key: ...' -H 'X-AgentGrid-Admin-MFA: 123456' \
  -H 'Content-Type: application/json' \
  -d '{"tier":"pro","cashfree_order_id":"order_123","cashfree_payment_id":"pay_123"}'
```

This selects the tier for the current rolling cycle and applies it immediately.
Access expires at the current cycle end, so the plan must be renewed for the next
cycle. Idempotent by Cashfree order ID. Requires both the admin key and a valid
TOTP code. Order/payment IDs are restricted to `[A-Za-z0-9_-]{3,128}`. Invalid
tiers, order IDs, keys, or MFA codes are rejected before any state change. In
production, missing MFA configuration and missing registration token fail closed.

The grant records an external order reference; actual base + overage payment is
recorded separately with `/record-payment` at cycle end.

## Environment

See `.env.example`. In production, `AGENTGRID_SIGNING_KEY_B64`,
`AGENTGRID_ADMIN_KEY`, and `AGENTGRID_ADMIN_MFA_SECRET` are required/used
fail-closed. Registration is intentionally open, so no registration token is
needed. `AGENTGRID_PREVIOUS_SIGNING_KEY_B64` is optional and only for rotation.
`AGENTGRID_RATE_LIMIT_PER_MIN` defaults to 120 and is shared across instances
when Postgres is used.

`AGENTGRID_SKIP_SCHEMA_ON_STARTUP=1` is for Lambda or other multi-instance
deployments. When set, run `python migrate.py` once before serving traffic;
this prevents cold starts from racing on schema or trigger creation.

Rolling-cycle rollover and statement snapshots happen lazily on first access in
a new cycle, so no scheduler or always-on worker is needed.

## Hardening and immutability

- Request bodies are capped at 64 KB from the **streamed bytes**, so chunked or
  missing `Content-Length` bodies cannot bypass the limit.
- Rate limiting is 120 requests/minute by default, keyed by API key (or client IP
  when no key is supplied). Postgres deployments use a shared atomic counter
  table; SQLite uses a process-local counter for local development.
- Responses include `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, and a restrictive `Content-Security-Policy`.
- Strict validation covers API keys, handoff IDs, SHA-256 task hashes,
  Cashfree IDs, endpoint URLs, scopes, timestamps, and TOTP input.
- Ed25519 verification accepts the current signing key and, when configured,
  the previous key so cards remain verifiable during rotation.
- Database triggers make `agents`, `handoffs`, `audit_events`, `billing_history`,
  and `overage_ledger` immutable: direct `UPDATE` and `DELETE` are blocked.
  `clients` remains mutable only for tier, cycle counters, and access expiry;
  `billing_statements` changes only from `unpaid`/`current` to `paid`.
- Audit metadata drops secret-looking keys before storage.

## Pre-deploy gate

Do not deploy until all of these are true:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q    # expected: all tests passing
```

- Production env values are set from a secret manager, not committed.
- Postgres/Neon connection is verified and `/health/ready` returns `ready`.
- Signing key and previous key (if rotating) are backed up securely.
- Admin TOTP secret is enrolled in an authenticator app.
- External Cashfree hosted links exist for Plus, Pro, and custom Enterprise.
- Public registration is open; abuse is bounded by the shared 120 req/min limit.
- No live Cashfree server keys, webhooks, wallet, escrow, or in-app checkout.

## Deployment targets

### Vercel Hobby (active)

The live deployment is on Vercel Hobby at `https://agentgrid-pied.vercel.app`,
backed by Neon Postgres. Python functions run the existing FastAPI app without
code changes. Deploy with `vercel deploy --prod --yes` from this folder.

See `DEPLOYMENT_VERCEL.md` for the full setup, environment variables, health
checks, smoke tests, and usage guardrails.

### Inactive alternatives (reference only)

The following are kept for reference and are **not** active deployment paths:

- Google Cloud Run — see `DEPLOYMENT_GCP.md` and `scripts/deploy_cloud_run.ps1`.
- AWS Lambda — see `DEPLOYMENT_AWS_LAMBDA.md` and `lambda_handler.py`.
- Oracle Always Free — see `DEPLOYMENT_ORACLE.md` (signup requires a card).
- Render Free — see `DEPLOYMENT_RENDER.md` (cold starts; inactive).
- Cloudflare Workers — abandoned: async SQLAlchemy needs greenlet, which is not
  available in that runtime.

## What was intentionally left out

Wallet balance, automatic overage deduction, escrow, marketplace payments, auto
top-up, live Cashfree keys on the server, webhooks, always-on database, and
CockroachDB.
