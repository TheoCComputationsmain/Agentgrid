# Onboarding rollout (shipped 2026-11-23)

All five activation items are implemented. Service is deployed to
`https://agentgrid-pied.vercel.app` and the public repo is pushed.

## What shipped

1. **`agrid register` output** (`sdk/agentgrid_protocol/cli.py`)
   After success it now prints three exact next steps (`agrid quickstart`,
   `agrid card <agent_id>`, `agrid receipts <agent_id>`) plus guide/API URLs,
   without ever printing the API key. A new `agrid receipts <agent_id>` command
   makes step 3 copy-pasteable. Error messages now say `agrid`, not `agentgrid`.

2. **3-step quickstart at the top of `/guide`** (`main.py`)
   "Start here: 3 steps (~1 minute)" with a single copy-paste block, and a link
   down to the FAQ. The OpenAPI description shown at `/docs` carries the same
   three commands and links to the guide.

3. **Copy-paste recipes** (`/guide`, `/docs` description, SDK README, repo README)
   - Verify a card offline with the published platform key (rotation-safe)
   - Record a scoped handoff and a narrowing child handoff
   - Read receipts by agent ID

4. **FAQ** (`/guide`, SDK README, repo README)
   Seeded from the friction points we already know: invite token, API key
   storage, what quickstart does, offline verification, scope widening, receipt
   privacy, payment requirement, free limits, upgrade/email change, other
   languages. It is explicitly marked as growing from real feedback. Log real
   questions in `FEEDBACK.md` and fold repeats into the FAQ, CLI output, or email.

5. **Automated welcome email** (`welcome_email.py`)
   On every registration (public or admin-assisted), AgentGrid sends the same
   three steps using one of three configured providers: your own webhook, the
   Resend HTTPS API, or SMTP (e.g. a Gmail app password). No provider
   credentials live in AgentGrid's code or repo; no API key is included in the
   message; failures never break registration (10s timeout, logged by type).

## Enable the welcome email (user-only)

Set exactly ONE mode in the Vercel project dashboard. No redeploy is needed —
the config is read at send time.

- **Mode 1 — webhook:** `AGENTGRID_WELCOME_EMAIL_WEBHOOK_URL` (your own endpoint;
  it receives `{to, client_id, type, subject, text, html}`), plus optional
  `AGENTGRID_WELCOME_EMAIL_WEBHOOK_TOKEN`.
- **Mode 2 — Resend:** `AGENTGRID_WELCOME_EMAIL_API_KEY` and
  `AGENTGRID_WELCOME_FROM_EMAIL`. Resend may require a verified sending domain
  for arbitrary recipients.
- **Mode 3 — SMTP:** `AGENTGRID_WELCOME_EMAIL_SMTP_HOST`, `..._PORT` (default
  465), `..._USER`, `..._PASSWORD`, and `AGENTGRID_WELCOME_FROM_EMAIL`. A Gmail
  app password works and needs no domain verification.

**Current state (Nov 23 2026): Mode 1 is LIVE.** A Google Apps Script web app
named `AgentGrid Welcome Sender` sends through the owner's Gmail. Its `/exec`
URL plus a shared `?token=` is stored only in Vercel as
`AGENTGRID_WELCOME_EMAIL_WEBHOOK_URL`. The token check keeps it from being an
open relay. Five SMTP variables are also saved but **unused**: Vercel's Python
runtime drops both 465 and 587 instantly (`SMTPServerDisconnected`), so SMTP is
a fallback for non-Vercel deployments only. Webhook mode takes precedence.

Test registrations that confirmed the live path: `smoke_welcome_27277909fb`
(SMTP failure, now fixed) and `smoke_welcome_5871d32f64` (webhook, no errors).
Direct bridge test also returned HTTP 200 `ok`.

## Remaining user steps

1. Publish SDK `0.2.2`:
   ```powershell
   cd "C:\Users\santhoshchithira\Documents\Default Project\AgentGrid\sdk"
   .\publish_safe.ps1
   ```
   `sdk/dist/` already contains only 0.2.2 artifacts; `twine check` passes.
   Public repo already points at 0.2.2 (commit `d46ad0a`).
2. ~~Set the Vercel env vars above~~ — DONE; webhook live and verified.
3. Confirm the test email arrived in Gmail inbox/spam, then email the three
   real signups personally and log their replies in `FEEDBACK.md`.

## Verification done

- AgentGrid service: 46 tests passed
- Public repo copy: 45 passed, 1 skipped (AWS Lambda adapter intentionally absent)
- SDK: 9 tests passed
- `python scripts/smoke_test_vercel.py`: ALL CHECKS PASSED after deploy
- Live `/guide` and `/openapi.json` checked for all new sections
- Public repo pushed: `d46ad0a`, `c788bb1`, and the SMTP-fallback/webhook-timeout fix
