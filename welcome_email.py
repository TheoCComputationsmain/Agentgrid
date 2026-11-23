"""Best-effort onboarding email delivered through a user-owned outbound webhook.

AgentGrid holds no email-provider credentials and sends no money-related data.
Set ``AGENTGRID_WELCOME_EMAIL_WEBHOOK_URL`` to an HTTPS endpoint you control;
AgentGrid POSTs a small JSON payload and that endpoint sends the real email
(Resend, Postmark, Make, n8n, or your own bridge all work).

The send is deliberately non-fatal: registration succeeds even if the webhook
is slow, misconfigured, or down.
"""
from __future__ import annotations

import asyncio
import html
import json
import logging
import os
from typing import Any, Callable
from urllib.request import Request, urlopen

logger = logging.getLogger("agentgrid.welcome_email")

WEBHOOK_URL_ENV = "AGENTGRID_WELCOME_EMAIL_WEBHOOK_URL"
WEBHOOK_TOKEN_ENV = "AGENTGRID_WELCOME_EMAIL_WEBHOOK_TOKEN"
DEFAULT_BASE_URL = "https://agentgrid-pied.vercel.app"

WebhookPoster = Callable[[str, dict[str, Any], str], None]


def _default_poster(url: str, payload: dict[str, Any], token: str) -> None:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers=headers,
    )
    with urlopen(request, timeout=5) as response:
        if response.status >= 400:
            raise RuntimeError(f"webhook returned HTTP {response.status}")


# Module-level so tests can replace it without any network access.
_poster: WebhookPoster = _default_poster


def is_configured() -> bool:
    """True when an outbound welcome-email webhook has been configured."""
    return bool(os.environ.get(WEBHOOK_URL_ENV, "").strip())


def build_message(client_id: str, base_url: str = "") -> dict[str, str]:
    """Build the three-step welcome message. Never includes the API key."""
    base = (base_url or DEFAULT_BASE_URL).rstrip("/")
    safe_id = html.escape(client_id)
    safe_base = html.escape(base)

    text = f"""Hi,

You're registered with AgentGrid. Client ID: {client_id}

Your agk_... API key was shown once and stored locally by the CLI. Back it up now if you haven't already.

Three steps to your first signed handoff (about a minute):

1. Run the quickstart
     agrid quickstart
   Creates two agents, verifies a card online and offline, signs a handoff, and reads the receipt.

2. Verify a card offline
     agrid card <agent_id>
   Use an ag_... ID printed by step 1. The signature check uses the published platform key.

3. Read a receipt
     agrid receipts <agent_id>
   Use the worker agent ID from step 1. Receipts are immutable and public by agent ID.

Guide: {base}/guide
API:   {base}/docs

If you paid for a tier, register with the same email you paid with and enter this exact Client ID on the payment form.

— Theo, AgentGrid
"""

    html_body = f"""<div style="font:15px/1.6 system-ui;color:#eaf0ff;background:#0b1020;padding:20px">
<h2>Welcome to AgentGrid</h2>
<p>You're registered. Client ID: <code>{safe_id}</code></p>
<p><strong>Back up your <code>agk_...</code> key now</strong> — the service shows it only once.</p>
<h3>Three steps to your first signed handoff</h3>
<ol>
<li><strong>Run the quickstart</strong><br><code>agrid quickstart</code><br>
<span style="color:#9db0d0">Two agents, a verified card, a signed handoff, and its receipt.</span></li>
<li><strong>Verify a card offline</strong><br><code>agrid card &lt;agent_id&gt;</code><br>
<span style="color:#9db0d0">Use an <code>ag_...</code> ID from step 1.</span></li>
<li><strong>Read a receipt</strong><br><code>agrid receipts &lt;agent_id&gt;</code><br>
<span style="color:#9db0d0">Use the worker agent ID from step 1.</span></li>
</ol>
<p><a href="{safe_base}/guide" style="color:#7ee7c7">Developer guide</a> &middot;
<a href="{safe_base}/docs" style="color:#7ee7c7">API reference</a></p>
<p>If you paid for a tier, use this same email and enter your exact Client ID on the payment form.</p>
<p>— Theo, AgentGrid</p>
</div>"""

    return {
        "type": "agentgrid.welcome",
        "client_id": client_id,
        "subject": "Welcome to AgentGrid — your first signed handoff in 3 steps",
        "text": text,
        "html": html_body,
    }


async def send_welcome_email(email: str, client_id: str, base_url: str = "") -> bool:
    """Dispatch the welcome payload. Returns False when disabled or on failure."""
    recipient = (email or "").strip().lower()
    if not recipient or not is_configured():
        return False

    url = os.environ[WEBHOOK_URL_ENV].strip()
    token = os.environ.get(WEBHOOK_TOKEN_ENV, "").strip()
    payload: dict[str, Any] = {"to": recipient, **build_message(client_id, base_url)}

    try:
        await asyncio.to_thread(_poster, url, payload, token)
        return True
    except Exception as exc:  # noqa: BLE001 - onboarding must never break registration
        logger.warning("Welcome email dispatch failed (%s)", type(exc).__name__)
        return False
