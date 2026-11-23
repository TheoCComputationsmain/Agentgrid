"""Best-effort onboarding email with three provider options.

AgentGrid never stores email-provider credentials in code or the repo. Set ONE
of these in the Vercel project environment:

1. ``AGENTGRID_WELCOME_EMAIL_WEBHOOK_URL`` — POST JSON to an endpoint you own
   (Resend bridge, Make, n8n, operator-automation, etc.).
2. ``AGENTGRID_WELCOME_EMAIL_API_KEY`` + ``AGENTGRID_WELCOME_FROM_EMAIL`` —
   send directly through Resend's HTTPS API.
3. ``AGENTGRID_WELCOME_EMAIL_SMTP_HOST``, ``..._SMTP_PORT``, ``..._SMTP_USER``,
   ``..._SMTP_PASSWORD`` + ``AGENTGRID_WELCOME_FROM_EMAIL`` — send via SMTP
   (e.g. a Gmail app password). Used only if 1 and 2 are not configured.

Every mode is best-effort: a 10-second timeout, failures logged by type only,
and registration never fails because email failed. No API key is ever included
in the message.
"""
from __future__ import annotations

import asyncio
import html
import json
import logging
import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any, Callable
from urllib.request import Request, urlopen

logger = logging.getLogger("agentgrid.welcome_email")

WEBHOOK_URL_ENV = "AGENTGRID_WELCOME_EMAIL_WEBHOOK_URL"
WEBHOOK_TOKEN_ENV = "AGENTGRID_WELCOME_EMAIL_WEBHOOK_TOKEN"
RESEND_KEY_ENV = "AGENTGRID_WELCOME_EMAIL_API_KEY"
FROM_ENV = "AGENTGRID_WELCOME_FROM_EMAIL"
SMTP_HOST_ENV = "AGENTGRID_WELCOME_EMAIL_SMTP_HOST"
SMTP_PORT_ENV = "AGENTGRID_WELCOME_EMAIL_SMTP_PORT"
SMTP_USER_ENV = "AGENTGRID_WELCOME_EMAIL_SMTP_USER"
SMTP_PASSWORD_ENV = "AGENTGRID_WELCOME_EMAIL_SMTP_PASSWORD"

DEFAULT_BASE_URL = "https://agentgrid-pied.vercel.app"
RESEND_API_URL = "https://api.resend.com/emails"

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
    with urlopen(request, timeout=10) as response:
        if response.status >= 400:
            raise RuntimeError(f"webhook returned HTTP {response.status}")


def _resend_poster(payload: dict[str, Any], api_key: str) -> None:
    request = Request(
        RESEND_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + api_key,
        },
    )
    with urlopen(request, timeout=10) as response:
        if response.status >= 400:
            raise RuntimeError(f"resend returned HTTP {response.status}")


def _smtp_poster(message: EmailMessage, host: str, port: int, user: str, password: str) -> None:
    context = ssl.create_default_context()
    # A real hostname in EHLO avoids providers dropping connections from an
    # unnamed serverless container.
    local_hostname = "agentgrid-pied.vercel.app"
    if port == 465:
        with smtplib.SMTP_SSL(
            host, port, timeout=10, context=context, local_hostname=local_hostname
        ) as server:
            server.login(user, password)
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=10, local_hostname=local_hostname) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(user, password)
            server.send_message(message)


def _safe_exc(exc: Exception, *secrets: str) -> str:
    """Exception text for logs, with any credential substrings removed."""
    text = str(exc)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[redacted]")
    return text[:200]


# Module level so tests can replace these without any network access.
_poster: WebhookPoster = _default_poster
_resend_send: Callable[[dict[str, Any], str], None] = _resend_poster
_smtp_send: Callable[[EmailMessage, str, int, str, str], None] = _smtp_poster


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def is_configured() -> bool:
    """True when any delivery mode has been configured."""
    return bool(
        _env(WEBHOOK_URL_ENV)
        or (_env(RESEND_KEY_ENV) and _env(FROM_ENV))
        or (
            _env(SMTP_HOST_ENV)
            and _env(SMTP_USER_ENV)
            and _env(SMTP_PASSWORD_ENV)
            and _env(FROM_ENV)
        )
    )


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


def build_verification_message(client_id: str, code: str, base_url: str = "") -> dict[str, str]:
    """Build the human-verification message. Never includes an API key."""
    base = (base_url or DEFAULT_BASE_URL).rstrip("/")
    safe_id = html.escape(client_id)
    safe_code = html.escape(code)
    safe_base = html.escape(base)

    text = f"""Hi,

Someone registered an AgentGrid client with this email.

Client ID: {client_id}
Verification code: {code}

The code expires in 15 minutes. Run:

    agrid verify {code}

Your API key is created only after this step, so the account cannot be used
until you confirm you control this inbox. If you did not register, ignore this
email — no key exists and no action is needed.

Guide: {base}/guide

— Theo, AgentGrid
"""

    html_body = f"""<div style="font:15px/1.6 system-ui;color:#eaf0ff;background:#0b1020;padding:20px">
<h2>Confirm your AgentGrid registration</h2>
<p>Client ID: <code>{safe_id}</code></p>
<p>Your verification code is
<strong style="font-size:22px;letter-spacing:3px">{safe_code}</strong></p>
<p>The code expires in 15 minutes. Run <code>agrid verify {safe_code}</code>
to create your API key. Until then the account cannot be used.</p>
<p>If you did not register, ignore this email — no key exists.</p>
<p><a href="{safe_base}/guide" style="color:#7ee7c7">Developer guide</a></p>
<p>— Theo, AgentGrid</p>
</div>"""

    return {
        "type": "agentgrid.verify",
        "client_id": client_id,
        "subject": "Your AgentGrid verification code",
        "text": text,
        "html": html_body,
    }


async def _dispatch(email: str, message: dict[str, str]) -> bool:
    """Send a prepared message through the configured provider."""
    recipient = (email or "").strip().lower()
    if not recipient:
        return False

    webhook_url = _env(WEBHOOK_URL_ENV)
    if webhook_url:
        payload: dict[str, Any] = {"to": recipient, **message}
        token = _env(WEBHOOK_TOKEN_ENV)
        try:
            await asyncio.to_thread(_poster, webhook_url, payload, token)
            return True
        except Exception as exc:  # noqa: BLE001 - onboarding must never break registration
            logger.warning("Welcome email webhook failed (%s)", type(exc).__name__)
            return False

    api_key = _env(RESEND_KEY_ENV)
    sender = _env(FROM_ENV)
    if api_key and sender:
        payload = {
            "from": sender,
            "to": [recipient],
            "subject": message["subject"],
            "text": message["text"],
            "html": message["html"],
        }
        try:
            await asyncio.to_thread(_resend_send, payload, api_key)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Welcome email API failed (%s)", type(exc).__name__)
            return False

    smtp_host = _env(SMTP_HOST_ENV)
    smtp_user = _env(SMTP_USER_ENV)
    smtp_password = _env(SMTP_PASSWORD_ENV)
    if smtp_host and smtp_user and smtp_password and sender:
        try:
            port = int(_env(SMTP_PORT_ENV) or "465")
        except ValueError:
            port = 465
        mail = EmailMessage()
        mail["Subject"] = message["subject"]
        mail["From"] = sender
        mail["To"] = recipient
        mail.set_content(message["text"])
        mail.add_alternative(message["html"], subtype="html")
        try:
            await asyncio.to_thread(
                _smtp_send, mail, smtp_host, port, smtp_user, smtp_password
            )
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Welcome email SMTP failed on %s (%s: %s)",
                port,
                type(exc).__name__,
                _safe_exc(exc, smtp_user, smtp_password),
            )
            # Some serverless egress paths drop implicit TLS but accept STARTTLS
            # (or vice versa). Try the other standard submission port once.
            fallback = 587 if port == 465 else 465
            try:
                await asyncio.to_thread(
                    _smtp_send, mail, smtp_host, fallback, smtp_user, smtp_password
                )
                return True
            except Exception as exc2:  # noqa: BLE001
                logger.warning(
                    "Welcome email SMTP fallback failed on %s (%s: %s)",
                    fallback,
                    type(exc2).__name__,
                    _safe_exc(exc2, smtp_user, smtp_password),
                )
                return False

    return False


async def send_welcome_email(email: str, client_id: str, base_url: str = "") -> bool:
    """Dispatch the three-step welcome message after verification."""
    return await _dispatch(email, build_message(client_id, base_url))


async def send_verification_email(
    email: str, client_id: str, code: str, base_url: str = ""
) -> bool:
    """Dispatch the one-time human-verification code."""
    return await _dispatch(email, build_verification_message(client_id, code, base_url))
