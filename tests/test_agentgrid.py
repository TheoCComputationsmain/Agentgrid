import asyncio
import base64
import hashlib
import os
import re
import sqlite3
import subprocess
import sys
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

TEST_DB_PATH = Path(__file__).resolve().parent / "agentgrid_test.db"
if TEST_DB_PATH.exists():
    TEST_DB_PATH.unlink()
os.environ["AGENTGRID_DATABASE_URL"] = (
    "sqlite+aiosqlite:///" + TEST_DB_PATH.as_posix()
)
os.environ["AGENTGRID_SIGNING_KEY_B64"] = base64.urlsafe_b64encode(bytes(range(32))).decode("ascii").rstrip("=")
os.environ["AGENTGRID_ADMIN_KEY"] = "test-admin-key"
os.environ["AGENTGRID_ADMIN_MFA_SECRET"] = "JBSWY3DPEHPK3PXP"
os.environ["AGENTGRID_OPS_LITE_KEY"] = "test-read-key"
os.environ["AGENTGRID_OPS_LITE_CATCH"] = "test-catch-phrase"

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import main


@pytest.fixture(scope="module")
def api():
    with TestClient(main.app) as client:
        yield client


@pytest.fixture(autouse=True)
def _fresh_rate_bucket():
    """Keep the shared 120/min test bucket from leaking between tests."""
    main._rate_bucket.clear()
    yield
    main._rate_bucket.clear()


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _new_agent_key():
    private = Ed25519PrivateKey.generate()
    public_b64 = _b64e(
        private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )
    return private, public_b64


def _register_with_email(api, client_id=None, email=None):
    """Register and complete the dev-mode email verification flow."""
    body = {"email": email or f"{uuid.uuid4().hex}@example.test"}
    if client_id is not None:
        body["client_id"] = client_id
    response = api.post("/v1/clients/register", json=body)
    assert response.status_code == 201, response.text
    registered = response.json()
    assert "api_key" not in registered
    code = registered["verification_code"]
    verified = api.post(
        "/v1/clients/verify-email",
        json={"client_id": registered["client_id"], "code": code},
    )
    assert verified.status_code == 200, verified.text
    return verified.json()


def _register(api, client_id=None, email=None):
    return _register_with_email(api, client_id, email)


def _headers(api_key):
    return {"X-AgentGrid-API-Key": api_key}


def _create_agent(api, api_key, name="Agent", capabilities=None):
    _, public_b64 = _new_agent_key()
    response = api.post(
        "/v1/agents",
        headers=_headers(api_key),
        json={
            "name": name,
            "capabilities": capabilities or ["read"],
            "public_key": public_b64,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _totp():
    return main._totp_code("JBSWY3DPEHPK3PXP", int(time.time() // 30))


def test_health_and_root(api):
    assert api.get("/health/live").json()["status"] == "alive"
    ready = api.get("/health/ready")
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"
    assert "AgentGrid" in api.get("/").text


def test_public_search_discovery_endpoints(api):
    base = main.PUBLIC_BASE_URL
    robots = api.get("/robots.txt")
    assert robots.status_code == 200
    assert "Sitemap: " + base + "/sitemap.xml" in robots.text
    assert "Disallow: /ops" in robots.text
    assert "Disallow: /ops-lite" in robots.text

    sitemap = api.get("/sitemap.xml")
    assert sitemap.status_code == 200
    assert "<urlset" in sitemap.text
    assert base + "/guide" in sitemap.text

    registered = _register(api, email="seo@example.test")
    agent = _create_agent(api, registered["api_key"], "Search Discovery Agent")
    sitemap_after = api.get("/sitemap.xml")
    assert "/a/" + agent["agent_id"] in sitemap_after.text

    landing = api.get("/").text
    assert '<link rel="canonical" href="' + base + '/">' in landing
    assert "application/ld+json" in landing
    assert "SoftwareApplication" in landing

    guide = api.get("/guide").text
    assert '<link rel="canonical" href="' + base + '/guide">' in guide
    assert "TechArticle" in guide
    assert "FAQPage" in guide

    card = api.get("/a/" + agent["agent_id"]).text
    assert '<link rel="canonical" href="' + base + "/a/" + agent["agent_id"] + '">' in card
    assert "application/ld+json" in card

    ops = api.get("/ops")
    assert "noindex" in ops.text
    assert ops.headers["x-robots-tag"] == "noindex, nofollow"


def test_ops_lite_single_step_snapshot(api):
    login = api.get("/ops-lite")
    assert login.status_code == 200
    assert "Read key" in login.text
    assert "Catch phrase" in login.text

    bad = api.post(
        "/v1/ops-lite/session",
        data={"key": "wrong", "catch_phrase": "wrong"},
        follow_redirects=False,
    )
    assert bad.status_code == 401
    assert "Invalid read key or catch phrase" in bad.text

    good = api.post(
        "/v1/ops-lite/session",
        data={"key": "test-read-key", "catch_phrase": "test-catch-phrase"},
        follow_redirects=False,
    )
    assert good.status_code == 303
    assert main.OPS_LITE_COOKIE in good.cookies

    dashboard = api.get("/ops-lite")
    assert dashboard.status_code == 200
    assert "Public users" in dashboard.text
    assert "Paid active" in dashboard.text
    assert "All accounts" not in dashboard.text
    assert "Recent clients" in dashboard.text
    assert "Sign out" in dashboard.text

    test_client = _register(api, client_id="smoke_ops_lite_" + uuid.uuid4().hex[:8])
    hidden = api.get("/ops-lite")
    assert test_client["client_id"] not in hidden.text
    hidden_detail = api.get(f"/ops-lite/client/{test_client['client_id']}")
    assert hidden_detail.status_code == 404

    stats = api.get("/v1/admin/stats")
    assert stats.status_code == 200
    assert "public_users" in stats.json()

    logout = api.post("/v1/ops-lite/logout", follow_redirects=False)
    assert logout.status_code == 303
    assert api.get("/ops-lite").text.count("Read key") >= 1


def test_no_code_quickstart_creates_real_handoff(api, monkeypatch):
    landing = api.get("/")
    assert "without writing code" in landing.text
    assert 'href="/quickstart"' in landing.text

    page = api.get("/quickstart")
    assert page.status_code == 200
    assert "no code needed" in page.text
    assert "no-store" in page.headers["cache-control"]

    captured: dict[str, str] = {}

    async def capture_code(email, client_id, code, base_url):
        captured["code"] = code

    monkeypatch.setattr(main, "send_verification_email", capture_code)

    started = api.post(
        "/v1/quickstart/start",
        data={"email": f"nocode_{uuid.uuid4().hex}@example.test"},
    )
    assert started.status_code == 200, started.text
    assert "Check your inbox" in started.text
    client_id = re.search(r"Client ID: <code>([^<]+)</code>", started.text).group(1)
    assert captured["code"]
    assert captured["code"] not in started.text

    bad = api.post(
        "/v1/quickstart/finish",
        data={"client_id": client_id, "code": "000000" if captured["code"] != "000000" else "111111"},
    )
    assert bad.status_code == 400
    assert "Invalid code" in bad.text

    finished = api.post(
        "/v1/quickstart/finish",
        data={"client_id": client_id, "code": captured["code"]},
    )
    assert finished.status_code == 200, finished.text
    assert "Your handoff is recorded" in finished.text
    assert "API key for CLI/SDK use" in finished.text
    assert "Shareable receipt link" in finished.text
    assert "Know another builder?" in finished.text
    assert re.search(r"h_[0-9a-f]{32}", finished.text)

    agents = _sqlite_rows("SELECT agent_id FROM agents WHERE client_id = ?", (client_id,))
    handoffs = _sqlite_rows("SELECT handoff_id FROM handoffs WHERE client_id = ?", (client_id,))
    assert len(agents) == 2
    assert len(handoffs) == 1


def test_open_registration_and_api_key_auth(api):
    # Public self-service registration needs no invite token.
    unauthenticated = api.get("/v1/clients/me")
    assert unauthenticated.status_code == 401
    registered = _register(api)
    assert registered["tier"] == "free"
    assert registered["limits"] == {"agents": 5, "handoffs": 100}
    assert registered["api_key"].startswith("agk_")
    me = api.get("/v1/clients/me", headers=_headers(registered["api_key"]))
    assert me.status_code == 200
    assert me.json()["client_id"] == registered["client_id"]
    assert me.json()["email_on_file"] is True
    assert me.json()["legacy_upgrade_available"] is False
    assert me.json()["next_step"] is None


def test_admin_assisted_registration(api):
    path = "/v1/admin/clients/register"
    cid = "admin_reg_" + uuid.uuid4().hex[:10]
    body_json = {"client_id": cid, "email": f"admin-{uuid.uuid4().hex[:8]}@example.test"}
    assert api.post(path, json=body_json).status_code == 401
    assert api.post(
        path,
        headers={"X-AgentGrid-Admin-Key": "test-admin-key"},
        json=body_json,
    ).status_code == 401
    admin_headers = {
        "X-AgentGrid-Admin-Key": "test-admin-key",
        "X-AgentGrid-Admin-MFA": _totp(),
    }
    created = api.post(path, headers=admin_headers, json=body_json)
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["client_id"] == cid
    assert body["api_key"].startswith("agk_")
    assert body["tier"] == "free"
    me = api.get("/v1/clients/me", headers=_headers(body["api_key"]))
    assert me.status_code == 200
    assert me.json()["client_id"] == cid
    duplicate = api.post(path, headers=admin_headers, json=body_json)
    assert duplicate.status_code == 409


def test_admin_stats_pulse_filters_test_accounts(api):
    assert api.get("/v1/admin/stats").status_code == 401
    headers = {"X-AgentGrid-Admin-Key": "test-admin-key", "X-AgentGrid-Admin-MFA": _totp()}

    before = api.get("/v1/admin/stats", headers=headers)
    assert before.status_code == 200
    before_public = before.json()["public_users"]["total"]

    client = _register(api)
    assert client["client_id"].startswith("cli_")
    _create_agent(api, client["api_key"], name="Pulse Agent")

    after = api.get("/v1/admin/stats", headers=headers)
    assert after.status_code == 200
    body = after.json()
    assert body["public_users"]["total"] == before_public + 1
    assert body["public_users"]["verified"] == body["public_users"]["total"]
    assert body["public_users"]["tiers"]["free"] >= 1
    assert body["public_users"]["agents"] >= 1
    assert body["public_users"]["active_users"] >= 1
    assert "unverified_signups" in body
    assert "smoke_" in body["excluded_prefixes"]


def test_agent_card_signature_and_verification(api):
    client = _register(api)
    card = _create_agent(api, client["api_key"], name="Research Agent", capabilities=["web_search"])
    assert card["signature"]
    assert card["capabilities"] == ["web_search"]
    # "overage" is response metadata, not part of the signed Agent Card payload.
    assert main.verify_platform(
        {k: v for k, v in card.items() if k not in {"signature", "verify_url", "overage"}},
        card["signature"],
    )
    public = api.get("/v1/agents/public-key")
    assert public.json()["algorithm"] == "Ed25519"
    json_card = api.get(f"/v1/agents/{card['agent_id']}.json")
    assert json_card.status_code == 200
    assert json_card.json()["signature"] == card["signature"]
    verified = api.get(f"/v1/agents/{card['agent_id']}/verify")
    assert verified.json()["signature_valid"] is True
    page = api.get(f"/a/{card['agent_id']}")
    assert page.status_code == 200
    assert "AgentGrid verified card" in page.text
    assert "Share this card" in page.text
    assert 'href="/quickstart"' in page.text


def test_agent_overage_hard_cap_and_upgrade(api, monkeypatch):
    monkeypatch.setitem(main.TIER_LIMITS["free"], "agents", 1)
    client = _register(api)
    headers = _headers(client["api_key"])

    first = _create_agent(api, client["api_key"], name="Included")
    assert first["overage"] is False
    second = _create_agent(api, client["api_key"], name="Extra one")
    third = _create_agent(api, client["api_key"], name="Extra two")
    assert second["overage"] is True
    assert third["overage"] is True

    blocked = api.post(
        "/v1/agents",
        headers=headers,
        json={"name": "Over hard cap", "public_key": _new_agent_key()[1]},
    )
    assert blocked.status_code == 402
    assert "hard cap (3)" in blocked.json()["detail"]

    ledger = _sqlite_rows(
        "SELECT usage_type, units, tier FROM overage_ledger WHERE client_id = ?",
        (client["client_id"],),
    )
    assert len(ledger) == 2
    assert {row["usage_type"] for row in ledger} == {"agent"}
    assert {row["tier"] for row in ledger} == {"free"}

    grant = api.post(
        f"/v1/admin/clients/{client['client_id']}/grant-access",
        headers={
            "X-AgentGrid-Admin-Key": "test-admin-key",
            "X-AgentGrid-Admin-MFA": _totp(),
        },
        json={
            "tier": "plus",
            "cashfree_order_id": "order_upgrade_" + uuid.uuid4().hex,
            "cashfree_payment_id": "pay_upgrade_" + uuid.uuid4().hex,
        },
    )
    assert grant.status_code == 200, grant.text
    assert grant.json()["tier"] == "plus"
    assert grant.json()["limits"] == {"agents": 100, "handoffs": 10_000}

    # Upgrades apply to the current rolling cycle, not only the next one.
    upgraded = _create_agent(api, client["api_key"], name="After upgrade")
    assert upgraded["overage"] is False


def test_handoff_signature_receipts_and_scope_chain(api):
    client = _register(api)
    first_private, first_public = _new_agent_key()
    second_private, second_public = _new_agent_key()

    first = api.post(
        "/v1/agents",
        headers=_headers(client["api_key"]),
        json={"name": "Planner", "capabilities": ["plan"], "public_key": first_public},
    ).json()
    second = api.post(
        "/v1/agents",
        headers=_headers(client["api_key"]),
        json={"name": "Worker", "capabilities": ["read"], "public_key": second_public},
    ).json()

    handoff_id = "h_" + uuid.uuid4().hex
    created_at = main._now_iso()
    task_hash = hashlib.sha256(b"do the thing").hexdigest()
    scope = {"allowed": ["read"], "max_actions": 3}
    payload = {
        "v": 1,
        "handoff_id": handoff_id,
        "from_agent_id": first["agent_id"],
        "to_agent_id": second["agent_id"],
        "task_hash": task_hash,
        "scope": scope,
        "created_at": created_at,
        "parent_handoff_id": "",
    }
    signature = _b64e(first_private.sign(main.canonical_bytes(payload)))
    response = api.post(
        f"/v1/agents/{first['agent_id']}/handoffs",
        headers=_headers(client["api_key"]),
        json={**{k: v for k, v in payload.items() if k != "from_agent_id"}, "signature": signature},
    )
    assert response.status_code == 201, response.text
    assert response.json()["signature_valid"] is True

    bad = api.post(
        f"/v1/agents/{first['agent_id']}/handoffs",
        headers=_headers(client["api_key"]),
        json={
            **{k: v for k, v in payload.items() if k != "from_agent_id"},
            "handoff_id": "h_" + uuid.uuid4().hex,
            "signature": _b64e(second_private.sign(main.canonical_bytes(payload))),
        },
    )
    assert bad.status_code == 401

    receipts = api.get(f"/v1/agents/{second['agent_id']}/receipts")
    assert receipts.status_code == 200
    assert any(item["handoff_id"] == handoff_id for item in receipts.json()["receipts"])

    # Nested delegation may narrow but not widen scope.
    child_id = "h_" + uuid.uuid4().hex
    child_scope = {"allowed": ["read"], "max_actions": 5}
    child_payload = {
        "v": 1,
        "handoff_id": child_id,
        "from_agent_id": second["agent_id"],
        "to_agent_id": first["agent_id"],
        "task_hash": task_hash,
        "scope": child_scope,
        "created_at": main._now_iso(),
        "parent_handoff_id": handoff_id,
    }
    widened = api.post(
        f"/v1/agents/{second['agent_id']}/handoffs",
        headers=_headers(client["api_key"]),
        json={
            **{k: v for k, v in child_payload.items() if k != "from_agent_id"},
            "signature": _b64e(second_private.sign(main.canonical_bytes(child_payload))),
        },
    )
    assert widened.status_code == 400


def test_admin_grant_requires_totp_and_is_idempotent(api):
    client = _register(api)
    order_id = "order_" + uuid.uuid4().hex
    missing_mfa = api.post(
        f"/v1/admin/clients/{client['client_id']}/grant-access",
        headers={"X-AgentGrid-Admin-Key": "test-admin-key"},
        json={
            "tier": "enterprise",
            "cashfree_order_id": order_id,
            "cashfree_payment_id": "pay_" + order_id,
        },
    )
    assert missing_mfa.status_code == 401

    headers = {"X-AgentGrid-Admin-Key": "test-admin-key", "X-AgentGrid-Admin-MFA": _totp()}
    first = api.post(
        f"/v1/admin/clients/{client['client_id']}/grant-access",
        headers=headers,
        json={
            "tier": "enterprise",
            "cashfree_order_id": order_id,
            "cashfree_payment_id": "pay_" + order_id,
        },
    )
    assert first.status_code == 200
    assert first.json()["duplicate"] is False
    assert first.json()["limits"] == {"agents": 10_000, "handoffs": 1_000_000}
    second = api.post(
        f"/v1/admin/clients/{client['client_id']}/grant-access",
        headers=headers,
        json={
            "tier": "enterprise",
            "cashfree_order_id": order_id,
            "cashfree_payment_id": "pay_" + order_id,
        },
    )
    assert second.status_code == 200
    assert second.json()["duplicate"] is True

    conflict = api.post(
        f"/v1/admin/clients/{_register(api)['client_id']}/grant-access",
        headers=headers,
        json={
            "tier": "pro",
            "cashfree_order_id": order_id,
            "cashfree_payment_id": "pay_conflict_" + uuid.uuid4().hex,
        },
    )
    assert conflict.status_code == 409

    comp = api.post(
        f"/v1/admin/clients/{_register(api)['client_id']}/grant-access",
        headers=headers,
        json={
            "tier": "plus",
            "cashfree_order_id": "order_comp_" + uuid.uuid4().hex,
            "cashfree_payment_id": "pay_comp_" + uuid.uuid4().hex,
            "grant_reason": "operator_comp",
            "reason_note": "support exception",
        },
    )
    assert comp.status_code == 200, comp.text
    assert comp.json()["grant_source"] == "operator_comp"


def _create_agent_with_key(api, api_key, name="Agent"):
    private, public_b64 = _new_agent_key()
    response = api.post(
        "/v1/agents",
        headers=_headers(api_key),
        json={"name": name, "capabilities": ["read"], "public_key": public_b64},
    )
    assert response.status_code == 201, response.text
    return private, response.json()


def _handoff_body(
    signer_private,
    from_agent_id,
    to_agent_id,
    *,
    handoff_id=None,
    scope=None,
    task_hash=None,
    created_at=None,
    parent=None,
):
    payload = {
        "v": 1,
        "handoff_id": handoff_id or "h_" + uuid.uuid4().hex,
        "from_agent_id": from_agent_id,
        "to_agent_id": to_agent_id,
        "task_hash": task_hash or hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
        "scope": scope if scope is not None else {"allowed": ["read"], "max_actions": 3},
        "created_at": created_at or main._now_iso(),
        "parent_handoff_id": parent or "",
    }
    signature = _b64e(signer_private.sign(main.canonical_bytes(payload)))
    body = {key: value for key, value in payload.items() if key != "from_agent_id"}
    body["signature"] = signature
    return body


def _sqlite_blocked(sql, params):
    connection = sqlite3.connect(TEST_DB_PATH)
    try:
        connection.execute(sql, params)
        connection.commit()
        return False
    except sqlite3.Error:
        connection.rollback()
        return True
    finally:
        connection.close()


def _sqlite_rows(sql, params=()):
    connection = sqlite3.connect(TEST_DB_PATH)
    connection.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in connection.execute(sql, params).fetchall()]
    finally:
        connection.close()


def test_source_has_no_aacl_references():
    root = Path(__file__).resolve().parents[1]
    forbidden = ("aacl", "customer_portal", "dashboard.html")
    allowed_suffixes = {".py", ".md", ".txt", ".example"}
    # "theoc" is now part of the official PyPI distribution name
    # `theoc-agentgrid-protocol`; only that exact phrase is permitted.
    allowed_phrases = ("theoc-agentgrid-protocol",)
    allowed_names = {"Dockerfile", ".dockerignore", ".gitignore"}
    checked = []

    this_file = Path(__file__).resolve()
    for path in root.rglob("*"):
        if not path.is_file() or path.resolve() == this_file:
            continue
        if "__pycache__" in path.parts or ".pytest_cache" in path.parts:
            continue
        if path.suffix not in allowed_suffixes and path.name not in allowed_names:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        for phrase in allowed_phrases:
            text = text.replace(phrase, "")
        checked.append(path.name)
        for term in forbidden:
            assert term not in text, f"{path.name} contains forbidden legacy reference: {term}"

    assert "main.py" in checked
    assert "README.md" in checked


def test_production_signing_key_fail_closed():
    env = os.environ.copy()
    env["AGENTGRID_APP_ENV"] = "production"
    env["AGENTGRID_SIGNING_KEY_B64"] = ""
    env["AGENTGRID_PREVIOUS_SIGNING_KEY_B64"] = ""
    result = subprocess.run(
        [sys.executable, "-c", "import main"],
        cwd=str(Path(__file__).resolve().parents[1]),
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "AGENTGRID_SIGNING_KEY_B64 is required in production" in result.stderr


def test_registration_duplicate_invalid_id_and_open_production(api, monkeypatch):
    missing_email = api.post("/v1/clients/register", json={})
    assert missing_email.status_code == 422

    client_id = "cli_fixed_" + uuid.uuid4().hex[:8]
    email = f"{uuid.uuid4().hex[:8]}@example.test"
    first = _register(api, client_id, email)
    assert first["client_id"] == client_id

    duplicate = api.post("/v1/clients/register", json={"client_id": client_id, "email": email})
    assert duplicate.status_code == 409

    invalid_id = api.post(
        "/v1/clients/register", json={"client_id": "bad id!", "email": email}
    )
    assert invalid_id.status_code == 422

    # An arbitrary token header is harmless; registration stays open.
    with_token = api.post(
        "/v1/clients/register",
        headers={"X-AgentGrid-Registration-Token": "anything"},
        json={"email": f"{uuid.uuid4().hex[:8]}@example.test"},
    )
    assert with_token.status_code == 201

    bad_format = api.get("/v1/clients/me", headers={"X-AgentGrid-API-Key": "short"})
    assert bad_format.status_code == 401

    unknown_key = api.get(
        "/v1/clients/me", headers=_headers("agk_" + "a" * 43)
    )
    assert unknown_key.status_code == 401

    monkeypatch.setattr(main, "APP_ENV", "production")
    open_in_prod = api.post(
        "/v1/clients/register", json={"email": f"{uuid.uuid4().hex[:8]}@example.test"}
    )
    assert open_in_prod.status_code == 201
    assert "verification_code" not in open_in_prod.json()
    assert "api_key" not in open_in_prod.json()


def _pending_registration(api, email=None):
    client_id = "verify_" + uuid.uuid4().hex[:10]
    response = api.post(
        "/v1/clients/register",
        json={"client_id": client_id, "email": email or f"{uuid.uuid4().hex[:8]}@example.test"},
    )
    assert response.status_code == 201, response.text
    return client_id, response.json()


def test_email_verification_issues_key_only_after_code(api):
    client_id, pending = _pending_registration(api)
    assert pending["verification_required"] is True
    assert "api_key" not in pending
    assert api.get("/v1/clients/me", headers={"X-AgentGrid-API-Key": "agk_" + "0" * 43}).status_code == 401

    correct = pending["verification_code"]
    wrong = "000000" if correct != "000000" else "111111"
    failed = api.post(
        "/v1/clients/verify-email", json={"client_id": client_id, "code": wrong}
    )
    assert failed.status_code == 400
    assert "attempt(s) remaining" in failed.json()["detail"]

    with sqlite3.connect(TEST_DB_PATH) as conn:
        attempts = conn.execute(
            "SELECT verification_attempts FROM clients WHERE client_id = ?", (client_id,)
        ).fetchone()[0]
    assert attempts == 1

    verified = api.post(
        "/v1/clients/verify-email", json={"client_id": client_id, "code": correct}
    )
    assert verified.status_code == 200, verified.text
    api_key = verified.json()["api_key"]
    assert api_key.startswith("agk_")
    assert api.get("/v1/clients/me", headers=_headers(api_key)).status_code == 200

    replay = api.post(
        "/v1/clients/verify-email", json={"client_id": client_id, "code": correct}
    )
    assert replay.status_code == 409

    with sqlite3.connect(TEST_DB_PATH) as conn:
        row = conn.execute(
            "SELECT email_verified, verification_code_hash, verification_sent_at "
            "FROM clients WHERE client_id = ?",
            (client_id,),
        ).fetchone()
    assert row == (1, None, None)


def test_legacy_account_upgrade_verifies_email_and_rotates_key(api):
    """Pre-email accounts can attach an email, prove the inbox, and get a new key."""
    legacy_id = "cli_legacy_upgrade"
    legacy = _register(api, client_id=legacy_id, email="old-legacy@example.test")
    old_key = legacy["api_key"]

    # Simulate a legacy row: verified, but no email on file and no pending code.
    with sqlite3.connect(TEST_DB_PATH) as conn:
        conn.execute(
            "UPDATE clients SET email = NULL, email_verified = 1, "
            "verification_code_hash = NULL, verification_expires_at = NULL, "
            "verification_sent_at = NULL WHERE client_id = ?",
            (legacy_id,),
        )
    before = api.get("/v1/clients/me", headers=_headers(old_key))
    assert before.status_code == 200
    assert before.json()["email_on_file"] is False
    assert before.json()["legacy_upgrade_available"] is True
    assert "agrid update --email" in before.json()["next_step"]

    upgrade = api.post(
        "/v1/clients/me/upgrade-email",
        headers=_headers(old_key),
        json={"email": "Legacy@Example.Test"},
    )
    assert upgrade.status_code == 200, upgrade.text
    data = upgrade.json()
    assert data["legacy_upgrade"] is True
    assert data["verification_required"] is True
    assert data["email"] == "legacy@example.test"
    assert "api_key" not in data
    code = data["verification_code"]

    # The old key is now intentionally unusable until the code is confirmed.
    assert api.get("/v1/clients/me", headers=_headers(old_key)).status_code == 401

    verified = api.post(
        "/v1/clients/verify-email", json={"client_id": legacy_id, "code": code}
    )
    assert verified.status_code == 200, verified.text
    new_key = verified.json()["api_key"]
    assert new_key != old_key
    after = api.get("/v1/clients/me", headers=_headers(new_key))
    assert after.status_code == 200
    assert after.json()["email_on_file"] is True
    assert after.json()["legacy_upgrade_available"] is False
    assert after.json()["next_step"] is None

    again = api.post(
        "/v1/clients/me/upgrade-email",
        headers=_headers(new_key),
        json={"email": "other@example.test"},
    )
    assert again.status_code == 409


def test_verification_expiry_resend_and_attempt_limit(api):
    client_id, pending = _pending_registration(api)
    code = pending["verification_code"]
    with sqlite3.connect(TEST_DB_PATH) as conn:
        conn.execute(
            "UPDATE clients SET verification_expires_at = ? WHERE client_id = ?",
            ("2000-01-01T00:00:00+00:00", client_id),
        )
    expired = api.post(
        "/v1/clients/verify-email", json={"client_id": client_id, "code": code}
    )
    assert expired.status_code == 410

    too_soon = api.post("/v1/clients/resend-verification", json={"client_id": client_id})
    assert too_soon.status_code == 429

    with sqlite3.connect(TEST_DB_PATH) as conn:
        conn.execute(
            "UPDATE clients SET verification_sent_at = ? WHERE client_id = ?",
            ("2000-01-01T00:00:00+00:00", client_id),
        )
    resent = api.post("/v1/clients/resend-verification", json={"client_id": client_id})
    assert resent.status_code == 200, resent.text
    new_code = resent.json()["verification_code"]

    wrong_codes = [f"{value:06d}" for value in range(10) if f"{value:06d}" != new_code][:5]
    for wrong in wrong_codes:
        failed = api.post(
            "/v1/clients/verify-email", json={"client_id": client_id, "code": wrong}
        )
        assert failed.status_code == 400
    locked = api.post(
        "/v1/clients/verify-email", json={"client_id": client_id, "code": new_code}
    )
    assert locked.status_code == 429


def test_agent_validation_failures(api):
    client = _register(api)
    headers = _headers(client["api_key"])

    cases = [
        {"name": "Bad key", "public_key": "not-a-valid-public-key-000000"},
        {"name": "Blank capability", "public_key": _new_agent_key()[1], "capabilities": ["  "]},
        {"name": "Bad endpoint", "public_key": _new_agent_key()[1], "endpoint_url": "ftp://bad.example"},
        {"name": "Too many capabilities", "public_key": _new_agent_key()[1], "capabilities": ["read"] * 51},
        {"name": "", "public_key": _new_agent_key()[1]},
    ]
    for body in cases:
        response = api.post("/v1/agents", headers=headers, json=body)
        assert response.status_code == 422, response.text

    assert api.get("/v1/agents", headers=headers).json()["count"] == 0


def test_handoff_failure_paths_are_rejected(api):
    client = _register(api)
    from_private, from_agent = _create_agent_with_key(api, client["api_key"], "From")
    _, to_agent = _create_agent_with_key(api, client["api_key"], "To")
    url = f"/v1/agents/{from_agent['agent_id']}/handoffs"
    headers = _headers(client["api_key"])

    valid_body = _handoff_body(from_private, from_agent["agent_id"], to_agent["agent_id"])
    assert api.post(url, headers=headers, json=valid_body).status_code == 201

    invalid_id = _handoff_body(
        from_private, from_agent["agent_id"], to_agent["agent_id"], handoff_id="bad"
    )
    assert api.post(url, headers=headers, json=invalid_id).status_code == 422

    invalid_hash = _handoff_body(
        from_private, from_agent["agent_id"], to_agent["agent_id"], task_hash="xyz"
    )
    assert api.post(url, headers=headers, json=invalid_hash).status_code == 422

    stale_time = (
        datetime.now(timezone.utc) - timedelta(hours=1)
    ).isoformat().replace("+00:00", "Z")
    stale = _handoff_body(
        from_private, from_agent["agent_id"], to_agent["agent_id"], created_at=stale_time
    )
    assert api.post(url, headers=headers, json=stale).status_code == 422

    oversized = _handoff_body(
        from_private,
        from_agent["agent_id"],
        to_agent["agent_id"],
        scope={"blob": "x" * 9_000},
    )
    assert api.post(url, headers=headers, json=oversized).status_code == 422

    wrong_private, _ = _new_agent_key()
    bad_signature = _handoff_body(
        wrong_private, from_agent["agent_id"], to_agent["agent_id"]
    )
    assert api.post(url, headers=headers, json=bad_signature).status_code == 401

    duplicate = api.post(url, headers=headers, json=valid_body)
    assert duplicate.status_code == 409

    orphan = _handoff_body(
        from_private,
        from_agent["agent_id"],
        to_agent["agent_id"],
        parent="h_" + uuid.uuid4().hex,
    )
    assert api.post(url, headers=headers, json=orphan).status_code == 400


def test_handoff_rejects_foreign_agent(api):
    owner = _register(api)
    intruder = _register(api)
    owner_private, owner_agent = _create_agent_with_key(api, owner["api_key"], "Owner")
    _, other_agent = _create_agent_with_key(api, intruder["api_key"], "Other")

    body = _handoff_body(owner_private, owner_agent["agent_id"], other_agent["agent_id"])
    response = api.post(
        f"/v1/agents/{owner_agent['agent_id']}/handoffs",
        headers=_headers(intruder["api_key"]),
        json=body,
    )
    assert response.status_code == 403


def test_handoff_overage_and_hard_cap(api, monkeypatch):
    limits = {name: dict(values) for name, values in main.TIER_LIMITS.items()}
    limits["free"]["handoffs"] = 1
    monkeypatch.setattr(main, "TIER_LIMITS", limits)

    client = _register(api)
    from_private, from_agent = _create_agent_with_key(api, client["api_key"], "From")
    _, to_agent = _create_agent_with_key(api, client["api_key"], "To")
    url = f"/v1/agents/{from_agent['agent_id']}/handoffs"
    headers = _headers(client["api_key"])

    included = api.post(url, headers=headers, json=_handoff_body(
        from_private, from_agent["agent_id"], to_agent["agent_id"]
    ))
    assert included.status_code == 201
    assert included.json()["overage"] is False

    for _ in range(2):
        extra = api.post(url, headers=headers, json=_handoff_body(
            from_private, from_agent["agent_id"], to_agent["agent_id"]
        ))
        assert extra.status_code == 201
        assert extra.json()["overage"] is True

    blocked = api.post(url, headers=headers, json=_handoff_body(
        from_private, from_agent["agent_id"], to_agent["agent_id"]
    ))
    assert blocked.status_code == 402
    assert "hard cap (3)" in blocked.json()["detail"]

    me = api.get("/v1/clients/me", headers=headers)
    assert me.json()["handoffs_used"] == 3

    ledger = _sqlite_rows(
        "SELECT usage_type, units, tier FROM overage_ledger WHERE client_id = ?",
        (client["client_id"],),
    )
    assert len(ledger) == 2
    assert {row["usage_type"] for row in ledger} == {"handoff"}


def test_rolling_cycle_bounds():
    assert main._next_cycle_date(date(2026, 11, 18)).isoformat() == "2026-12-18"
    assert main._next_cycle_date(date(2026, 12, 18)).isoformat() == "2027-01-18"
    assert main._next_cycle_date(date(2026, 1, 31)).isoformat() == "2026-02-28"
    assert main._next_cycle_date(date(2028, 1, 31)).isoformat() == "2028-02-29"


def test_statement_is_ledger_backed_and_external_only(api, monkeypatch):
    today = datetime.now(timezone.utc).date()
    async def no_rollover(client, db):
        return None

    monkeypatch.setattr(main, "_next_cycle_date", lambda _value: today)
    monkeypatch.setattr(main, "ensure_current_period", no_rollover)
    monkeypatch.setitem(main.TIER_LIMITS["free"], "agents", 1)
    monkeypatch.setitem(main.TIER_LIMITS["free"], "handoffs", 1)

    client = _register(api)
    assert client["cycle_start"] == today.isoformat()
    assert client["cycle_end"] == today.isoformat()
    headers = _headers(client["api_key"])

    from_private, from_agent = _create_agent_with_key(api, client["api_key"], "From")
    _, to_agent = _create_agent_with_key(api, client["api_key"], "To")
    url = f"/v1/agents/{from_agent['agent_id']}/handoffs"

    included = api.post(url, headers=headers, json=_handoff_body(
        from_private, from_agent["agent_id"], to_agent["agent_id"]
    ))
    assert included.status_code == 201
    assert included.json()["overage"] is False

    extra = api.post(url, headers=headers, json=_handoff_body(
        from_private, from_agent["agent_id"], to_agent["agent_id"]
    ))
    assert extra.status_code == 201
    assert extra.json()["overage"] is True

    statement = api.get("/v1/billing/statement", headers=headers)
    assert statement.status_code == 200
    body = statement.json()
    assert body["final"] is True
    assert body["payment_status"] == "unpaid"
    assert body["cashfree_order_id"] is None
    assert body["base_fee_usd"] == "0"
    assert body["overage"]["handoffs"]["count"] == 1
    assert body["overage"]["handoffs"]["amount_usd"] == "0.001"
    assert body["overage"]["agents"]["extra_agents"] == 1
    assert body["overage"]["agents"]["agent_days"] == 1
    assert body["overage"]["agents"]["amount_usd"] == "0.1"
    assert body["total_due_microdollars"] == 101_000
    assert body["total_due_usd"] == "0.101"
    assert "No in-app payment" in body["payment_instructions"]


def test_statement_payment_is_external_and_idempotent(api, monkeypatch):
    today = datetime.now(timezone.utc).date()
    async def no_rollover(client, db):
        return None

    monkeypatch.setattr(main, "_next_cycle_date", lambda _value: today)
    monkeypatch.setattr(main, "ensure_current_period", no_rollover)

    client = _register(api)
    start = client["cycle_start"]
    url = f"/v1/admin/clients/{client['client_id']}/statements/{start}/record-payment"
    admin_headers = {
        "X-AgentGrid-Admin-Key": "test-admin-key",
        "X-AgentGrid-Admin-MFA": _totp(),
    }
    order_id = "order_stmt_" + uuid.uuid4().hex

    first = api.post(url, headers=admin_headers, json={
        "cashfree_order_id": order_id,
        "cashfree_payment_id": "pay_" + uuid.uuid4().hex,
    })
    assert first.status_code == 200, first.text
    assert first.json()["duplicate"] is False
    assert first.json()["payment_status"] == "paid"

    duplicate = api.post(url, headers=admin_headers, json={"cashfree_order_id": order_id})
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True

    different_order = api.post(url, headers=admin_headers, json={
        "cashfree_order_id": "order_other_" + uuid.uuid4().hex
    })
    assert different_order.status_code == 409

    statement = api.get("/v1/billing/statement", headers=_headers(client["api_key"]))
    assert statement.json()["payment_status"] == "paid"
    assert statement.json()["cashfree_order_id"] == order_id


def test_record_payment_rejects_open_cycle(api):
    client = _register(api)
    url = f"/v1/admin/clients/{client['client_id']}/statements/{client['cycle_start']}/record-payment"
    response = api.post(
        url,
        headers={
            "X-AgentGrid-Admin-Key": "test-admin-key",
            "X-AgentGrid-Admin-MFA": _totp(),
        },
        json={"cashfree_order_id": "order_open_" + uuid.uuid4().hex},
    )
    assert response.status_code == 409


def test_admin_grant_failure_paths(api, monkeypatch):
    client = _register(api)
    url = f"/v1/admin/clients/{client['client_id']}/grant-access"
    valid = {
        "tier": "pro",
        "cashfree_order_id": "order_" + uuid.uuid4().hex,
        "cashfree_payment_id": "pay_" + uuid.uuid4().hex,
    }

    wrong_key = api.post(
        url,
        headers={
            "X-AgentGrid-Admin-Key": "wrong-key",
            "X-AgentGrid-Admin-MFA": _totp(),
        },
        json=valid,
    )
    assert wrong_key.status_code == 401

    wrong_mfa = api.post(
        url,
        headers={"X-AgentGrid-Admin-Key": "test-admin-key", "X-AgentGrid-Admin-MFA": "abcdef"},
        json=valid,
    )
    assert wrong_mfa.status_code == 401

    headers = {"X-AgentGrid-Admin-Key": "test-admin-key", "X-AgentGrid-Admin-MFA": _totp()}
    invalid_tier = api.post(url, headers=headers, json={**valid, "tier": "free"})
    assert invalid_tier.status_code == 422

    invalid_order = api.post(url, headers=headers, json={**valid, "cashfree_order_id": "bad id!"})
    assert invalid_order.status_code == 422

    missing_payment = api.post(
        url, headers=headers, json={k: v for k, v in valid.items() if k != "cashfree_payment_id"}
    )
    assert missing_payment.status_code == 422
    assert "cashfree_payment_id" in missing_payment.json()["detail"]

    bad_reason = api.post(url, headers=headers, json={**valid, "grant_reason": "because"})
    assert bad_reason.status_code == 422

    operator_without_note = api.post(
        url, headers=headers, json={**valid, "grant_reason": "operator_comp"}
    )
    assert operator_without_note.status_code == 422

    missing_client = api.post(
        f"/v1/admin/clients/cli_missing_{uuid.uuid4().hex[:8]}/grant-access",
        headers=headers,
        json=valid,
    )
    assert missing_client.status_code == 404

    monkeypatch.setattr(main, "ADMIN_MFA_SECRET", "!!!")
    bad_secret = api.post(url, headers=headers, json=valid)
    assert bad_secret.status_code == 401

    monkeypatch.setattr(main, "ADMIN_MFA_SECRET", "")
    monkeypatch.setattr(main, "APP_ENV", "production")
    no_mfa_config = api.post(
        url,
        headers={"X-AgentGrid-Admin-Key": "test-admin-key"},
        json=valid,
    )
    assert no_mfa_config.status_code == 503


def test_immutable_tables_reject_direct_update_and_delete(api):
    client = _register(api)
    from_private, from_agent = _create_agent_with_key(api, client["api_key"], "From")
    _, to_agent = _create_agent_with_key(api, client["api_key"], "To")
    handoff_body = _handoff_body(from_private, from_agent["agent_id"], to_agent["agent_id"])
    assert api.post(
        f"/v1/agents/{from_agent['agent_id']}/handoffs",
        headers=_headers(client["api_key"]),
        json=handoff_body,
    ).status_code == 201

    grant = api.post(
        f"/v1/admin/clients/{client['client_id']}/grant-access",
        headers={"X-AgentGrid-Admin-Key": "test-admin-key", "X-AgentGrid-Admin-MFA": _totp()},
        json={
            "tier": "plus",
            "cashfree_order_id": "order_immutable_" + uuid.uuid4().hex,
            "cashfree_payment_id": "pay_immutable_" + uuid.uuid4().hex,
        },
    )
    assert grant.status_code == 200

    cases = [
        (
            "UPDATE agents SET name = 'tampered' WHERE agent_id = :id",
            {"id": from_agent["agent_id"]},
        ),
        ("DELETE FROM agents WHERE agent_id = :id", {"id": from_agent["agent_id"]}),
        (
            "UPDATE handoffs SET task_hash = :hash WHERE handoff_id = :id",
            {"hash": "0" * 64, "id": handoff_body["handoff_id"]},
        ),
        ("DELETE FROM handoffs WHERE handoff_id = :id", {"id": handoff_body["handoff_id"]}),
        (
            "UPDATE audit_events SET action = 'tampered' WHERE client_id = :id",
            {"id": client["client_id"]},
        ),
        ("DELETE FROM audit_events WHERE client_id = :id", {"id": client["client_id"]}),
        (
            "UPDATE billing_history SET tier = 'free' WHERE client_id = :id",
            {"id": client["client_id"]},
        ),
        ("DELETE FROM billing_history WHERE client_id = :id", {"id": client["client_id"]}),
        (
            "UPDATE overage_ledger SET units = 99 WHERE client_id = :id",
            {"id": client["client_id"]},
        ),
        ("DELETE FROM overage_ledger WHERE client_id = :id", {"id": client["client_id"]}),
    ]

    client_row = _sqlite_rows(
        "SELECT cycle_start, cycle_end FROM clients WHERE client_id = ?",
        (client["client_id"],),
    )[0]
    ledger_connection = sqlite3.connect(TEST_DB_PATH)
    try:
        ledger_connection.execute(
            "INSERT INTO overage_ledger "
            "(client_id, cycle_start, cycle_end, usage_type, units, unit_price_microdollars, "
            "tier, reference_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                client["client_id"],
                client_row["cycle_start"],
                client_row["cycle_end"],
                "handoff",
                1,
                main.OVERAGE_HANDOFF_MICRODOLLARS,
                "free",
                "h_ledger_immutable_test",
                main._now_iso(),
            ),
        )
        ledger_connection.commit()
    finally:
        ledger_connection.close()

    for sql, params in cases:
        assert _sqlite_blocked(sql, params), sql

    connection = sqlite3.connect(TEST_DB_PATH)
    try:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'").fetchall()
    finally:
        connection.close()
    trigger_names = {row[0] for row in rows}
    for table in main.IMMUTABLE_TABLES:
        assert f"ag_{table}_no_update" in trigger_names
        assert f"ag_{table}_no_delete" in trigger_names


def test_signing_key_rotation_accepts_previous_key(api, monkeypatch):
    previous = Ed25519PrivateKey.generate()
    monkeypatch.setattr(main, "PREVIOUS_PLATFORM_PRIVATE", previous)
    monkeypatch.setattr(main, "PLATFORM_VERIFICATION_KEYS", [main.PLATFORM_PRIVATE, previous])

    payload = {"v": 1, "purpose": "rotation-test"}
    previous_signature = _b64e(previous.sign(main.canonical_bytes(payload)))
    assert main.verify_platform(payload, previous_signature) is True

    unrelated_private, _ = _new_agent_key()
    unrelated_signature = _b64e(unrelated_private.sign(main.canonical_bytes(payload)))
    assert main.verify_platform(payload, unrelated_signature) is False

    public = api.get("/v1/agents/public-key")
    assert public.json()["previous_public_key"] == main._public_b64(previous)


def test_audit_metadata_is_sanitized():
    cleaned = main._safe_audit_metadata(
        {
            "api_key": "agk_secret",
            "access-token": "secret",
            "nested": {"password": "secret"},
            "safe_field": "ok",
        }
    )
    assert cleaned == {"safe_field": "ok"}


def test_body_size_limit_rate_limit_and_security_headers(api, monkeypatch):
    response = api.get("/v1/agents/public-key")
    expected_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }
    for name, value in expected_headers.items():
        assert response.headers[name] == value
    assert "script-src 'none'" in response.headers["Content-Security-Policy"]

    oversized = api.post(
        "/v1/clients/register",
        content=b"x" * (main.MAX_BODY_BYTES + 1),
    )
    assert oversized.status_code == 413
    assert oversized.headers["X-Content-Type-Options"] == "nosniff"

    monkeypatch.setattr(main, "_rate_bucket", {})
    monkeypatch.setattr(main, "RATE_LIMIT_PER_MIN", 1)
    limited_headers = {"X-AgentGrid-API-Key": "agk_rate_" + uuid.uuid4().hex}
    assert api.get("/v1/agents/public-key", headers=limited_headers).status_code == 200
    limited = api.get("/v1/agents/public-key", headers=limited_headers)
    assert limited.status_code == 429
    assert limited.headers["X-Frame-Options"] == "DENY"


def test_migration_script_creates_schema(tmp_path):
    db_path = tmp_path / "migration_test.db"
    env = os.environ.copy()
    env["AGENTGRID_DATABASE_URL"] = "sqlite+aiosqlite:///" + db_path.as_posix()
    env["AGENTGRID_SKIP_SCHEMA_ON_STARTUP"] = "1"
    project_root = Path(main.__file__).resolve().parent

    result = subprocess.run(
        [sys.executable, "migrate.py"],
        cwd=project_root,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert db_path.exists()

    with sqlite3.connect(db_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert "agents" in tables
    assert "rate_limit_counters" in tables


def test_skip_schema_on_startup_flag(tmp_path):
    db_path = tmp_path / "skip_schema_test.db"
    env = os.environ.copy()
    env["AGENTGRID_DATABASE_URL"] = "sqlite+aiosqlite:///" + db_path.as_posix()
    env["AGENTGRID_SKIP_SCHEMA_ON_STARTUP"] = "1"
    script = """
from fastapi.testclient import TestClient
import main
with TestClient(main.app) as client:
    print(client.get('/health/live').status_code)
"""

    result = subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        cwd=Path(main.__file__).resolve().parent,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "200" in result.stdout
    assert not db_path.exists()


def test_rate_limit_uses_shared_counter_for_postgres(monkeypatch):
    calls: list[str] = []

    async def fake_shared(bucket_key: str) -> bool:
        calls.append(bucket_key)
        return False

    monkeypatch.setattr(
        main, "DATABASE_URL", "postgresql+asyncpg://user:pass@localhost/db"
    )
    monkeypatch.setattr(main, "_consume_shared_rate_limit", fake_shared)

    assert asyncio.run(main._consume_rate_limit("bucket")) is False
    assert calls == ["bucket"]


def test_lambda_handler_is_callable():
    # The public repo is the Vercel-only source; the AWS Lambda adapter is not
    # shipped here. Skip instead of failing when that file is absent.
    if not (Path(__file__).resolve().parents[1] / "lambda_handler.py").exists():
        pytest.skip("lambda_handler.py is not part of the public Vercel-only repo")
    import lambda_handler

    assert callable(lambda_handler.handler)


def test_admin_status_shows_access_and_billing_events(api):
    client = _register(api)
    headers = {"X-AgentGrid-Admin-Key": "test-admin-key", "X-AgentGrid-Admin-MFA": _totp()}
    order = "order_status_" + uuid.uuid4().hex
    grant = api.post(
        f"/v1/admin/clients/{client['client_id']}/grant-access",
        headers=headers,
        json={
            "tier": "plus",
            "cashfree_order_id": order,
            "cashfree_payment_id": "pay_status_" + uuid.uuid4().hex,
        },
    )
    assert grant.status_code == 200, grant.text

    response = api.get(f"/v1/admin/clients/{client['client_id']}/status", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["client_id"] == client["client_id"]
    assert body["tier"] == "plus"
    assert body["access_active"] is True
    assert body["payment_status"] == "current"
    assert body["amount_due_usd"] == "20"
    assert body["usage"]["hard_caps"] == {"agents": 300, "handoffs": 30000}
    assert any(event["cashfree_order_id"] == order for event in body["recent_billing_events"])


def test_admin_status_requires_mfa_and_404s_for_unknown(api):
    client = _register(api)
    no_mfa = api.get(
        f"/v1/admin/clients/{client['client_id']}/status",
        headers={"X-AgentGrid-Admin-Key": "test-admin-key"},
    )
    assert no_mfa.status_code == 401

    headers = {"X-AgentGrid-Admin-Key": "test-admin-key", "X-AgentGrid-Admin-MFA": _totp()}
    missing = api.get(
        "/v1/admin/clients/cli_missing_" + uuid.uuid4().hex[:8] + "/status",
        headers=headers,
    )
    assert missing.status_code == 404


def test_admin_list_clients_returns_overview(api):
    client = _register(api)
    headers = {"X-AgentGrid-Admin-Key": "test-admin-key", "X-AgentGrid-Admin-MFA": _totp()}
    response = api.get("/v1/admin/clients?limit=5", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["count"] >= 1
    row = next(item for item in body["clients"] if item["client_id"] == client["client_id"])
    assert row["tier"] == "free"
    assert row["payment_status"] == "current"
    assert row["invoice_id"].startswith("inv_")
    assert row["email_verified"] is True
    assert row["disposable_email"] is False
    assert row["email"].endswith("@example.test")
    assert "***@" in row["email"]
    assert row["agent_count"] == 0
    assert row["handoff_count"] == 0
    assert row["last_activity_at"] is None
    assert row["is_test_account"] is False
    assert row["signal"] == "verified_inactive"


def test_ops_live_page_and_read_only_session(api):
    page = api.get("/ops")
    assert page.status_code == 200, page.text
    assert "Live operator console" in page.text
    assert "TheoC Computations" in page.text
    assert "Signup authenticity signals" in page.text
    assert "auto-refresh" in page.text
    assert "Include operator/test accounts" in page.text
    assert "state.includeTests || !c.is_test_account" in page.text

    assert api.get("/v1/admin/stats").status_code == 401
    denied = api.post(
        "/v1/admin/session", json={"admin_key": "wrong", "mfa": _totp()}
    )
    assert denied.status_code == 401

    login = api.post(
        "/v1/admin/session",
        json={"admin_key": "test-admin-key", "mfa": _totp()},
    )
    assert login.status_code == 200, login.text
    assert login.json()["scope"] == "ops:read"
    assert api.get("/v1/admin/stats").status_code == 200
    assert api.get("/v1/admin/clients?limit=1").status_code == 200

    mutation = api.post(
        "/v1/admin/clients/cli_missing/grant-access",
        json={
            "tier": "plus",
            "cashfree_order_id": "ord_ops_test",
            "cashfree_payment_id": "pay_ops_test",
        },
    )
    assert mutation.status_code == 401

    assert api.post("/v1/admin/session/logout").status_code == 200
    assert api.get("/v1/admin/stats").status_code == 401


def test_admin_flags_disposable_email_without_blocking_signup(api):
    registered = _register(api, email=f"bot{uuid.uuid4().hex[:6]}@mailinator.com")
    headers = {"X-AgentGrid-Admin-Key": "test-admin-key", "X-AgentGrid-Admin-MFA": _totp()}
    response = api.get("/v1/admin/clients?limit=5", headers=headers)
    assert response.status_code == 200, response.text
    row = next(
        item for item in response.json()["clients"]
        if item["client_id"] == registered["client_id"]
    )
    assert row["email_verified"] is True
    assert row["disposable_email"] is True
    assert row["signal"] == "disposable_email"


def test_guide_has_three_step_quickstart_recipes_and_faq(api):
    guide = api.get("/guide").text
    assert "Start here: 3 steps" in guide
    for marker in (
        "agrid register",
        "agrid verify",
        "agrid resend",
        "agrid quickstart",
        "agrid card",
        "agrid receipts",
        "Copy-paste recipes",
        "offline-verify",
        "scoped-handoff",
        "receipt-read",
        "scope-design",
        "receipt-design",
        "How scoped delegation works",
        "What a receipt records",
        "FAQ",
        "invite token",
    ):
        assert marker in guide, marker
    description = api.get("/openapi.json").json()["info"]["description"]
    assert "agrid quickstart" in description
    assert "developer guide" in description


def test_verification_and_welcome_emails_via_webhook(api, monkeypatch):
    import welcome_email

    captured: list[tuple] = []
    monkeypatch.setenv(welcome_email.WEBHOOK_URL_ENV, "https://example.test/hook")
    monkeypatch.setenv(welcome_email.WEBHOOK_TOKEN_ENV, "webhook-token")
    monkeypatch.setattr(
        welcome_email,
        "_poster",
        lambda url, payload, token: captured.append((url, payload, token)),
    )

    cid = "welcome_" + uuid.uuid4().hex[:10]
    registered = api.post(
        "/v1/clients/register", json={"client_id": cid, "email": "New.User@Example.com"}
    )
    assert registered.status_code == 201, registered.text
    assert len(captured) == 1
    url, verify_payload, token = captured[0]
    assert url == "https://example.test/hook"
    assert token == "webhook-token"
    assert verify_payload["type"] == "agentgrid.verify"
    assert "verification code" in verify_payload["subject"]
    assert registered.json()["verification_code"] in verify_payload["text"]
    assert "TheoC Computations, AgentGrid" in verify_payload["text"]
    assert "TheoC Computations, AgentGrid" in verify_payload["html"]

    captured.clear()
    response = api.post(
        "/v1/clients/verify-email",
        json={"client_id": cid, "code": registered.json()["verification_code"]},
    )
    assert response.status_code == 200, response.text
    assert len(captured) == 1

    url, payload, token = captured[0]
    assert url == "https://example.test/hook"
    assert token == "webhook-token"
    assert payload["to"] == "new.user@example.com"
    assert payload["client_id"] == cid
    assert payload["type"] == "agentgrid.welcome"
    assert "3 steps" in payload["subject"]
    for step in ("agrid quickstart", "agrid card", "agrid receipts"):
        assert step in payload["text"]
        assert step in payload["html"]
    assert "TheoC Computations, AgentGrid" in payload["text"]
    assert "TheoC Computations, AgentGrid" in payload["html"]
    api_key = response.json()["api_key"]
    assert api_key not in payload["text"]
    assert api_key not in payload["html"]


def test_email_failure_never_breaks_registration_or_verification(api, monkeypatch):
    import welcome_email

    monkeypatch.setenv(welcome_email.WEBHOOK_URL_ENV, "https://example.test/hook")
    monkeypatch.delenv(welcome_email.WEBHOOK_TOKEN_ENV, raising=False)

    def boom(url, payload, token):
        raise RuntimeError("webhook down")

    monkeypatch.setattr(welcome_email, "_poster", boom)
    cid = "welcome_" + uuid.uuid4().hex[:10]
    registered = api.post(
        "/v1/clients/register", json={"client_id": cid, "email": "down@example.com"}
    )
    assert registered.status_code == 201, registered.text
    verified = api.post(
        "/v1/clients/verify-email",
        json={"client_id": cid, "code": registered.json()["verification_code"]},
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["client_id"] == cid
    assert verified.json()["api_key"].startswith("agk_")


def test_emails_disabled_without_provider(api, monkeypatch):
    import welcome_email

    monkeypatch.delenv(welcome_email.WEBHOOK_URL_ENV, raising=False)
    monkeypatch.delenv(welcome_email.RESEND_KEY_ENV, raising=False)
    monkeypatch.delenv(welcome_email.SMTP_HOST_ENV, raising=False)
    captured: list[tuple] = []
    monkeypatch.setattr(welcome_email, "_poster", lambda *args: captured.append(args))
    cid = "nowelcome_" + uuid.uuid4().hex[:10]
    registered = api.post(
        "/v1/clients/register", json={"client_id": cid, "email": "quiet@example.com"}
    )
    assert registered.status_code == 201, registered.text
    verified = api.post(
        "/v1/clients/verify-email",
        json={"client_id": cid, "code": registered.json()["verification_code"]},
    )
    assert verified.status_code == 200, verified.text
    assert captured == []


def test_verification_and_welcome_use_resend_when_configured(api, monkeypatch):
    import welcome_email

    monkeypatch.delenv(welcome_email.WEBHOOK_URL_ENV, raising=False)
    monkeypatch.setenv(welcome_email.RESEND_KEY_ENV, "re_test_key")
    monkeypatch.setenv(welcome_email.FROM_ENV, "AgentGrid <hello@example.com>")
    captured: list[tuple] = []
    monkeypatch.setattr(
        welcome_email,
        "_resend_send",
        lambda payload, key: captured.append((payload, key)),
    )

    cid = "resend_" + uuid.uuid4().hex[:10]
    registered = api.post(
        "/v1/clients/register", json={"client_id": cid, "email": "Buyer@Example.com"}
    )
    assert registered.status_code == 201, registered.text
    assert len(captured) == 1
    verify_payload, key = captured[0]
    assert key == "re_test_key"
    assert verify_payload["subject"].startswith("Your AgentGrid verification code")

    captured.clear()
    response = api.post(
        "/v1/clients/verify-email",
        json={"client_id": cid, "code": registered.json()["verification_code"]},
    )
    assert response.status_code == 200, response.text
    assert len(captured) == 1
    payload, key = captured[0]
    assert key == "re_test_key"
    assert payload["from"] == "AgentGrid <hello@example.com>"
    assert payload["to"] == ["buyer@example.com"]
    assert "3 steps" in payload["subject"]
    assert response.json()["api_key"] not in payload["text"]
    assert response.json()["api_key"] not in payload["html"]


def test_verification_and_welcome_use_smtp_when_configured(api, monkeypatch):
    import welcome_email

    monkeypatch.delenv(welcome_email.WEBHOOK_URL_ENV, raising=False)
    monkeypatch.delenv(welcome_email.RESEND_KEY_ENV, raising=False)
    monkeypatch.setenv(welcome_email.SMTP_HOST_ENV, "smtp.example.com")
    monkeypatch.setenv(welcome_email.SMTP_PORT_ENV, "465")
    monkeypatch.setenv(welcome_email.SMTP_USER_ENV, "sender@example.com")
    monkeypatch.setenv(welcome_email.SMTP_PASSWORD_ENV, "not-a-real-password")
    monkeypatch.setenv(welcome_email.FROM_ENV, "AgentGrid <sender@example.com>")
    captured: list[tuple] = []
    monkeypatch.setattr(welcome_email, "_smtp_send", lambda *args: captured.append(args))

    cid = "smtp_" + uuid.uuid4().hex[:10]
    registered = api.post(
        "/v1/clients/register", json={"client_id": cid, "email": "SMTP.User@Example.com"}
    )
    assert registered.status_code == 201, registered.text
    assert len(captured) == 1
    assert captured[0][0]["Subject"].startswith("Your AgentGrid verification code")

    captured.clear()
    response = api.post(
        "/v1/clients/verify-email",
        json={"client_id": cid, "code": registered.json()["verification_code"]},
    )
    assert response.status_code == 200, response.text
    assert len(captured) == 1
    mail, host, port, user, password = captured[0]
    assert mail["To"] == "smtp.user@example.com"
    assert "3 steps" in mail["Subject"]
    assert (host, port, user, password) == (
        "smtp.example.com",
        465,
        "sender@example.com",
        "not-a-real-password",
    )
