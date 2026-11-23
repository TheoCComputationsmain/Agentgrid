"""Offline unit tests for the SDK using an injected fake transport."""
from __future__ import annotations

import json

import pytest

from agentgrid_protocol import (
    AgentGrid,
    AgentGridError,
    canonical,
    load_api_key,
    save_api_key,
    unsigned_card,
)
from agentgrid_protocol import cli
from agentgrid_protocol.crypto import AgentKey, b64d, b64e
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def fake_client():
    """Return (client, captured calls) with a realistic in-memory API."""
    calls: list[dict] = []
    cards: dict[str, dict] = {}
    receipts: dict[str, list[dict]] = {}
    platform = AgentKey.generate()

    def transport(method, path, body, headers):
        calls.append({"method": method, "path": path, "body": body, "headers": headers})
        if method == "POST" and path == "/v1/clients/register":
            return 201, {
                "client_id": "cli_fake123",
                "verification_required": True,
                "tier": "free",
            }
        if method == "POST" and path == "/v1/clients/verify-email":
            return 200, {
                "client_id": body["client_id"],
                "email_verified": True,
                "api_key": "agk_fake_key",
                "tier": "free",
            }
        if method == "POST" and path == "/v1/clients/resend-verification":
            return 200, {"client_id": body["client_id"], "verification_required": True}
        if method == "POST" and path == "/v1/clients/me/upgrade-email":
            return 200, {
                "client_id": "cli_test",
                "email": body["email"].strip().lower(),
                "verification_required": True,
                "legacy_upgrade": True,
            }
        if path == "/health/ready":
            return 200, {"status": "ready", "database": "connected"}
        if path == "/v1/clients/me":
            return 200, {"client_id": "cli_test", "tier": "free", "cycle_start": "2026-11-19"}
        if path == "/v1/agents/public-key":
            return 200, {"public_key": platform.public_b64, "algorithm": "Ed25519"}
        if method == "POST" and path == "/v1/agents":
            agent_id = "ag_" + str(len(cards) + 1).zfill(32)
            card = {
                "v": 1,
                "agent_id": agent_id,
                "name": body["name"],
                "description": body.get("description", ""),
                "capabilities": body["capabilities"],
                "endpoint": "",
                "public_key": body["public_key"],
                "status": "ACTIVE",
                "issued_at": "2026-11-19T00:00:00Z",
            }
            message = canonical(card)
            card["signature"] = b64e(platform.private.sign(message))
            cards[agent_id] = card
            receipts[agent_id] = []
            return 201, {**card, "overage": False}
        if path.endswith(".json"):
            agent_id = path.split("/")[-1].split(".")[0]
            return 200, cards[agent_id]
        if path.endswith("/verify"):
            agent_id = path.split("/")[-2]
            return 200, {"agent_id": agent_id, "signature_valid": True, "status": "ACTIVE"}
        if method == "POST" and path.endswith("/handoffs"):
            from_id = path.split("/")[-2]
            receipt = {"handoff_id": body["handoff_id"], "from_agent_id": from_id}
            receipts[body["to_agent_id"]].append(receipt)
            return 201, receipt
        if path.endswith("/receipts"):
            agent_id = path.split("/")[-2]
            return 200, {"receipts": receipts[agent_id]}
        if path.startswith("/v1/billing/statement"):
            return 200, {"invoice_id": "inv_test", "total_due_usd": "0"}
        raise AssertionError("unexpected request: " + method + " " + path)

    client = AgentGrid(api_key="agk_test_key", transport=transport)
    return client, calls


def test_quickstart_signs_real_payload_without_sending_private_key():
    client, calls = fake_client()
    result = client.quickstart()

    assert result["verification"]["online"] is True
    assert result["verification"]["offline"] is True
    assert result["receipt"]["handoff_id"].startswith("h_")
    assert result["receipt_count"] == 1

    creates = [c for c in calls if c["path"] == "/v1/agents" and c["method"] == "POST"]
    assert len(creates) == 2
    for create in creates:
        assert "public_key" in create["body"]
        assert "private" not in json.dumps(create["body"]).lower()

    handoff = next(c for c in calls if c["path"].endswith("/handoffs"))
    payload = {k: v for k, v in handoff["body"].items() if k != "signature"}
    signature = handoff["body"]["signature"]
    from_public = next(c["body"]["public_key"] for c in creates if c["body"]["name"] == "Planner")
    Ed25519PublicKey.from_public_bytes(b64d(from_public)).verify(
        b64d(signature), canonical(payload)
    )


def test_api_key_sent_and_http_errors_raise_typed_error():
    def transport(method, path, body, headers):
        assert headers["X-AgentGrid-API-Key"] == "agk_test_key"
        return 422, {"detail": "bad scope"}

    client = AgentGrid(api_key="agk_test_key", transport=transport)
    with pytest.raises(AgentGridError) as exc:
        client.me()
    assert exc.value.status == 422
    assert "bad scope" in exc.value.detail


def test_missing_key_reports_actionable_error():
    client = AgentGrid(api_key=None, transport=lambda *a: (200, {}))
    with pytest.raises(AgentGridError) as exc:
        client.me()
    assert "agrid register" in exc.value.detail


def test_key_file_round_trip(tmp_path, monkeypatch):
    path = tmp_path / "creds.json"
    monkeypatch.delenv("AGENTGRID_API_KEY", raising=False)
    save_api_key("agk_example", path)
    assert load_api_key(path) == "agk_example"
    assert "agk_example" in path.read_text()
    monkeypatch.setenv("AGENTGRID_API_KEY", "agk_from_env")
    assert load_api_key(path) == "agk_from_env"


def test_unsigned_card_drops_response_metadata():
    card = {
        "agent_id": "ag_1",
        "signature": "abc",
        "verify_url": "/v1/agents/ag_1/verify",
        "overage": False,
    }
    assert unsigned_card(card) == {"agent_id": "ag_1"}


def test_register_then_verify_issues_key():
    calls: list[dict] = []

    def transport(method, path, body, headers):
        calls.append({"method": method, "path": path, "body": body, "headers": headers})
        if path == "/v1/clients/register":
            return 201, {
                "client_id": "cli_new",
                "verification_required": True,
                "tier": "free",
            }
        return 200, {"client_id": "cli_new", "api_key": "agk_new_key", "tier": "free"}

    client = AgentGrid(api_key=None, transport=transport)
    registered = client.register(email="me@example.com")
    assert registered["client_id"] == "cli_new"
    assert "api_key" not in registered
    assert client.api_key is None

    verified = client.verify_email("cli_new", "123456")
    assert verified["api_key"] == "agk_new_key"
    assert client.api_key == "agk_new_key"

    assert calls[0]["path"] == "/v1/clients/register"
    assert calls[0]["body"] == {"email": "me@example.com"}
    assert "X-AgentGrid-API-Key" not in calls[0]["headers"]
    assert calls[1]["path"] == "/v1/clients/verify-email"
    assert calls[1]["body"] == {"client_id": "cli_new", "code": "123456"}
    assert "X-AgentGrid-API-Key" not in calls[1]["headers"]


def test_register_requires_email_and_verify_validates_code():
    client = AgentGrid(api_key=None, transport=lambda *a: (201, {}))
    with pytest.raises(AgentGridError) as exc:
        client.register(email="   ")
    assert "real email is required" in str(exc.value)

    with pytest.raises(AgentGridError) as exc:
        client.verify_email("cli_new", "12ab")
    assert "6-digit code" in str(exc.value)


def test_cli_register_prints_verify_step_and_stores_no_key(monkeypatch, capsys):
    saved: dict[str, str] = {}
    pending: dict[str, str] = {}

    class Fake:
        base_url = "https://agentgrid-pied.vercel.app"

        def register(self, *, email, client_id=""):
            assert email == "me@example.com"
            return {
                "client_id": "cli_cli123",
                "verification_required": True,
                "tier": "free",
            }

    monkeypatch.setattr(cli, "AgentGrid", lambda **kwargs: Fake())
    def fake_save(key):
        saved["key"] = key
        return "creds.json"

    monkeypatch.setattr(cli, "save_api_key", fake_save)
    monkeypatch.setattr(
        cli,
        "save_pending_client",
        lambda client_id: pending.setdefault("client_id", client_id) or "pending.json",
    )

    assert cli.main(["register", "--email", "me@example.com"]) == 0
    output = capsys.readouterr().out
    assert "cli_cli123" in output
    assert pending["client_id"] == "cli_cli123"
    assert saved == {}
    assert "No API key exists yet" in output
    assert "agrid verify" in output
    assert "Verification runs your first signed handoff automatically" in output
    assert "agrid resend" in output
    assert "/guide" in output
    assert "/docs" in output


def test_client_upgrade_email_posts_with_existing_key():
    client, calls = fake_client()
    with pytest.raises(AgentGridError) as exc:
        client.upgrade_email("   ")
    assert "real email is required" in str(exc.value)

    result = client.upgrade_email(" Legacy@Example.Test ")
    assert result["legacy_upgrade"] is True
    assert result["email"] == "legacy@example.test"
    call = calls[-1]
    assert call["method"] == "POST"
    assert call["path"] == "/v1/clients/me/upgrade-email"
    assert call["headers"]["X-AgentGrid-API-Key"] == "agk_test_key"


def test_cli_update_starts_legacy_upgrade_and_saves_pending_id(monkeypatch, capsys):
    client, calls = fake_client()
    pending: dict[str, str] = {}

    monkeypatch.setattr(cli, "load_api_key", lambda: "agk_legacy")
    monkeypatch.setattr(cli, "AgentGrid", lambda **kwargs: client)
    monkeypatch.setattr(
        cli,
        "save_pending_client",
        lambda client_id: pending.setdefault("client_id", client_id) or "pending.json",
    )

    assert cli.main(["update", "--email", "Legacy@Example.Test"]) == 0
    output = capsys.readouterr().out
    call = next(c for c in calls if c["path"] == "/v1/clients/me/upgrade-email")
    assert call["body"]["email"] == "Legacy@Example.Test"
    assert pending["client_id"] == "cli_test"
    assert "Legacy account update started" in output
    assert "agrid verify <code>" in output
    assert "stops working until you verify" in output
    assert "agk_" not in output


def test_cli_verify_saves_key_and_clears_pending(monkeypatch, capsys):
    saved: dict[str, str] = {}
    cleared: list[bool] = []

    class Obj:
        def __init__(self, agent_id):
            self.agent_id = agent_id
            self.card_url = "https://agentgrid-pied.vercel.app/a/" + agent_id

    class Fake:
        base_url = "https://agentgrid-pied.vercel.app"

        def verify_email(self, client_id, code):
            assert client_id == "cli_cli123"
            assert code == "123456"
            return {"api_key": "agk_verified_secret", "tier": "free"}

        def quickstart(self):
            return {
                "from_agent": Obj("ag_planner"),
                "to_agent": Obj("ag_worker"),
                "verification": {"online": True, "offline": True},
                "receipt": {"handoff_id": "h_verify_test"},
                "receipt_count": 1,
            }

    monkeypatch.setattr(cli, "AgentGrid", lambda **kwargs: Fake())
    monkeypatch.setattr(cli, "load_pending_client", lambda: "cli_cli123")
    def fake_save(key):
        saved["key"] = key
        return "creds.json"

    monkeypatch.setattr(cli, "save_api_key", fake_save)
    monkeypatch.setattr(cli, "clear_pending_client", lambda: cleared.append(True))

    assert cli.main(["verify", "123456"]) == 0
    output = capsys.readouterr().out
    assert saved["key"] == "agk_verified_secret"
    assert "agk_verified_secret" not in output
    assert cleared == [True]
    assert "Email verified" in output
    assert "Running your first signed handoff now" in output
    assert "h_verify_test" in output
    assert "ag_planner -> ag_worker" in output
    assert "agrid receipts ag_worker" in output
    assert "agk_verified_secret" not in output


def test_cli_verify_no_quickstart_keeps_manual_next_steps(monkeypatch, capsys):
    class Fake:
        base_url = "https://agentgrid-pied.vercel.app"

        def verify_email(self, client_id, code):
            return {"api_key": "agk_manual", "tier": "free"}

        def quickstart(self):
            raise AssertionError("quickstart must not run with --no-quickstart")

    monkeypatch.setattr(cli, "AgentGrid", lambda **kwargs: Fake())
    monkeypatch.setattr(cli, "load_pending_client", lambda: "cli_cli123")
    monkeypatch.setattr(cli, "save_api_key", lambda key: "creds.json")
    monkeypatch.setattr(cli, "clear_pending_client", lambda: None)

    assert cli.main(["verify", "123456", "--no-quickstart"]) == 0
    output = capsys.readouterr().out
    assert "three steps to your first signed handoff" in output
    assert "agrid quickstart" in output


def test_cli_resend_uses_pending_client(monkeypatch, capsys):
    called: list[str] = []

    class Fake:
        base_url = "https://agentgrid-pied.vercel.app"

        def resend_verification(self, client_id):
            called.append(client_id)
            return {"client_id": client_id, "verification_required": True}

    monkeypatch.setattr(cli, "AgentGrid", lambda **kwargs: Fake())
    monkeypatch.setattr(cli, "load_pending_client", lambda: "cli_cli123")

    assert cli.main(["resend"]) == 0
    assert called == ["cli_cli123"]
    assert "fresh 6-digit code" in capsys.readouterr().out


def test_cli_quickstart_prints_success(monkeypatch, capsys):
    fake, _ = fake_client()
    monkeypatch.setenv("AGENTGRID_API_KEY", "agk_test_key")
    monkeypatch.setattr(cli, "AgentGrid", lambda **kwargs: fake)
    assert cli.main(["quickstart"]) == 0
    output = capsys.readouterr().out
    assert "Registered agents" in output
    assert "Signed handoff accepted" in output
    assert "agk_test_key" not in output


def test_cli_receipts_prints_receipt_details(monkeypatch, capsys):
    class Fake:
        base_url = "https://agentgrid-pied.vercel.app"

        def receipts(self, agent_id):
            assert agent_id == "ag_worker"
            return {
                "agent_id": agent_id,
                "count": 1,
                "receipts": [
                    {
                        "handoff_id": "h_abc",
                        "from_agent_id": "ag_planner",
                        "to_agent_id": "ag_worker",
                        "task_hash": "a" * 64,
                        "scope": {"allowed": ["read"], "max_actions": 2},
                        "created_at": "2026-11-23T00:00:00Z",
                    }
                ],
            }

    monkeypatch.setenv("AGENTGRID_API_KEY", "agk_test_key")
    monkeypatch.setattr(cli, "AgentGrid", lambda **kwargs: Fake())
    assert cli.main(["receipts", "ag_worker"]) == 0
    output = capsys.readouterr().out
    assert "h_abc" in output
    assert "ag_planner -> ag_worker" in output
    assert "a" * 64 in output
    assert '"allowed": ["read"]' in output
    assert "agk_test_key" not in output
