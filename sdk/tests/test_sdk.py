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
                "api_key": "agk_fake_key",
                "tier": "free",
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
    assert "agentgrid register" in exc.value.detail


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


def test_register_uses_open_endpoint_and_stores_key():
    calls: list[dict] = []

    def transport(method, path, body, headers):
        calls.append({"method": method, "path": path, "body": body, "headers": headers})
        return 201, {"client_id": "cli_new", "api_key": "agk_new_key", "tier": "free"}

    client = AgentGrid(api_key=None, transport=transport)
    result = client.register(email="me@example.com")

    assert result["client_id"] == "cli_new"
    assert client.api_key == "agk_new_key"
    assert calls[0]["path"] == "/v1/clients/register"
    assert calls[0]["body"] == {"email": "me@example.com"}
    assert "X-AgentGrid-API-Key" not in calls[0]["headers"]


def test_cli_register_stores_key_without_printing(monkeypatch, capsys):
    saved: dict[str, str] = {}

    class Fake:
        base_url = "https://agentgrid-pied.vercel.app"

        def register(self, *, email="", client_id=""):
            assert email == "me@example.com"
            return {
                "client_id": "cli_cli123",
                "api_key": "agk_secret_from_register",
                "tier": "free",
            }

    def fake_save(key):
        saved["key"] = key
        return "creds.json"

    monkeypatch.setattr(cli, "AgentGrid", lambda **kwargs: Fake())
    monkeypatch.setattr(cli, "save_api_key", fake_save)

    assert cli.main(["register", "--email", "me@example.com"]) == 0
    output = capsys.readouterr().out
    assert "cli_cli123" in output
    assert "agk_secret_from_register" not in output
    assert saved["key"] == "agk_secret_from_register"


def test_cli_quickstart_prints_success(monkeypatch, capsys):
    fake, _ = fake_client()
    monkeypatch.setenv("AGENTGRID_API_KEY", "agk_test_key")
    monkeypatch.setattr(cli, "AgentGrid", lambda **kwargs: fake)
    assert cli.main(["quickstart"]) == 0
    output = capsys.readouterr().out
    assert "Registered agents" in output
    assert "Signed handoff accepted" in output
    assert "agk_test_key" not in output
