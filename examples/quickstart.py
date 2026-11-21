"""Your first verified agent handoff on AgentGrid.

This script:
  1. Registers two agents with their own Ed25519 public keys.
  2. Verifies a signed Agent Card online and offline.
  3. Signs a handoff from one agent to the other.
  4. Reads the immutable receipt.

Setup:
  pip install -r requirements-local.txt
  set AGENTGRID_API_KEY=agk_...        (ask the operator for one)
  set AGENTGRID_BASE_URL=https://agentgrid-pied.vercel.app
  python examples/quickstart.py

The API key is read from the environment and never printed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

BASE = os.environ.get("AGENTGRID_BASE_URL", "https://agentgrid-pied.vercel.app").rstrip("/")
API_KEY = os.environ.get("AGENTGRID_API_KEY", "")


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical(payload: dict) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def call(method: str, path: str, body: dict | None = None, auth: bool = True) -> dict:
    headers = {"Content-Type": "application/json"}
    if auth:
        if not API_KEY:
            raise RuntimeError("Set AGENTGRID_API_KEY before running this example.")
        headers["X-AgentGrid-API-Key"] = API_KEY
    req = Request(
        BASE + path,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        method=method,
        headers=headers,
    )
    try:
        with urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {path} -> HTTP {exc.code}: {detail}") from exc


def new_agent_key() -> tuple[Ed25519PrivateKey, str]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, b64e(public)


def main() -> int:
    print("AgentGrid quickstart -> " + BASE + "\n")

    # 1. Two agents, each with its own key pair.
    from_private, from_public = new_agent_key()
    to_private, to_public = new_agent_key()

    a = call("POST", "/v1/agents", {
        "name": "Planner",
        "description": "Breaks work into tasks",
        "capabilities": ["plan"],
        "public_key": from_public,
    })
    b = call("POST", "/v1/agents", {
        "name": "Worker",
        "description": "Executes approved tasks",
        "capabilities": ["read"],
        "public_key": to_public,
    })
    print(f"1. Registered agents: {a['agent_id']} -> {b['agent_id']}")

    # 2. Verify the signed card, both online and offline.
    card = call("GET", f"/v1/agents/{a['agent_id']}.json", auth=False)
    verify = call("GET", f"/v1/agents/{a['agent_id']}/verify", auth=False)
    platform = call("GET", "/v1/agents/public-key", auth=False)
    unsigned = {k: v for k, v in card.items() if k not in ("signature", "verify_url", "overage")}
    Ed25519PublicKey.from_public_bytes(b64d(platform["public_key"])).verify(
        b64d(card["signature"]), canonical(unsigned)
    )
    print(f"2. Card verified online={verify['signature_valid']} and offline=True")

    # 3. Sign a handoff with the FROM agent's private key.
    payload = {
        "v": 1,
        "handoff_id": "h_" + uuid.uuid4().hex,
        "from_agent_id": a["agent_id"],
        "to_agent_id": b["agent_id"],
        "task_hash": hashlib.sha256(b"summarize the quarterly report").hexdigest(),
        "scope": {"allowed": ["read"], "max_actions": 3},
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "parent_handoff_id": "",
    }
    signature = b64e(from_private.sign(canonical(payload)))
    receipt = call("POST", f"/v1/agents/{a['agent_id']}/handoffs", {**payload, "signature": signature})
    print(f"3. Signed handoff accepted: {receipt['handoff_id']}")

    # 4. Read the immutable receipt history.
    receipts = call("GET", f"/v1/agents/{b['agent_id']}/receipts")
    print(f"4. Receipts for worker: {len(receipts.get('receipts', []))}")

    print("\nDone. Open the card at " + BASE + "/a/" + a["agent_id"])
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        print("ERROR: " + str(exc), file=sys.stderr)
        sys.exit(1)
