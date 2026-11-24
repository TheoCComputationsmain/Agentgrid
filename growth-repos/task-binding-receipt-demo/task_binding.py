"""Local model of AgentGrid task-hash binding and receipt signatures.

The raw task text never leaves this file. AgentGrid receives ``task_hash`` (a
SHA-256 digest) inside a canonical JSON payload signed by the from-agent's local
Ed25519 key. Changing the task changes the hash; changing the hash breaks the
signature.

No network access and no API key are needed for this demo.
"""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

TASK = "summarize the quarterly report"
TAMPERED_TASK = "rewrite the quarterly report"
SCOPE: dict[str, Any] = {"allowed": ["read"], "max_actions": 2}


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical(payload: dict[str, Any]) -> bytes:
    """The exact JSON bytes AgentGrid signs and verifies."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def task_digest(task: str) -> str:
    """SHA-256 hex digest stored as ``task_hash``; raw task text is not stored."""
    return hashlib.sha256(task.encode("utf-8")).hexdigest()


def build_payload(
    task: str,
    *,
    from_agent_id: str = "ag_from",
    to_agent_id: str = "ag_to",
    scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the canonical handoff payload, with a hash instead of raw text."""
    return {
        "v": 1,
        "handoff_id": "h_" + uuid.uuid4().hex,
        "from_agent_id": from_agent_id,
        "to_agent_id": to_agent_id,
        "task_hash": task_digest(task),
        "scope": dict(scope or SCOPE),
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "parent_handoff_id": "",
    }


def sign_payload(payload: dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    return b64e(private_key.sign(canonical(payload)))


def verify_payload(
    payload: dict[str, Any], signature_b64: str, public_key_b64: str
) -> bool:
    """Return True when the signature matches the canonical payload bytes."""
    try:
        public_key = Ed25519PublicKey.from_public_bytes(b64d(public_key_b64))
        public_key.verify(b64d(signature_b64), canonical(payload))
        return True
    except Exception:
        return False


def run_demo() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key_b64 = b64e(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )

    payload = build_payload(TASK)
    signature = sign_payload(payload, private_key)

    print("Task (local only):   " + TASK)
    print("Stored task_hash:    " + payload["task_hash"])
    print("Signed fields:       " + ", ".join(sorted(payload)))
    print("Signature valid:     " + str(verify_payload(payload, signature, public_key_b64)))

    assert task_digest(TASK) == payload["task_hash"]
    assert verify_payload(payload, signature, public_key_b64)

    tampered = dict(payload)
    tampered["task_hash"] = task_digest(TAMPERED_TASK)
    print("Tampered task hash:  " + tampered["task_hash"])
    print("Signature after tamper: " + str(verify_payload(tampered, signature, public_key_b64)))

    assert task_digest(TAMPERED_TASK) != payload["task_hash"]
    assert not verify_payload(tampered, signature, public_key_b64)
    print("Only the digest is stored. Changing the task breaks the hash, and changing")
    print("the hash breaks the signature over the canonical payload.")


if __name__ == "__main__":
    run_demo()
