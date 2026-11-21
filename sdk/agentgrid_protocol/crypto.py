"""Local cryptography helpers for the AgentGrid SDK.

Private keys are generated and used on the machine running the SDK. They are
never sent to AgentGrid; only the public key is registered.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Response metadata that is not part of the platform-signed card payload.
CARD_METADATA_KEYS = frozenset({"signature", "verify_url", "overage"})


def b64e(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    """Decode unpadded or padded base64url."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical(payload: dict[str, Any]) -> bytes:
    """Canonical JSON used by AgentGrid for every signature."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def unsigned_card(card: dict[str, Any]) -> dict[str, Any]:
    """Return exactly the fields covered by the platform signature."""
    return {key: value for key, value in card.items() if key not in CARD_METADATA_KEYS}


def task_digest(task: str) -> str:
    """SHA-256 of a task description, as required by the handoff payload."""
    return hashlib.sha256(task.encode("utf-8")).hexdigest()


@dataclass
class AgentKey:
    """An Ed25519 key pair belonging to one local agent."""

    private: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "AgentKey":
        return cls(Ed25519PrivateKey.generate())

    @property
    def public_b64(self) -> str:
        return b64e(
            self.private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )

    def sign(self, payload: dict[str, Any]) -> str:
        return b64e(self.private.sign(canonical(payload)))
