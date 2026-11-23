"""AgentGrid SDK: signed agent identity, handoffs, and receipts in a few lines."""
from __future__ import annotations

from .client import (
    DEFAULT_BASE_URL,
    Agent,
    AgentGrid,
    AgentGridError,
    clear_pending_client,
    default_key_path,
    default_pending_path,
    load_api_key,
    load_pending_client,
    save_api_key,
    save_pending_client,
)
from .crypto import AgentKey, b64d, b64e, canonical, task_digest, unsigned_card

__version__ = "0.2.4"
__all__ = [
    "DEFAULT_BASE_URL",
    "Agent",
    "AgentGrid",
    "AgentGridError",
    "AgentKey",
    "clear_pending_client",
    "default_pending_path",
    "b64d",
    "b64e",
    "canonical",
    "default_key_path",
    "load_api_key",
    "load_pending_client",
    "save_api_key",
    "save_pending_client",
    "task_digest",
    "unsigned_card",
]
