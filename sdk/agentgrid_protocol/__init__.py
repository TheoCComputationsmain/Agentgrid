"""AgentGrid SDK: signed agent identity, handoffs, and receipts in a few lines."""
from __future__ import annotations

from .client import (
    DEFAULT_BASE_URL,
    Agent,
    AgentGrid,
    AgentGridError,
    default_key_path,
    load_api_key,
    save_api_key,
)
from .crypto import AgentKey, b64d, b64e, canonical, task_digest, unsigned_card

__version__ = "0.2.2"
__all__ = [
    "DEFAULT_BASE_URL",
    "Agent",
    "AgentGrid",
    "AgentGridError",
    "AgentKey",
    "b64d",
    "b64e",
    "canonical",
    "default_key_path",
    "load_api_key",
    "save_api_key",
    "task_digest",
    "unsigned_card",
]
