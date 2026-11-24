"""Unofficial LangGraph node that records an AgentGrid signed handoff.

Copy this module into a LangGraph project with ``theoc-agentgrid-protocol``
installed and an ``AGENTGRID_API_KEY`` in the environment. The node writes one
real receipt per invocation. It does not alter graph routing; it only records
the handoff that the graph has already decided to make.
"""
from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any, Callable, Mapping, TypedDict

if TYPE_CHECKING:
    from agentgrid_protocol import Agent


DEFAULT_TASK = "summarize the quarterly report using read-only sources"
DEFAULT_SCOPE: dict[str, Any] = {"allowed": ["read"], "max_actions": 2}


class HandoffState(TypedDict, total=False):
    """LangGraph state keys used by the node."""

    task: str
    task_hash: str
    scope: dict[str, Any]
    agentgrid_receipt: dict[str, Any]


def make_agentgrid_handoff_node(
    *,
    planner: Agent,
    worker: Agent,
    scope: Mapping[str, Any] | None = None,
) -> Callable[[HandoffState], HandoffState]:
    """Return a LangGraph node that records a signed handoff.

    ``planner`` and ``worker`` are AgentGrid ``Agent`` objects created by the
    caller. Their private keys stay in the caller's process. Only a SHA-256
    task hash is sent to the service; the raw task text is not stored.
    """

    node_scope = dict(scope or DEFAULT_SCOPE)

    def node(state: HandoffState) -> HandoffState:
        task = str(state.get("task") or DEFAULT_TASK)
        receipt = planner.handoff_to(
            worker,
            task=task,
            scope=dict(state.get("scope") or node_scope),
        )
        expected_hash = hashlib.sha256(task.encode("utf-8")).hexdigest()
        if receipt.get("task_hash") != expected_hash:
            raise RuntimeError("AgentGrid receipt task_hash does not match the local task text")
        return {
            **state,
            "task_hash": receipt["task_hash"],
            "agentgrid_receipt": receipt,
        }

    return node


def attach_agentgrid_node(graph: Any, *, node: Callable[[HandoffState], HandoffState]) -> Any:
    """Add the node to a compiled-style graph when LangGraph is available.

    This helper is intentionally small: callers with a different graph shape can
    ignore it and add ``node`` directly with ``graph.add_node``.
    """
    try:
        graph.add_node("agentgrid_handoff", node)
    except AttributeError as exc:
        raise TypeError("graph must expose add_node(name, node)") from exc
    return graph
