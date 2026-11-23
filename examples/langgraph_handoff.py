"""Drop an AgentGrid signed handoff into a LangGraph graph.

Copy this file into your own project, set AGENTGRID_API_KEY, and adapt
``handoff_node``. It works without LangGraph installed (it runs the node
directly), and uses LangGraph automatically when it is available.

The same node body drops into other frameworks:

CrewAI
    def handoff_tool(planner, worker, task):
        return planner.handoff_to(
            worker,
            task=task.description,
            scope={"allowed": ["read"], "max_actions": 2},
        )

OpenAI Agents SDK
    from agents import function_tool

    @function_tool
    def record_agentgrid_handoff(task: str) -> dict:
        return planner.handoff_to(
            worker, task=task, scope={"allowed": ["read"], "max_actions": 2}
        )

In every case the private key stays local; only the public key is registered,
and AgentGrid stores an immutable receipt for the signed handoff.
"""
from __future__ import annotations

import os
from typing import Any, TypedDict

from agentgrid_protocol import Agent, AgentGrid

DEFAULT_TASK = "summarize the quarterly report using read-only sources"
DEFAULT_SCOPE: dict[str, Any] = {"allowed": ["read"], "max_actions": 2}


class HandoffState(TypedDict, total=False):
    task: str
    agentgrid_receipt: dict[str, Any]


def build_agents() -> tuple[AgentGrid, Agent, Agent]:
    """Register fresh local agents; keep their private keys in this process."""
    ag = AgentGrid()

    planner = ag.create_agent(
        "LangGraph Planner",
        capabilities=["plan"],
        description="Decides what work should be delegated.",
    )
    worker = ag.create_agent(
        "LangGraph Worker",
        capabilities=["read"],
        description="Carries out the read-only task.",
    )
    print("Agent IDs: " + planner.agent_id + " -> " + worker.agent_id)
    return ag, planner, worker


def handoff_node(planner: Agent, worker: Agent):
    """Return a LangGraph node that records a real signed handoff."""

    def _node(state: HandoffState) -> HandoffState:
        receipt = planner.handoff_to(
            worker,
            task=state.get("task", DEFAULT_TASK),
            scope=DEFAULT_SCOPE,
        )
        return {**state, "agentgrid_receipt": receipt}

    return _node


def run_with_langgraph(node, initial: HandoffState) -> dict[str, Any] | None:
    """Use LangGraph when installed; return None when it is not available."""
    try:
        from langgraph.graph import END, StateGraph
    except ImportError:
        return None

    graph = StateGraph(HandoffState)
    graph.add_node("agentgrid_handoff", node)
    graph.set_entry_point("agentgrid_handoff")
    graph.add_edge("agentgrid_handoff", END)
    return graph.compile().invoke(initial)


def main() -> int:
    ag, planner, worker = build_agents()
    node = handoff_node(planner, worker)
    initial: HandoffState = {"task": os.environ.get("AGENTGRID_TASK", DEFAULT_TASK)}

    result = run_with_langgraph(node, initial)
    if result is None:
        print("LangGraph not installed; running the node directly.")
        result = node(initial)

    receipt = result["agentgrid_receipt"]
    print("Signed handoff: " + receipt["handoff_id"])
    print("Task hash:      " + receipt["task_hash"])
    print("Scope:          " + str(receipt.get("scope", DEFAULT_SCOPE)))
    print("Worker receipts:" + str(len(worker.receipts())))
    print("Card:           " + planner.card_url)
    print("API:            " + ag.base_url + "/docs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
