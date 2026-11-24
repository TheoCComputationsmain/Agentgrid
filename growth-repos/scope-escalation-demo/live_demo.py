"""Optional live proof against your own AgentGrid account.

This script creates three agents and one accepted child handoff, then attempts
two widened child handoffs that the hosted API must reject. Failed handoffs are
not stored, so only the accepted one becomes a receipt.

Set your own key in your own environment first:

    export AGENTGRID_API_KEY=agk_...     # macOS/Linux
    set AGENTGRID_API_KEY=agk_...        # Windows CMD

No key is read from a file by this demo, printed, or sent anywhere except the
official AgentGrid base URL.
"""
from __future__ import annotations

import os

from agentgrid_protocol import AgentGrid, AgentGridError
from agentgrid_protocol.client import Agent

from scope_chain import (
    NARROWED_SCOPE,
    PARENT_SCOPE,
    WIDENED_ALLOWED_SCOPE,
    WIDENED_ACTIONS_SCOPE,
)

TASK = "summarize one read-only page"


def _expect_widening_rejected(
    worker: Agent,
    sub: Agent,
    *,
    scope: dict,
    parent_handoff_id: str,
    label: str,
) -> None:
    try:
        worker.handoff_to(
            sub,
            task=TASK,
            scope=scope,
            parent_handoff_id=parent_handoff_id,
        )
    except AgentGridError as exc:
        print(f"REJECT  {label:22} HTTP {exc.status}: {exc.detail}")
        assert exc.status == 400, exc.detail
        assert "may not be widened" in exc.detail, exc.detail
        return
    raise AssertionError(f"{label} was accepted but should have been rejected")


def main() -> int:
    if not os.environ.get("AGENTGRID_API_KEY", "").strip():
        raise SystemExit(
            "Set AGENTGRID_API_KEY in your own environment to run live mode. "
            "Local mode (`python scope_chain.py`) needs no key."
        )

    ag = AgentGrid()
    print("Service: " + ag.base_url)
    planner = ag.create_agent("Scope Demo Planner", capabilities=["plan"])
    worker = ag.create_agent("Scope Demo Worker", capabilities=["read"])
    sub = ag.create_agent("Scope Demo Sub-worker", capabilities=["read"])
    print(f"Agents:  {planner.agent_id} -> {worker.agent_id} -> {sub.agent_id}")

    parent = planner.handoff_to(worker, task=TASK, scope=PARENT_SCOPE)
    parent_id = parent["handoff_id"]
    print(f"Parent:  {parent_id} scope={parent['scope']}")

    child = worker.handoff_to(
        sub,
        task=TASK,
        scope=NARROWED_SCOPE,
        parent_handoff_id=parent_id,
    )
    print(f"ACCEPT  narrowed child     {child['handoff_id']} scope={child['scope']}")

    _expect_widening_rejected(
        worker,
        sub,
        scope=WIDENED_ALLOWED_SCOPE,
        parent_handoff_id=parent_id,
        label="add write capability",
    )
    _expect_widening_rejected(
        worker,
        sub,
        scope=WIDENED_ACTIONS_SCOPE,
        parent_handoff_id=parent_id,
        label="raise max_actions",
    )

    worker_receipts = worker.receipts()
    sub_receipts = sub.receipts()
    print(f"Worker receipts: {len(worker_receipts)}")
    print(f"Sub-worker receipts: {len(sub_receipts)} (only the narrowed child is stored)")
    assert len(worker_receipts) == 1
    assert len(sub_receipts) == 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
