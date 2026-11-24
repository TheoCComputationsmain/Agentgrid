import hashlib
import sys
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentgrid_handoff import DEFAULT_SCOPE, attach_agentgrid_node, make_agentgrid_handoff_node  # noqa: E402


class FakeAgent:
    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        self.calls: list[dict[str, Any]] = []

    def handoff_to(self, target: "FakeAgent", *, task: str, scope: dict[str, Any]) -> dict[str, Any]:
        self.calls.append({"target": target.agent_id, "task": task, "scope": scope})
        return {
            "handoff_id": "h_" + "0" * 32,
            "to_agent_id": target.agent_id,
            "task_hash": hashlib.sha256(task.encode("utf-8")).hexdigest(),
            "scope": scope,
            "parent_handoff_id": "",
        }


class FakeGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Any] = {}

    def add_node(self, name: str, node: Any) -> None:
        self.nodes[name] = node


class AgentGridHandoffTests(unittest.TestCase):
    def test_node_records_receipt_and_hash_without_network(self) -> None:
        planner = FakeAgent("ag_planner")
        worker = FakeAgent("ag_worker")
        node = make_agentgrid_handoff_node(planner=planner, worker=worker)  # type: ignore[arg-type]

        result = node({"task": "read one page"})

        self.assertEqual(result["task_hash"], hashlib.sha256(b"read one page").hexdigest())
        self.assertEqual(result["agentgrid_receipt"]["scope"], DEFAULT_SCOPE)
        self.assertEqual(planner.calls[0]["target"], "ag_worker")

    def test_state_scope_overrides_default(self) -> None:
        planner = FakeAgent("ag_planner")
        worker = FakeAgent("ag_worker")
        node = make_agentgrid_handoff_node(planner=planner, worker=worker)  # type: ignore[arg-type]
        scope = {"allowed": ["read"], "max_actions": 1}

        result = node({"task": "read one page", "scope": scope})

        self.assertEqual(result["agentgrid_receipt"]["scope"], scope)

    def test_node_rejects_hash_mismatch(self) -> None:
        class BadAgent(FakeAgent):
            def handoff_to(self, target, *, task, scope):
                receipt = super().handoff_to(target, task=task, scope=scope)
                receipt["task_hash"] = "0" * 64
                return receipt

        node = make_agentgrid_handoff_node(planner=BadAgent("ag_p"), worker=FakeAgent("ag_w"))  # type: ignore[arg-type]
        with self.assertRaises(RuntimeError):
            node({"task": "read one page"})

    def test_attach_helper_adds_named_node(self) -> None:
        planner = FakeAgent("ag_planner")
        worker = FakeAgent("ag_worker")
        node = make_agentgrid_handoff_node(planner=planner, worker=worker)  # type: ignore[arg-type]
        graph = attach_agentgrid_node(FakeGraph(), node=node)

        self.assertEqual(graph.nodes["agentgrid_handoff"], node)


if __name__ == "__main__":
    unittest.main()
