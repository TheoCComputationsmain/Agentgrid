"""Optional live proof against your own AgentGrid account.

Creates two agents, records one real handoff, then reads the public receipt and
verifies its signature locally. The signer key is compared with the from-agent's
public card before verification.

Set your own key in your own environment first:

    export AGENTGRID_API_KEY=agk_...     # macOS/Linux
    set AGENTGRID_API_KEY=agk_...        # Windows CMD
"""
from __future__ import annotations

import os

from agentgrid_protocol import AgentGrid

from task_binding import TASK, TAMPERED_TASK, task_digest, verify_payload


def main() -> int:
    if not os.environ.get("AGENTGRID_API_KEY", "").strip():
        raise SystemExit(
            "Set AGENTGRID_API_KEY in your own environment to run live mode. "
            "Local mode (`python task_binding.py`) needs no key."
        )

    ag = AgentGrid()
    print("Service: " + ag.base_url)
    planner = ag.create_agent("Task Binding Planner", capabilities=["plan"])
    worker = ag.create_agent("Task Binding Worker", capabilities=["read"])
    print(f"Agents:  {planner.agent_id} -> {worker.agent_id}")

    receipt = planner.handoff_to(
        worker,
        task=TASK,
        scope={"allowed": ["read"], "max_actions": 2},
    )
    print("Receipt: " + receipt["handoff_id"])
    print("Task hash on receipt: " + receipt["task_hash"])

    stored = next(
        item for item in worker.receipts() if item["handoff_id"] == receipt["handoff_id"]
    )
    assert stored["task_hash"] == task_digest(TASK)
    print("Local digest matches: True")

    card = ag.card(stored["from_agent_id"])
    key_matches_card = card.get("public_key") == stored.get("signer_public_key")
    print("Signer key matches from-agent card: " + str(key_matches_card))
    assert key_matches_card

    signed_payload = {
        key: value
        for key, value in stored.items()
        if key not in {"signature", "signer_public_key"}
    }
    signed_payload["v"] = 1
    signature_valid = verify_payload(
        signed_payload,
        stored["signature"],
        stored["signer_public_key"],
    )
    print("Receipt signature valid locally: " + str(signature_valid))
    assert signature_valid

    print("Different task digest: " + task_digest(TAMPERED_TASK))
    assert task_digest(TAMPERED_TASK) != stored["task_hash"]
    print("The raw task text is not present in the receipt.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
