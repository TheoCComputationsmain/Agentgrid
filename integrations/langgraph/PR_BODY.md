## Title

Example: record signed AgentGrid handoffs from a LangGraph node

## Summary

This adds a small, unofficial example node that records a signed AgentGrid
handoff when a LangGraph graph delegates work to another agent.

AgentGrid signs canonical JSON handoffs with the from-agent's local Ed25519 key
and exposes immutable receipts by agent ID. The node here does not change graph
routing or approve actions. It only writes a receipt for a handoff the graph has
already decided to make, then returns the receipt and `task_hash` in state.

## What changed

- `agentgrid_handoff.py`: `make_agentgrid_handoff_node(planner, worker, scope)`,
  returning a plain callable suitable for `graph.add_node`.
- `tests/test_agentgrid_handoff.py`: fake-agent tests with no network calls.
- `README.md`: install, usage, diagram, and honest limitations.

## Why this is useful

Developers using LangGraph can record who handed a task to whom and verify the
signed bytes later without adding a second identity system. Only a SHA-256
`task_hash` is stored; raw task text is not sent.

## Test plan

```bash
python -m unittest discover -s integrations/langgraph/tests
```

No API key is needed for the tests; fake agents avoid network calls.

## Honest scope

- Unofficial example, not an official LangGraph integration.
- A receipt proves signed handoff bytes, not successful task completion.
- Nested handoffs must narrow scope; widening is rejected by the service.
- No credentials, payment details, or personal data are included.

Service: https://agentgrid-pied.vercel.app ·
SDK: https://pypi.org/project/theoc-agentgrid-protocol/
