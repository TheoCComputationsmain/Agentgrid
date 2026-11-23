# AgentGrid examples

## Plug-and-play framework handoff

`langgraph_handoff.py` shows the exact node to paste into a LangGraph, CrewAI, or
OpenAI Agents SDK project. It creates a planner and worker, signs a scoped
handoff with `planner.handoff_to(worker, ...)`, and prints the immutable receipt.
LangGraph is optional: without it installed, the same node runs directly.

```bash
pip install theoc-agentgrid-protocol
export AGENTGRID_API_KEY=agk_your_key_here   # or set it in PowerShell
python examples/langgraph_handoff.py
```

The file docstring includes the CrewAI and OpenAI Agents SDK adaptations. Use
`AGENTGRID_TASK` to change the delegated task.

## Your first verified handoff

`quickstart.py` registers two agents, verifies a signed Agent Card online and
offline, signs a handoff, and reads the immutable receipt. It is the fastest way
to see what AgentGrid actually does.

### 1. Get an API key

Ask the operator to register a client for you. They will give you a key that
starts with `agk_`. The key is shown only once, so store it somewhere safe. On the operator's own
machine, `quickstart.py` also loads a key from `examples/.dev_api_key`
automatically if no environment variable is set.

### 2. Set up

From the AgentGrid folder:

```bash
pip install -r requirements-local.txt
```

Then set two environment variables:

```powershell
# Windows PowerShell
$env:AGENTGRID_API_KEY = "agk_your_key_here"
$env:AGENTGRID_BASE_URL = "https://agentgrid-pied.vercel.app"
```

```bash
# macOS / Linux
export AGENTGRID_API_KEY=agk_your_key_here
export AGENTGRID_BASE_URL=https://agentgrid-pied.vercel.app
```

### 3. Run

```bash
python examples/quickstart.py
```

Expected output: two agents registered, card verified online and offline, one
signed handoff accepted, and one receipt listed. The script prints a link to the
Agent Card page so you can view it in a browser.

### What to notice

- The Agent Card is signed by AgentGrid, not by the agent. Anyone can verify it
  offline using the public key at `/v1/agents/public-key`.
- The handoff is signed by the **from-agent's** private key. AgentGrid verifies
  that signature against the registered public key before storing anything.
- Scope is capped at 8 KB of canonical JSON, and nested handoffs cannot widen
  the scope they inherited.
- Receipts are immutable: database triggers block updates and deletes.
