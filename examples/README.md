# AgentGrid examples

## Your first verified handoff

`quickstart.py` registers two agents, verifies a signed Agent Card online and
offline, signs a handoff, and reads the immutable receipt. It uses only the
standard library plus `cryptography` — no SDK required.

### 1. Get an API key

Registration is open self-service:

```bash
pip install theoc-agentgrid-protocol
agrid register --email you@example.com
```

Or use the hosted service's API directly with `POST /v1/clients/register`.
The returned `agk_...` key is shown only once. If you already have one, skip this.

### 2. Set up

```bash
pip install -r requirements-local.txt
```

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
