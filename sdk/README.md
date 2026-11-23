# AgentGrid Protocol SDK for Python

Signed identity, discovery, and handoff receipts for AI agents — in a few lines.

AgentGrid is infrastructure for agents, not another chatbot. This SDK handles
local Ed25519 key generation, canonical signing, handoff payloads, offline card
verification, and receipt/statement reads against the live service.

## Install

```bash
pip install theoc-agentgrid-protocol
```

## Quickstart: register, verify, handoff

Registration is open self-service — no invite token, no operator approval — but a
real email is required to prove the signup is from a reachable human:

```bash
agrid register --email you@example.com   # sends a 6-digit code; no key yet
agrid verify 123456                      # code from inbox; key + first handoff happen here
```

`agrid register` prints only the Client ID and tier. We send a 6-digit code to
the address; no `agk_...` key exists until `agrid verify` confirms it. The key is
then stored under `~/.agentgrid/credentials.json`, never displayed, and should be
backed up. Verification immediately runs a real signed handoff and prints the
receipt, so there is no fourth command. Pass `--no-quickstart` to skip it, or run
`agrid quickstart` later for another demo. If the code expires, run `agrid resend`
(60-second cooldown). If you already have a key, use `agrid login`.

Expected output:

```text
AgentGrid quickstart -> https://agentgrid-pied.vercel.app

1. Registered agents: ag_... -> ag_...
2. Card verified online=True and offline=True
3. Signed handoff accepted: h_...
4. Receipts for worker: 1

Done. Open the card at https://agentgrid-pied.vercel.app/a/ag_...
```

Other commands:

```bash
agrid register                   # create an unverified client (prompts for email)
agrid verify <code>              # confirm code, save key, run first handoff
agrid verify <code> --no-quickstart  # confirm code only
agrid resend                     # request a fresh code if the first expired
agrid login                      # store an API key you already have
agrid doctor                     # service, database, and account status
agrid statement                  # current invoice and hard caps
agrid card ag_...                # public card + online/offline signature check
agrid receipts ag_...            # immutable receipts for an agent
```

## Python usage

```python
from agentgrid_protocol import AgentGrid

ag = AgentGrid()                 # reads AGENTGRID_API_KEY or ~/.agentgrid/credentials.json

# Or register and verify a free client right from Python:
# pending = ag.register(email="you@example.com")   # no api_key yet
# me = ag.verify_email(pending["client_id"], "123456")  # now ag.api_key is set

planner = ag.create_agent("Planner", capabilities=["plan"])
worker = ag.create_agent("Worker", capabilities=["read"])

print(ag.verify_card(planner.agent_id))
# {'agent_id': 'ag_...', 'online': True, 'status': 'ACTIVE', 'offline': True}

receipt = planner.handoff_to(worker, task="summarize the quarterly report")
print(receipt["handoff_id"])
print(len(worker.receipts()))
```

The private key for each agent is generated locally and stays in the `Agent`
object. Only the public key is registered with AgentGrid. A handoff signature
covers the canonical JSON payload; the service verifies it against the
from-agent's registered public key before storing an immutable receipt.

### Framework drop-in

Copy `examples/langgraph_handoff.py` from the repository into your own project.
It is a single `handoff_node` you can paste into LangGraph, and its docstring has
the CrewAI and OpenAI Agents SDK equivalents. It calls
`planner.handoff_to(worker, task=..., scope=...)` and prints the real receipt.

## Copy-paste recipes

### Verify a card offline

```python
from agentgrid_protocol import AgentGrid, canonical, unsigned_card
from agentgrid_protocol.crypto import b64d
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ag = AgentGrid()                  # no auth needed for public reads
card = ag.card("ag_...")          # any public agent ID
keys = ag.public_keys()           # includes previous_public_key during rotation
message = canonical(unsigned_card(card))
signature = b64d(card["signature"])

for key_b64 in (keys.get("public_key", ""), keys.get("previous_public_key", "")):
    if not key_b64:
        continue
    try:
        Ed25519PublicKey.from_public_bytes(b64d(key_b64)).verify(signature, message)
        print("offline signature: VALID")
        break
    except Exception:
        continue
else:
    print("offline signature: INVALID")
```

CLI equivalent: `agrid card ag_...`. During rotation the previous platform key
stays published so older cards remain verifiable.

### Record a scoped handoff

```python
from agentgrid_protocol import AgentGrid

ag = AgentGrid()
planner = ag.create_agent("Planner", capabilities=["plan"])
worker = ag.create_agent("Worker", capabilities=["read"])

receipt = planner.handoff_to(
    worker,
    task="summarize the quarterly report",
    scope={"allowed": ["read"], "max_actions": 2},
)
print(receipt["handoff_id"], receipt["scope"])

# A child handoff may only narrow the parent's scope:
sub = ag.create_agent("Sub-worker", capabilities=["read"])
child = worker.handoff_to(
    sub,
    task="fetch one page",
    scope={"allowed": ["read"], "max_actions": 1},
    parent_handoff_id=receipt["handoff_id"],
)
print(child["handoff_id"])
```

A child's `allowed` list must be a subset of its parent's and `max_actions`
cannot increase. Only a SHA-256 task hash is stored, never the raw task text.

### Read a receipt

```python
from agentgrid_protocol import AgentGrid

ag = AgentGrid()
data = ag.receipts("ag_...")       # public: no API key needed
for r in data["receipts"]:
    print(r["handoff_id"], r["from_agent_id"], "->", r["to_agent_id"])
    print("  task hash:", r["task_hash"])
    print("  scope:", r["scope"], "created:", r["created_at"])
print("total:", data["count"])
```

CLI equivalent: `agrid receipts ag_...`. Receipts are immutable at the database
level and readable by anyone who knows the agent ID.

### FAQ

- **Do I need an invite token?** No. Registration is open self-service.
- **Where is my API key?** Stored at `~/.agentgrid/credentials.json`, never
  printed. The service shows it only once; back it up.
- **What does `agrid quickstart` do?** Creates two agents with local keys,
  verifies a card, signs a real scoped handoff, and reads the receipt.
- **Can a child widen inherited scope?** No — subset only, and `max_actions`
  cannot increase.
- **Are receipts private?** No. They are public by agent ID and contain a task
  hash, not raw task text. Do not put secrets in the task field.
- **Do I need a card to start?** No. Free tier requires no payment method;
  all payments happen outside AgentGrid.
- **What if I exceed free limits?** Overage is metered up to 3× included
  limits, then new writes return HTTP 402. Check `agrid statement`.

### Statements

```python
statement = ag.statement()
print(statement["invoice_id"], statement["total_due_usd"], statement["hard_caps"])
```

Usage above included limits is metered in an immutable ledger. Overage is
$1 per 1,000 extra handoffs and $0.10 per extra agent per day. Every tier,
including Free, allows overage up to a 3x hard cap. Payments happen outside
the platform; AgentGrid only records external references after an operator
confirms them.

## Configuration

| Source | Purpose |
|---|---|
| `AGENTGRID_API_KEY` | API key used for authenticated calls |
| `AGENTGRID_BASE_URL` | Override the production URL |
| `~/.agentgrid/credentials.json` | Locally stored key written by `agrid login` |

No key is ever printed by the SDK or CLI. Environment variables take priority
over the stored file.

## Errors

All API and configuration failures raise `AgentGridError` with `status` and
`detail` attributes.

```python
from agentgrid_protocol import AgentGrid, AgentGridError

try:
    AgentGrid().me()
except AgentGridError as exc:
    print(exc.status, exc.detail)
```

## Requirements

Python 3.10+ and `cryptography`. The SDK uses only the standard library for
HTTP, so it works anywhere Python runs.
