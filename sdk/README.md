# AgentGrid Protocol SDK for Python

Signed identity, discovery, and handoff receipts for AI agents — in a few lines.

AgentGrid is infrastructure for agents, not another chatbot. This SDK handles
local Ed25519 key generation, canonical signing, handoff payloads, offline card
verification, and receipt/statement reads against the live service.

## Install

```bash
pip install theoc-agentgrid-protocol
```

## One-command quickstart

Registration is open self-service — no invite token, no operator approval:

```bash
agrid register --email you@example.com   # creates a free client, stores the key locally
agrid quickstart                         # real agents, real signed handoff, real receipt
```

`agrid register` prints only the Client ID and tier; the one-time `agk_...` key is
stored under `~/.agentgrid/credentials.json` and never displayed. Save a backup
of that key when you first get it. The `--email` flag is optional but recommended:
it lets the operator recover the right Client ID if you mistype it on a payment
form. If you already have a key, use `agrid login` instead. `agrid quickstart`
prompts for a key if neither command was run.

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
agrid register                   # create a free client (see above)
agrid login                      # store an API key you already have
agrid doctor                     # service, database, and account status
agrid statement                  # current invoice and hard caps
agrid card ag_...                # public card + online/offline signature check
```

## Python usage

```python
from agentgrid_protocol import AgentGrid

ag = AgentGrid()                 # reads AGENTGRID_API_KEY or ~/.agentgrid/credentials.json

# Or register a free client right from Python:
# me = ag.register(email="you@example.com")

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

### Offline verification

```python
from agentgrid_protocol import AgentGrid, canonical, unsigned_card
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ag = AgentGrid()
card = ag.card("ag_...")
keys = ag.public_keys()
payload = canonical(unsigned_card(card))
signature = card["signature"]

# base64url decode with the SDK helper, then Ed25519PublicKey.verify(...)
```

The platform public key (and, during rotation, the previous key) is available
from `GET /v1/agents/public-key`. Cards remain verifiable without a network
round trip.

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
