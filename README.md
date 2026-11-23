# AgentGrid

**Signed identity, discovery, and handoff receipts for AI agents.**

[Live service](https://agentgrid-pied.vercel.app) ·
[Developer guide](https://agentgrid-pied.vercel.app/guide) ·
[API reference](https://agentgrid-pied.vercel.app/docs) ·
[PyPI](https://pypi.org/project/theoc-agentgrid-protocol/)

AgentGrid is infrastructure for agents, not another chatbot. Register agents,
publish signed capability cards that anyone can verify offline, and record signed
handoffs between agents with scoped, immutable receipts.

There is **no money inside the platform**: no wallet, escrow, auto top-up,
in-app checkout, or automatic deduction. Usage is metered in an immutable ledger;
subscriptions and overage are paid externally at cycle end.

## Why

When one agent delegates to another, three questions come up fast:

1. **Who is this agent, really?** — a signed Agent Card, verifiable with a published Ed25519 key.
2. **What was it allowed to do?** — a signed handoff with an explicit scope; nested handoffs cannot widen it.
3. **What actually happened?** — an immutable receipt, readable by both sides.

AgentGrid answers all three with one small HTTP API and a Python SDK.

## 60-second quickstart

Registration is open self-service — no invite token, no operator approval.

```bash
pip install theoc-agentgrid-protocol
agrid register --email you@example.com
agrid quickstart
agrid card <agent_id>        # ag_... ID printed by quickstart
agrid receipts <agent_id>    # worker ID printed by quickstart
```

`agrid register` stores your one-time `agk_...` key locally, never prints it,
and then shows the exact next steps. `agrid quickstart` registers two agents,
verifies a card online and offline, signs a handoff, and reads the receipt.
`agrid card` and `agrid receipts` let you check that work afterwards.

```text
AgentGrid quickstart -> https://agentgrid-pied.vercel.app

1. Registered agents: ag_... -> ag_...
2. Card verified online=True and offline=True
3. Signed handoff accepted: h_...
4. Receipts for worker: 1
```

The service is live at **https://agentgrid-pied.vercel.app**. Public cards look like
`https://agentgrid-pied.vercel.app/a/ag_...`.

## Python usage

```python
from agentgrid_protocol import AgentGrid

ag = AgentGrid()                 # reads AGENTGRID_API_KEY or ~/.agentgrid/credentials.json

planner = ag.create_agent("Planner", capabilities=["plan"])
worker  = ag.create_agent("Worker", capabilities=["read"])

print(ag.verify_card(planner.agent_id))
# {'agent_id': 'ag_...', 'online': True, 'status': 'ACTIVE', 'offline': True}

receipt = planner.handoff_to(worker, task="summarize the quarterly report")
print(receipt["handoff_id"], len(worker.receipts()))
```

The private key for each agent is generated locally and never sent to AgentGrid.
Only the public key is registered. Handoffs are signed by the **from-agent** over
canonical JSON; the service verifies the signature before storing an immutable
receipt.

### Offline card verification

```python
from agentgrid_protocol import AgentGrid, canonical, unsigned_card
from agentgrid_protocol.crypto import b64d
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ag = AgentGrid()
card = ag.card("ag_...")
keys = ag.public_keys()             # includes previous_public_key during rotation
Ed25519PublicKey.from_public_bytes(b64d(keys["public_key"])).verify(
    b64d(card["signature"]), canonical(unsigned_card(card))
)
```

During rotation, iterate over both `public_key` and `previous_public_key`. CLI
equivalent: `agrid card ag_...`.

### Scoped handoff

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
```

A child handoff may only narrow inherited scope: `allowed` must be a subset and
`max_actions` cannot increase. Only a SHA-256 task hash is stored.

### Read a receipt

```python
from agentgrid_protocol import AgentGrid

data = AgentGrid().receipts("ag_...")   # public: no API key needed
for r in data["receipts"]:
    print(r["handoff_id"], r["from_agent_id"], "->", r["to_agent_id"])
    print("  task hash:", r["task_hash"], "scope:", r["scope"])
print("total:", data["count"])
```

CLI equivalent: `agrid receipts ag_...`. Receipts are immutable and readable by
anyone who knows the agent ID.

## FAQ

- **Do I need an invite token?** No. Registration is open self-service.
- **Where is my API key?** In `~/.agentgrid/credentials.json`; it is never
  printed and shown only once by the service. Back it up.
- **What does `agrid quickstart` do?** Creates two agents with local Ed25519
  keys, verifies a card online and offline, signs a scoped handoff, and reads
  the receipt — all real operations.
- **Can a child agent widen inherited scope?** No. Subset only, and
  `max_actions` cannot increase.
- **Are receipts private?** No. Public by agent ID, containing a task hash, not
  raw task text. Do not put sensitive data in the task field.
- **Do I need a payment method?** No. Free tier needs no card; payments are
  entirely external.
- **What happens at the free limits?** Overage is metered up to 3× included
  limits, then writes return HTTP 402. Check `agrid statement`.

## Signed handoff payload

```json
{
  "v": 1,
  "handoff_id": "h_<32 hex>",
  "from_agent_id": "ag_...",
  "to_agent_id": "ag_...",
  "task_hash": "<64 hex SHA-256>",
  "scope": {"allowed": ["read"], "max_actions": 3},
  "created_at": "<ISO-8601 Z>",
  "parent_handoff_id": ""
}
```

The service rejects stale timestamps (>300s), oversized scopes (>8 KB), non-finite
numbers, and delegations that try to widen inherited scope. Receipts are immutable
at the database level: triggers block direct `UPDATE` and `DELETE`.

## Tiers

| Tier | Base | Included agents | Included handoffs / cycle |
|---|---:|---:|---:|
| Free | $0 | 5 | 100 |
| Plus | $20 | 100 | 10,000 |
| Pro | $150 | 1,000 | 100,000 |
| Enterprise | Custom $2,500–$5,000 | 10,000 | 1,000,000 |

A cycle is one rolling month anchored to the signup day (Nov 18 → Dec 18 → Jan 18);
there is no calendar-month reset. **Every tier, including Free, allows overage** at
`$1 per 1,000 extra handoffs` plus `$0.10 per extra agent per day`, up to a hard cap
of 3× included limits. `GET /v1/billing/statement` returns the invoice and totals.
External payments use a fixed ₹85 = $1 conversion; internal statements stay in USD.

Payment links: [Plus](https://payments.cashfree.com/forms/agentgrid-plus) ·
[Pro](https://payments.cashfree.com/forms/agentgrid-pro) ·
[Enterprise](https://payments.cashfree.com/forms/agentgrid-enterprise)

Upgrade flow: register with the email you will pay with, get your Client ID, open
the tier link, and enter that exact **AgentGrid Client ID** in the required field.
The same email lets the operator recover a mistyped Client ID automatically. Access
upgrades once payment is confirmed.

## Repository layout

```text
main.py                  FastAPI service (API, landing page, guide, docs)
sdk/                     Published Python SDK + CLI (`agrid`)
examples/quickstart.py   Dependency-free end-to-end example
tests/                   Service tests
docs/                    External payment workflow, Vercel deployment
```

## Run locally

```bash
pip install -r requirements-dev.txt
cp .env.example .env
python -m pytest -q
uvicorn main:app --reload
```

Local development uses SQLite by default. Production requires
`AGENTGRID_SIGNING_KEY_B64`, `AGENTGRID_ADMIN_KEY`, and `AGENTGRID_ADMIN_MFA_SECRET`;
missing values fail closed. See [docs/DEPLOYMENT_VERCEL.md](docs/DEPLOYMENT_VERCEL.md).

## Security notes

- Ed25519 signatures cover the original unsigned payload; response-only metadata
  (like `overage`) is not signed.
- Request bodies are capped at 64 KB from streamed bytes; rate limit is 120 req/min.
- Admin endpoints require an admin key **and** a valid TOTP code.
- Audit metadata drops secret-looking keys before storage.
- No Cashfree server keys, webhooks, wallet, or in-app checkout live in this service.

## License

MIT — see [LICENSE](LICENSE).
