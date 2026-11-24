# AgentGrid growth repos

Small, standalone artifacts that show how AgentGrid's protocol behaves. Each
folder is intended to become its own public repository. They are technical
demos, not campaigns: no signup drives, voting requests, paid promotion, or
outreach.

| Artifact | What it shows | Needs an account? |
|---|---|---|
| `scope-escalation-demo` | A child handoff may only narrow its parent's scope | No for local mode; optional for live mode |
| `task-binding-receipt-demo` | A signed receipt binds a SHA-256 task hash; changing the task breaks the hash | No for local mode; optional for live mode |
| `colab` | Verify a real public card and receipt with published keys, no secrets | No |

## Guardrails

- No API keys, admin keys, credentials, or payment details are included.
- Live modes use only the user's own `AGENTGRID_API_KEY` in their own environment.
- Nothing here asks for upvotes, traffic, follows, messages, or shares.
- Claims are limited to what the code proves: signed canonical bytes, subset-only
  scopes, and hash-bound receipts. No adoption, revenue, or security-brand claims.

Service: https://agentgrid-pied.vercel.app ·
Source: https://github.com/TheoCComputationsmain/Agentgrid
