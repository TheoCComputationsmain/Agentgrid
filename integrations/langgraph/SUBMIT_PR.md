# Submitting the LangGraph example PR

This submission is user-owned. Do not ask anyone else to submit it, and do not
share credentials with the assistant.

## Prepare

From `agentgrid-public` on your own machine:

```bash
git checkout -b agentgrid-langgraph-example
```

The folder to propose is:

```text
integrations/langgraph/
├── README.md
├── PR_BODY.md
├── agentgrid_handoff.py
└── tests/test_agentgrid_handoff.py
```

Local check:

```bash
python -m unittest discover -s integrations/langgraph/tests
```

No API key is needed for the tests.

## Open the PR

1. Fork or branch the target repository from your own GitHub account.
2. Add the four files into the target's examples/integrations area, respecting
   that project's layout.
3. Open a pull request from your own account.
4. Paste `PR_BODY.md` as the description.
5. Keep the title: **Example: record signed AgentGrid handoffs from a LangGraph node**.

## If asked to change it

- Keep it unofficial: “example”, not “official integration”.
- Keep the no-network tests.
- Do not add credentials, payment details, adoption metrics, or traffic asks.
- If the target project rejects third-party examples, do not push further. Leave
  the folder in the AgentGrid repo as documentation instead.

## After submission

Paste the PR URL into `AgentGrid/GROWTH_ARTIFACTS.md` when you want it recorded.
Do not ask for votes, reviews from strangers, or promotion.
