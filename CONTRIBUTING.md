# Contributing

Thanks for taking a look. Bug reports, protocol feedback, and small PRs are welcome.

## Local setup

```bash
pip install -r requirements-dev.txt
cp .env.example .env
python -m pytest -q
```

The test suite uses SQLite and generated keys — no network or secrets required.

## Guidelines

- Keep the service credential-free: no payment keys, webhooks, or money handling.
- Card signatures must cover the original unsigned payload; response metadata is not signed.
- Add a test for every behavior change.
- Do not commit `.env`, API keys, or database files (`.gitignore` covers these).

## Security issues

Please report them privately to the maintainer rather than opening a public issue.
