# Contributing

## Prerequisites

- Python 3.11+
- Linux recommended for sniffer-mode development
- `libpcap-dev` installed for `python-libpcap` builds

## Local setup

```bash
cp .env.example .env
pip install -e ".[dev]"
```

## Development workflow

1. Create a feature branch.
2. Make focused changes.
3. Run quality gates locally.
4. Open a pull request with a clear summary and test evidence.

## Required checks

```bash
ruff check osniffy/ tests/
ruff format --check osniffy/ tests/
mypy osniffy/
pytest
```

## Testing guidance

- Add unit tests for parser/config/CLI/DB logic changes.
- Keep tests deterministic; prefer fixture bytes over live traffic.
- For integration behavior, use mocks or ephemeral infrastructure.

## Security expectations

- Never commit credentials, API tokens, or real `.env` files.
- Prefer least-privilege DB roles.
- Document any raw-socket or privileged runtime assumptions in PRs.
