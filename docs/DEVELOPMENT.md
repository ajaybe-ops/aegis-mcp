# Development

## Prerequisites

- Python 3.11+

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## Commands

```bash
pytest --cov                 # full suite (coverage gate: 75%)
pytest tests/test_triage.py -q   # single area
aegis-mcp eval                # offline eval suite
ruff check . && ruff format --check .
mypy                          # strict, src only
bandit -r src -q              # static security lint
pip-audit                      # dependency vulnerability audit
```

## Test layout

- Unit: config, risk, sanitize, cache, limits, auth, http client, store, intel, triage.
- E2E: `tests/test_server_e2e.py` drives the real MCP surface via in-memory transport.
- Eval: `src/aegis_mcp/evals/` — 12 deterministic scenarios over the MCP surface.
- Helpers: `tests/helpers.py` (offline settings, sessions, report factories).

## Conventions

- Strict typing (mypy strict) and ruff (E, F, I, UP, B, SIM, ASYNC, S, RUF) + formatting.
- All external content flows through sanitization before structured output.
- New tools must use `ToolGuard.call` and declare scopes.

## CI

`.github/workflows/ci.yml` runs lint, format, type check, tests with coverage, and the offline eval suite on every push/PR to `main`.

## Security linting

`.github/workflows/security.yml` runs `bandit` and `pip-audit`.
