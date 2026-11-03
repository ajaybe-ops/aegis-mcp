# Aegis MCP

**A production-oriented Model Context Protocol (MCP) server for vulnerability intelligence and agentic incident triage.**

Aegis connects AI agents (Claude, Cursor, custom agent runtimes, MCP-capable copilots) to structured vulnerability intelligence — NVD, FIRST EPSS, CISA KEV, and OSV — and turns multi-step incident workflows into auditable, idempotent, policy-scored operations.

> Status: **Beta (0.1.0)** — local development, stdio transport, deterministic offline fixtures, and the full MCP tool/resource/prompt surface are implemented and tested. Live-feed behavior, OAuth IdP integration, and production hardening are in progress.

## Why this exists

Security teams increasingly run agentic workflows ("triage this CVE", "scan this dependency set") that need:

- **Deterministic scoring** — a transparent additive risk model with per-factor attribution, not a black-box model.
- **Multi-source evidence** — CVSS + EPSS + KEV + OSV correlation with explicit source coverage.
- **Safety rails** — untrusted feed text is sanitized, never executed; scores are decision support, not predictions.
- **Operational rigor** — typed errors, retries, circuit breakers, rate limits, deadlines, idempotency, observability.

## Feature map

| Area | Implementation |
| --- | --- |
| Tools | `lookup_cve`, `search_vulnerabilities`, `scan_packages`, `triage_incident`, `get_incident_report`, `server_health` |
| Resources | `aegis://policy/risk`, `aegis://catalog/sources`, `aegis://server/manifest`, `aegis://incidents/{incident_id}` |
| Prompts | `triage_vulnerability`, `incident_brief`, `package_upgrade_plan` |
| Auth | JWT (HS256 secret or JWKS) bearer validation + scope enforcement; local development principals on stdio |
| Risk | Deterministic `risk-v1` additive model (CVSS 50 / EPSS 15 / KEV 25 / asset 10; KEV floor 60) |
| Resilience | TTL/LRU cache with single-flight, token-bucket rate limits, retries with jitter, circuit breaker, deadlines |
| Persistence | SQLite triage reports + idempotent fingerprints |
| Observability | OpenTelemetry spans/metrics via OTLP, structured JSON logs, correlation middleware |
| Ops | Health/readiness endpoints, config validation fail-closed, CLI (`serve`, `check`, `token`, `eval`) |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]

# Offline deterministic mode (tests, evals, demos) — no network required
aegis-mcp serve --transport stdio

# Or streamable HTTP (requires JWT auth; see Security)
aegis-mcp serve --transport streamable-http
aegis-mcp check
```

Minimal MCP client configuration (stdio):

```json
{
  "mcpServers": {
    "aegis": {
      "command": "/absolute/path/to/.venv/bin/aegis-mcp",
      "args": ["serve", "--transport", "stdio"],
      "env": { "AEGIS_OFFLINE": "true" }
    }
  }
}
```

## Configuration

All settings are environment-driven via the `AEGIS_` prefix (pydantic-settings) and validated fail-closed at startup.

Key variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `AEGIS_ENVIRONMENT` | `development` | `development` / `test` / `staging` / `production` |
| `AEGIS_TRANSPORT` | `stdio` | `stdio` or `streamable-http` |
| `AEGIS_HOST` / `AEGIS_PORT` | `127.0.0.1` / `8000` | Bind address and port |
| `AEGIS_MCP_PATH` | `/mcp` | Streamable HTTP MCP endpoint path |
| `AEGIS_PUBLIC_URL` | `http://localhost:8000` | Public base URL (JWT audience) |
| `AEGIS_AUTH_MODE` | `local` | `local` (stdio only) or `jwt` |
| `AEGIS_JWT_SECRET` | – | HS256 signing secret (≥ 32 chars) |
| `AEGIS_JWT_ALGORITHMS` | `HS256` | Comma-separated allowlist; `none` is forbidden |
| `AEGIS_JWT_ISSUER` | `https://aegis.local` | Expected issuer |
| `AEGIS_JWT_AUDIENCE` | public URL | Expected audience |
| `AEGIS_JWT_JWKS_URL` | – | JWKS endpoint for RS256/ES256 IdP validation |
| `AEGIS_REQUIRED_SCOPES` | `aegis:read` | Transport-level required scope |
| `AEGIS_LOCAL_SCOPES` | `aegis:read,aegis:triage` | Scopes granted to local stdio principal |
| `AEGIS_ALLOWED_HOSTS` / `AEGIS_ALLOWED_ORIGINS` | localhost defaults | DNS-rebinding / CORS allowlists |
| `AEGIS_READ_RATE_PER_MINUTE` / `AEGIS_READ_BURST` | `60` / `15` | Read limiter defaults |
| `AEGIS_TRIAGE_RATE_PER_MINUTE` / `AEGIS_TRIAGE_BURST` | `10` / `3` | Triage limiter defaults |
| `AEGIS_UPSTREAM_TIMEOUT_SECONDS` / `AEGIS_UPSTREAM_CONNECT_TIMEOUT_SECONDS` | `8` / `3` | Outbound HTTP timeouts |
| `AEGIS_MAX_RETRIES` / `AEGIS_RETRY_BASE_DELAY_SECONDS` / `AEGIS_RETRY_MAX_DELAY_SECONDS` | `3` / `0.15` / `2.0` | Retry policy |
| `AEGIS_CIRCUIT_FAILURE_THRESHOLD` / `AEGIS_CIRCUIT_RESET_SECONDS` | `5` / `30` | Circuit breaker |
| `AEGIS_MAX_UPSTREAM_RESPONSE_BYTES` | `2097152` | Response size cap |
| `AEGIS_NVD_API_KEY` | – | Optional NVD API key |
| `AEGIS_CACHE_TTL_SECONDS` / `AEGIS_KEV_CACHE_TTL_SECONDS` | `300` / `3600` | Cache TTLs |
| `AEGIS_CACHE_MAX_ENTRIES` | `2048` | Cache LRU bound |
| `AEGIS_OTEL_ENABLED` / `AEGIS_OTEL_ENDPOINT` / `AEGIS_OTEL_SERVICE_NAME` / `AEGIS_OTEL_CONSOLE_EXPORT` | – / – / `aegis-mcp` / `false` | OpenTelemetry |
| `AEGIS_SQLITE_PATH` | `data/aegis.db` | Triage report persistence |
| `AEGIS_OFFLINE` | `false` | Deterministic fixture mode |

Copy `.env.example` to `.env` for local defaults. Security invariants that fail startup:

- `streamable-http` **requires** JWT auth (local auth is stdio-only).
- Production requires an `https` public URL and a configured JWT secret/JWKS.
- JWT secrets must be ≥ 32 characters; algorithm allowlist must not include `none`.
- JWKS URLs must use `https` unless localhost.

## Tools

### `lookup_cve`
Enrich one CVE with NVD CVSS, FIRST EPSS, CISA KEV; return deterministic risk score with factor contributions. Scope `aegis:read`.

### `search_vulnerabilities`
Keyword search over NVD with EPSS/KEV enrichment and risk-ranked results; supports CVSS floor and KEV-only filters.

### `scan_packages`
Query OSV.dev for package/version advisory sets (Maven, npm, PyPI, Go, NuGet, RubyGems, crates.io, Packagist, Debian, Ubuntu) and extract fixed versions.

### `triage_incident`
Multi-step workflow: validate → fetch CVE + package intelligence concurrently → correlate aliases → score → prioritize → persist. Idempotent by input fingerprint. Degrades to `partial` with explicit coverage when sources fail or deadline expires.

### `get_incident_report`
Read the latest persisted report for an incident.

### `server_health`
Non-sensitive runtime status (version, transport, offline mode, cache, breakers, readiness).

## Resources

- `aegis://policy/risk` — machine-readable risk model (`risk-v1`).
- `aegis://catalog/sources` — upstream source catalog (NVD, EPSS, KEV, OSV).
- `aegis://server/manifest` — capabilities, scopes, limits, data-handling contract.
- `aegis://incidents/{incident_id}` — persisted triage report.

## Prompts

- `triage_vulnerability` — guided single-CVE assessment with injection guardrails.
- `incident_brief` — audience-specific brief from a persisted report.
- `package_upgrade_plan` — verification-first upgrade plan from an OSV scan.

## Error handling, resilience, security

- Typed public error codes: `AEGIS_INVALID_INPUT`, `AEGIS_FORBIDDEN`, `AEGIS_NOT_FOUND`, `AEGIS_UPSTREAM_ERROR`, `AEGIS_UPSTREAM_CIRCUIT_OPEN`, `AEGIS_DEADLINE_EXCEEDED`, `AEGIS_RATE_LIMITED`.
- Retries with jitter and `Retry-After`; upstream circuit breaker; bounded concurrency; response size caps.
- Token-bucket rate limiting per principal; tool-level scope enforcement on top of transport scope checks.
- Structured JSON logs with redaction and correlation IDs; tool spans + counters + histograms.

## Observability

OpenTelemetry spans and metrics are exported via OTLP (`AEGIS_OTEL_ENDPOINT`). Console span export is available for local demos. See `docs/OPERATIONS.md`.

## Testing, evals, CI

```bash
pytest --cov                 # 171 tests; coverage gate 75%
aegis-mcp eval                # 12-scenario offline eval suite over the real MCP surface
ruff check . && ruff format --check .
mypy                            # strict
```

GitHub Actions: `.github/workflows/ci.yml` (lint/type/test/eval) and `.github/workflows/security.yml` (bandit, pip-audit).

## Docker

```bash
docker compose up --build
# -> MCP server on http://localhost:8000/mcp, OTel collector on :4318
```

## Limitations and closest working alternatives

- **Offline mode is deterministic fixtures** — values are snapshots, not live data; labeled `offline fixture snapshot`.
- **No managed IdP integration in-process** — JWKS validation is implemented; OAuth authorization-server endpoints require an external provider.
- **No horizontal scaling of SQLite** — single-node persistence; move behind a proxy for multi-node.
- **Docker image build could not be verified** in the authoring environment (no Docker daemon available); the `Dockerfile` and compose file are provided and CI will exercise the build path.

## License

MIT — see [LICENSE](LICENSE).

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security](docs/SECURITY.md)
- [Operations](docs/OPERATIONS.md)
- [Development](docs/DEVELOPMENT.md)
- [Security policy](SECURITY.md)
