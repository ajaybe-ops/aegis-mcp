# Operations

## Service lifecycle

```bash
aegis-mcp serve --transport stdio      # default
aegis-mcp serve --transport streamable-http
aegis-mcp check                         # non-secret config summary (CI smoke check)
aegis-mcp token --subject developer     # dev JWT minting (never in production)
aegis-mcp eval                          # offline eval suite
```

## Health endpoints (streamable-http)

- `GET /healthz` → liveness: `{"status":"ok","service":"aegis-mcp","version":"..."}`
- `GET /readyz` → readiness: store connectivity check, `503` when not ready.

Both are intentionally unauthenticated and contain no secrets.

## Observability

- OpenTelemetry: spans for tools (`tool.<name>`), metrics `aegis.tool.calls/duration`, `aegis.upstream.*`, `aegis.cache.*`, `aegis.ratelimit.*`, `aegis.auth.*`, histograms `aegis.triage.*`.
- OTLP export via `AEGIS_OTEL_ENDPOINT`; console span export via `AEGIS_OTEL_CONSOLE_EXPORT`.
- Structured JSON logs via `AEGIS_LOG_FORMAT=json`; redaction applied.

## Persistence

SQLite at `AEGIS_SQLITE_PATH` (default `data/aegis.db`); reports keyed by incident id with input fingerprints for idempotent reuse.

## Rate limits and tuning

Read: `AEGIS_READ_RATE_PER_MINUTE` (60) / burst (15). Triage: `AEGIS_TRIAGE_RATE_PER_MINUTE` (10) / burst (3).

## Deployment

See `Dockerfile`, `docker-compose.yml`, and `.env.example`. The compose stack runs the server plus an OpenTelemetry collector.

## Troubleshooting

- `invalid configuration` from `aegis-mcp check` → inspect output; fail-closed invariants (HTTP + local auth, production TLS, secret length, algorithms).
- Tool errors carry typed codes; retry with backoff for `AEGIS_RATE_LIMITED`, `AEGIS_UPSTREAM_ERROR`, `AEGIS_DEADLINE_EXCEEDED`.
- Partial reports (`status: partial`) indicate degraded coverage — inspect `partial_failures` and re-run with a larger deadline.

## Limitations

- Single-node SQLite.
- No built-in IdP authorization server; external IdP supplies JWTs.
