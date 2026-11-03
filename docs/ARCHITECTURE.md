# Aegis MCP — production-oriented MCP server for vulnerability intelligence and agentic incident triage.

## 1. Purpose

Aegis exposes a secure, deterministic, and observable Model Context Protocol surface for
vulnerability intelligence and agentic incident response, backed by free public feeds
(NVD, FIRST EPSS, CISA KEV, OSV.dev).

## 2. High-level design

```
Agent / MCP client
        │  stdio | streamable HTTP (JWT bearer)
        ▼
┌────────────────────────────┐
│ Aegis MCP server           │
│  tools / resources / prompts│
│  auth (JWT/local)           │
│  rate limits, guard        │
│  cache, TTL + single flight│
│  triage workflow           │
│  store (SQLite)            │
└─────────────┬──────────────┘
              │ allowlisted outbound
              ▼
   NVD · FIRST EPSS · CISA KEV · OSV.dev
```

Key modules:

- `src/aegis_mcp/server.py` — runtime wiring, lifespan, health, HTTP app.
- `src/aegis_mcp/tools/`, `resources/`, `prompts/` — MCP surface.
- `src/aegis_mcp/workflows/triage.py` — multi-step triage.
- `src/aegis_mcp/intel/` — upstream clients + orchestration + fixtures.
- `src/aegis_mcp/domain/` — models, risk, sanitize, errors.
- `src/aegis_mcp/security/` — auth, guard, limits.
- `src/aegis_mcp/infra/` — cache, logging, store, telemetry.

## 3. Risk model

Deterministic additive model `risk-v1` with transparent factor contributions and KEV floor.

## 4. Security posture

Fail-closed config, JWT validation, scope enforcement, sanitization, rate limits, redaction.

## 5. Observability

OpenTelemetry + structured logs.

## 6. Testing and evaluation

pytest suite (unit + E2E), offline eval suite over real MCP surface.

## 7. Deployment

Docker / compose / CI.

## 8. Status and limitations

Beta; offline fixtures; single-node store; IdP integration external.
