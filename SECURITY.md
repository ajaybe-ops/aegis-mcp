# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x | ✅ |

## Reporting a vulnerability

Please open a GitHub security advisory or contact the maintainers privately. Do **not** open public issues for vulnerabilities.

## Scope

- Authentication bypass (JWT validation, scope enforcement, audience checks).
- Injection into untrusted external content handling (prompt injection, ANSI/bidi/control character handling).
- Path traversal or unsafe persistence behavior.
- Secret handling (redaction, logging, resource exposure).

## Design constraints that are intentional

- Local development authenticates via stdio principal (`local-stdio`) with the configured local scopes; this mode is refused for streamable HTTP.
- `none` JWT algorithm is forbidden; only an explicit allowlist is accepted.
- External content is treated as untrusted data, sanitized, and never executed.
- Production deployments require HTTPS public URLs and configured JWT credentials.
- Rate limits, circuit breakers, and bounded concurrency are fail-safe defaults.

## Threat model summary

| Threat | Mitigation |
| --- | --- |
| Token replay / forged token | HS256 signature + issuer + audience + expiry validation |
| Missing scope | Transport-level required scopes + per-tool scope checks |
| Algorithm downgrade | Allowlist, `none` forbidden |
| Prompt injection from feeds | Sanitization + guardrails in prompts + instructions to treat content as data |
| Log leakage of secrets | Redaction + `SecretStr` + secret-free health/manifest outputs |
| Burst abuse | Token bucket + hard caps |
| Provider outage cascade | Circuit breaker + retry jitter + deadline |
