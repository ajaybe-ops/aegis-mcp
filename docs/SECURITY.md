# Security

See the top-level [SECURITY.md](../SECURITY.md) for reporting policy and threat-model summary, and [docs/SECURITY.md](SECURITY.md) for design-level controls.

## Design-level controls implemented

1. **Fail-closed configuration** — invalid transport/auth combinations raise at startup.
2. **JWT validation** — signature, issuer, audience, expiry, required claims; algorithm allowlist; `none` forbidden; JWKS https-only (localhost excepted).
3. **Scope enforcement** — transport-required scopes plus per-tool scopes; typed `AEGIS_FORBIDDEN` denials.
4. **Input validation** — allowlist regexes for CVE/incident/package/version/asset; length caps; control-char/ANSI/bidi/zero-width stripping; URL allowlist.
5. **Prompt injection resistance** — untrusted content never executed; prompt guardrails; sanitized text only.
6. **Secret handling** — `SecretStr`, redaction, secret-free health/manifest outputs, no secrets in resources.
7. **Rate limits / resilience** — token bucket, retries with jitter, circuit breaker, deadlines, size caps.

## Known limitations

- Local auth is development-grade (stdio only).
- JWT HS256 secret-based validation is for environments that can protect the secret; JWKS supported for IdP-based deployments.
- Single-node persistence.
