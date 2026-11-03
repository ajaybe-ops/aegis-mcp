"""Typed domain errors with stable, non-leaking public error codes."""

from __future__ import annotations

from dataclasses import dataclass


class AegisError(Exception):
    """Base class for anticipated failures that are safe to show to an MCP client."""

    code = "AEGIS_ERROR"
    retryable = False

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def public_message(self) -> str:
        return f"{self.code}: {self.message}"


class InputValidationError(AegisError):
    code = "AEGIS_INVALID_INPUT"


class AuthzError(AegisError):
    code = "AEGIS_FORBIDDEN"


class NotFoundError(AegisError):
    code = "AEGIS_NOT_FOUND"


class StoreError(AegisError):
    code = "AEGIS_STORE_ERROR"


@dataclass
class RateLimitError(AegisError):
    retry_after_seconds: float = 1.0

    code = "AEGIS_RATE_LIMITED"
    retryable = True

    def __init__(self, key: str, retry_after_seconds: float) -> None:
        super().__init__(f"rate limit exceeded for {key}; retry after {retry_after_seconds:.1f}s")
        self.retry_after_seconds = retry_after_seconds


class UpstreamError(AegisError):
    code = "AEGIS_UPSTREAM_ERROR"

    def __init__(
        self,
        provider: str,
        message: str,
        *,
        status_code: int | None = None,
        retryable: bool = True,
        detail: str | None = None,
    ) -> None:
        super().__init__(f"{provider}: {message}", detail=detail)
        self.provider = provider
        self.status_code = status_code
        self.retryable = retryable


class CircuitOpenError(AegisError):
    code = "AEGIS_UPSTREAM_CIRCUIT_OPEN"
    retryable = True

    def __init__(self, provider: str, retry_in_seconds: float) -> None:
        super().__init__(f"{provider}: circuit open; retry in {retry_in_seconds:.1f}s")
        self.provider = provider
        self.retry_in_seconds = retry_in_seconds


class DeadlineExceededError(AegisError):
    code = "AEGIS_DEADLINE_EXCEEDED"
    retryable = True


class ProviderNotFoundError(AegisError):
    code = "AEGIS_UPSTREAM_NOT_FOUND"
