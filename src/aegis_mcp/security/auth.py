"""OAuth 2.1 resource-server token verification and scope enforcement.

Aegis is a resource server, not an authorization server. It validates JWTs issued
by an external IdP using either a shared HS256 secret (local development only) or
a JWKS endpoint (RS256/ES256). The SDK's bearer middleware enforces the baseline
``aegis:read`` scope at the transport boundary; tools enforce finer scopes here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import anyio.to_thread
import jwt
from jwt import PyJWKClient
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken

from ..config import Settings
from ..domain.errors import AuthzError
from ..domain.sanitize import clean_untrusted

_LOCAL_SUBJECT = "local-stdio"


@dataclass(frozen=True)
class Principal:
    subject: str
    scopes: frozenset[str]
    method: str
    issuer: str | None = None
    client_id: str | None = None

    @property
    def limiter_key(self) -> str:
        raw = f"{self.issuer or ''}|{self.client_id or ''}|{self.subject}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _extract_scopes(claims: dict[str, Any]) -> frozenset[str]:
    scopes: set[str] = set()
    raw_scope = claims.get("scope")
    if isinstance(raw_scope, str):
        scopes.update(part for part in raw_scope.split() if part)
    raw_scp = claims.get("scp")
    if isinstance(raw_scp, str):
        scopes.update(part for part in raw_scp.split() if part)
    elif isinstance(raw_scp, list):
        scopes.update(part for part in raw_scp if isinstance(part, str))
    return frozenset(item[:128] for item in scopes if item)


class JWTTokenVerifier:
    """Implements the SDK ``TokenVerifier`` protocol; returns None on any failure."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._algorithms = settings.jwt_algorithms_list
        self._audience = settings.audience
        self._issuer = settings.jwt_issuer
        self._leeway = settings.jwt_leeway_seconds
        self._secret = settings.jwt_secret.get_secret_value() if settings.jwt_secret else None
        self._jwks = (
            PyJWKClient(settings.jwt_jwks_url, cache_keys=True, lifespan=300) if settings.jwt_jwks_url else None
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token or len(token) > 8_192:
            return None
        try:
            key: Any
            if self._jwks is not None:
                signing_key = await anyio.to_thread.run_sync(self._jwks.get_signing_key_from_jwt, token)
                key = signing_key.key
            else:
                key = self._secret
            claims = jwt.decode(
                token,
                key,
                algorithms=self._algorithms,
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError:
            return None
        except Exception:
            # A JWKS fetch/parse failure must fail closed, never crash the transport.
            return None

        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            return None
        audience_claim = claims.get("aud")
        issued_for: str | None = None
        if isinstance(audience_claim, str) and audience_claim == self._audience:
            issued_for = audience_claim
        elif isinstance(audience_claim, list) and self._audience in audience_claim:
            issued_for = self._audience
        client_id = claims.get("client_id")
        return AccessToken(
            token=token,
            client_id=str(client_id) if client_id else subject,
            scopes=sorted(_extract_scopes(claims)),
            expires_at=int(claims["exp"]) if "exp" in claims else None,
            resource=issued_for,
            subject=subject,
            claims=claims,
        )


class AuthService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self.verifier: JWTTokenVerifier | None = JWTTokenVerifier(settings) if settings.auth_mode == "jwt" else None

    def current_principal(self) -> Principal:
        token = get_access_token()
        if token is not None:
            subject = token.subject or token.client_id
            return Principal(
                subject=clean_untrusted(subject, max_length=128),
                scopes=frozenset(token.scopes),
                method="jwt",
                issuer=str((token.claims or {}).get("iss") or "") or None,
                client_id=token.client_id,
            )
        if self._settings.auth_mode == "local":
            return Principal(
                subject=_LOCAL_SUBJECT,
                scopes=frozenset(self._settings.local_scopes_list),
                method="local",
                issuer=None,
                client_id=_LOCAL_SUBJECT,
            )
        raise AuthzError("authentication required; present a valid bearer token")

    @staticmethod
    def require(principal: Principal, *required: str) -> None:
        missing = sorted(set(required) - principal.scopes)
        if missing:
            raise AuthzError("missing required scope(s): " + ", ".join(missing))
