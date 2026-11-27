"""Authentication (Keycloak OIDC access tokens) and role-based access control.

Every API call carries `Authorization: Bearer <access token>` issued by the
`opt` realm. The API never trusts a tenant id sent by the client: the tenant
comes from the token's `groups` claim (exactly one group named `tenant-<id>`),
and the role from `realm_access.roles`.

Configuration (environment):
    OPT_OIDC_ISSUER     expected `iss`, e.g. https://sso.opt.itstar.vn/realms/opt
    OPT_OIDC_AUDIENCE   expected `aud` (default: opt-api)
    OPT_OIDC_JWKS_URL   where to fetch signing keys (default: <issuer>/protocol/openid-connect/certs)
"""
from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum

import jwt
from fastapi import Depends, Header, HTTPException

TENANT_GROUP_PREFIX = "tenant-"
_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
_ALGORITHMS = ["RS256", "PS256", "ES256"]


class Role(IntEnum):
    """Ordered: each role can do everything the roles below it can."""
    VIEWER = 1   # read engagements, findings, reports
    TESTER = 2   # start scans, run scope checks
    LEAD = 3     # create engagements, approve medium-risk steps
    OWNER = 4    # tenant administration


_ROLE_NAMES = {f"opt-{r.name.lower()}": r for r in Role}


@dataclass(frozen=True)
class Principal:
    subject: str
    username: str
    tenant: str
    role: Role


def _settings() -> tuple[str, str, str]:
    issuer = os.environ.get("OPT_OIDC_ISSUER", "").rstrip("/")
    if not issuer:
        raise HTTPException(status_code=503, detail="authentication is not configured")
    audience = os.environ.get("OPT_OIDC_AUDIENCE", "opt-api")
    jwks_url = os.environ.get("OPT_OIDC_JWKS_URL") or f"{issuer}/protocol/openid-connect/certs"
    return issuer, audience, jwks_url


_jwks_clients: dict[str, jwt.PyJWKClient] = {}


def _jwks_signing_key(token: str, jwks_url: str):
    client = _jwks_clients.get(jwks_url)
    if client is None:
        client = _jwks_clients[jwks_url] = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=300, timeout=5)
    return client.get_signing_key_from_jwt(token).key


# Replaced in tests with a function that returns a local public key.
signing_key: Callable[[str, str], object] = _jwks_signing_key


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status_code=401, detail=detail, headers={"WWW-Authenticate": "Bearer"})


def decode(token: str) -> dict:
    issuer, audience, jwks_url = _settings()
    try:
        key = signing_key(token, jwks_url)
        return jwt.decode(token, key, algorithms=_ALGORITHMS, audience=audience, issuer=issuer,
                          options={"require": ["exp", "iat", "iss", "aud", "sub"]}, leeway=30)
    except jwt.PyJWKClientError:
        raise HTTPException(status_code=503, detail="identity provider unavailable") from None
    except jwt.InvalidTokenError:
        raise _unauthorized("invalid token") from None


def principal_from_claims(claims: dict) -> Principal:
    groups = claims.get("groups") or []
    tenants = sorted({g.lstrip("/").removeprefix(TENANT_GROUP_PREFIX) for g in groups
                      if isinstance(g, str) and g.lstrip("/").startswith(TENANT_GROUP_PREFIX)})
    if len(tenants) != 1:
        raise HTTPException(status_code=403, detail="token must name exactly one tenant")
    tenant = tenants[0]
    if not _TENANT_RE.fullmatch(tenant):
        raise HTTPException(status_code=403, detail="invalid tenant id")
    roles = [_ROLE_NAMES[r] for r in (claims.get("realm_access") or {}).get("roles", []) if r in _ROLE_NAMES]
    if not roles:
        raise HTTPException(status_code=403, detail="no OPT role")
    return Principal(subject=claims["sub"], username=claims.get("preferred_username") or claims["sub"],
                     tenant=tenant, role=max(roles))


def current_principal(authorization: str | None = Header(default=None)) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise _unauthorized("missing bearer token")
    return principal_from_claims(decode(authorization[7:].strip()))


def require(role: Role) -> Callable[..., Principal]:
    def dependency(p: Principal = Depends(current_principal)) -> Principal:
        if p.role < role:
            raise HTTPException(status_code=403, detail=f"requires role opt-{role.name.lower()}")
        return p
    return dependency
