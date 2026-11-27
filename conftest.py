"""Shared test setup: a local signing key stands in for Keycloak.

Tests get tokens from the `token` fixture; the API verifies them with the
public half of a key generated once per session.
"""
import time
import uuid

import pytest

ISSUER = "https://sso.test/realms/opt"


@pytest.fixture(scope="session")
def _signing_key():
    rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def _oidc(request, monkeypatch):
    try:
        from opt_api import auth
    except ImportError:  # suites that do not use the API (e.g. the worker job)
        yield
        return
    key = request.getfixturevalue("_signing_key")
    monkeypatch.setenv("OPT_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("OPT_OIDC_AUDIENCE", "opt-api")
    monkeypatch.setattr(auth, "signing_key", lambda token, url: key.public_key())
    yield


@pytest.fixture
def token(_signing_key):
    """token(tenant, role="opt-lead", **claims) -> Authorization headers."""
    import jwt

    def make(tenant=None, role="opt-lead", *, groups=None, key=None, **claims):
        now = int(time.time())
        body = {"iss": ISSUER, "aud": "opt-api", "sub": str(uuid.uuid4()), "iat": now, "exp": now + 300,
                "preferred_username": f"{role}@{tenant}",
                "groups": groups if groups is not None else ([f"tenant-{tenant}"] if tenant else []),
                "realm_access": {"roles": [role] if role else []}}
        body.update(claims)
        return {"Authorization": "Bearer " + jwt.encode(body, key or _signing_key, algorithm="RS256")}
    return make
