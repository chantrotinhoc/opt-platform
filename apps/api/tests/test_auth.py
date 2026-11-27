"""Token verification and RBAC. None of these reach the database."""
import time

import pytest
from fastapi.testclient import TestClient

from opt_api import auth
from opt_api.main import app

client = TestClient(app)
ENGAGEMENT = {"name": "x", "roe_valid_from": "2026-12-01T00:00:00+07:00",
              "roe_valid_to": "2026-12-31T00:00:00+07:00", "rules": [{"kind": "domain", "value": "lab.example.vn"}]}


def status(headers, path="/api/v1/whoami"):
    return client.get(path, headers=headers).status_code


def test_missing_token_is_401():
    assert status({}) == 401
    assert status({"Authorization": "Basic YTpi"}) == 401


def test_token_signed_by_another_key_is_401(token):
    rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert status(token("demo-a", key=other)) == 401


@pytest.mark.parametrize("claims", [
    {"exp": int(time.time()) - 120},
    {"aud": "account"},
    {"iss": "https://evil.example/realms/opt"},
])
def test_expired_or_foreign_tokens_are_401(token, claims):
    assert status(token("demo-a", **claims)) == 401


def test_unsigned_token_is_401():
    import jwt
    now = int(time.time())
    t = jwt.encode({"iss": "https://sso.test/realms/opt", "aud": "opt-api", "sub": "x", "iat": now, "exp": now + 60,
                    "groups": ["tenant-demo-a"], "realm_access": {"roles": ["opt-owner"]}}, None, algorithm="none")
    assert status({"Authorization": f"Bearer {t}"}) == 401


@pytest.mark.parametrize("groups", [[], ["tenant-demo-a", "tenant-demo-b"], ["admins"], ["tenant-../etc"]])
def test_token_must_name_exactly_one_valid_tenant(token, groups):
    assert status(token(groups=groups)) == 403


def test_token_without_opt_role_is_403(token):
    assert status(token("demo-a", role="offline_access")) == 403


def test_highest_role_wins_and_group_path_is_accepted():
    p = auth.principal_from_claims({"sub": "u1", "groups": ["/tenant-demo-a"],
                                    "realm_access": {"roles": ["opt-viewer", "opt-lead", "uma_authorization"]}})
    assert (p.tenant, p.role, p.username) == ("demo-a", auth.Role.LEAD, "u1")


@pytest.mark.parametrize("role", ["opt-viewer", "opt-tester"])
def test_only_leads_create_engagements(token, role):
    # Rejected by RBAC before any database access.
    assert client.post("/api/v1/engagements", json=ENGAGEMENT, headers=token("demo-a", role=role)).status_code == 403


def test_viewer_cannot_start_scans_or_scope_checks(token):
    h = token("demo-a", role="opt-viewer")
    eid = "00000000-0000-0000-0000-000000000000"
    assert client.post(f"/api/v1/engagements/{eid}/scans", json={"target": "a.lab.example.vn"}, headers=h).status_code == 403
    assert client.post(f"/api/v1/engagements/{eid}/scope-check",
                       json={"target": "a.lab.example.vn", "risk": "passive"}, headers=h).status_code == 403


def test_unconfigured_auth_fails_closed(token, monkeypatch):
    h = token("demo-a")
    monkeypatch.delenv("OPT_OIDC_ISSUER")
    assert status(h) == 503
