"""Gate G1 (part): tenant isolation enforced by PostgreSQL RLS, exercised both
directly as the opt_app role and through the API."""
import os
from datetime import datetime, timedelta, timezone

import psycopg
import pytest
from fastapi.testclient import TestClient

from opt_api.main import app

pytestmark = pytest.mark.db

NOW = datetime.now(timezone.utc)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def A(token):
    return token("demo-a")


@pytest.fixture
def B(token):
    return token("demo-b")


def _app_conn():
    return psycopg.connect(os.environ["OPT_DATABASE_URL"], autocommit=False)


def _engagement(client, headers, name, rules):
    body = {"name": name, "roe_valid_from": (NOW - timedelta(days=1)).isoformat(),
            "roe_valid_to": (NOW + timedelta(days=30)).isoformat(), "rules": rules}
    r = client.post("/api/v1/engagements", json=body, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_unknown_tenant_rejected(client, token):
    assert client.get("/api/v1/whoami", headers=token("nobody-here")).status_code == 403


def test_engagements_are_invisible_across_tenants(client, A, B):
    eid = _engagement(client, A, "iso-a", [{"kind": "domain", "value": "lab.example.vn"}])
    assert eid in [e["id"] for e in client.get("/api/v1/engagements", headers=A).json()]
    assert eid not in [e["id"] for e in client.get("/api/v1/engagements", headers=B).json()]
    r = client.post(f"/api/v1/engagements/{eid}/scope-check",
                    json={"target": "juice.lab.example.vn", "risk": "passive"}, headers=B)
    assert r.status_code == 404


def test_scope_check_end_to_end(client, A):
    eid = _engagement(client, A, "scope-a", [{"kind": "domain", "value": "lab.example.vn"},
                                             {"kind": "domain", "value": "pay.lab.example.vn", "exclude": True}])

    def check(target, risk, agent=False):
        r = client.post(f"/api/v1/engagements/{eid}/scope-check",
                        json={"target": target, "risk": risk, "requested_by_agent": agent}, headers=A)
        assert r.status_code == 200, r.text
        return r.json()

    assert check("juice.lab.example.vn", "low")["allowed"]          # verified in seed
    assert not check("other.lab.example.vn", "low")["allowed"]      # not verified
    assert check("other.lab.example.vn", "passive")["allowed"]      # passive needs no verification
    assert not check("pay.lab.example.vn", "passive")["allowed"]    # excluded
    assert not check("google.com", "passive")["allowed"]            # out of scope
    assert not check("dvwa.lab.example.vn", "low")["allowed"]       # B's verification does not count
    assert not check("https://juice.lab.example.vn", "passive")["allowed"]  # malformed
    assert check("juice.lab.example.vn", "medium", agent=True)["needs_approval"]
    assert client.get("/api/v1/audit/verify", headers=A).json() == {"chain_valid": True}


def test_no_tenant_set_sees_nothing():
    with _app_conn() as conn:
        for table in ["tenant", "engagement", "scope_rule", "target", "finding", "agent_step", "audit_event", "scan"]:
            assert conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0, table


def test_cannot_write_into_another_tenant():
    with _app_conn() as conn:
        conn.execute("SELECT set_config('app.tenant_id', 'demo-a', true)")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("INSERT INTO target (tenant_id, value) VALUES ('demo-b', 'evil.example.vn')")


def test_cannot_move_rows_to_another_tenant():
    with _app_conn() as conn:
        conn.execute("SELECT set_config('app.tenant_id', 'demo-a', true)")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE target SET tenant_id = 'demo-b'")


def test_audit_log_is_append_only():
    with _app_conn() as conn:
        conn.execute("SELECT set_config('app.tenant_id', 'demo-a', true)")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM audit_event")
    with psycopg.connect(os.environ["OPT_ADMIN_DATABASE_URL"]) as owner:
        with pytest.raises(psycopg.errors.RaiseException):
            owner.execute("UPDATE audit_event SET actor = 'x'")


def test_app_role_cannot_create_tenants():
    with _app_conn() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("INSERT INTO tenant (id, name, kms_key_id) VALUES ('evil', 'x', 'k')")


def test_child_rows_cannot_reference_another_tenants_engagement(client, B):
    """FK checks bypass RLS, so the composite (tenant_id, engagement_id) key must
    reject this even for the table owner."""
    eid = _engagement(client, B, "fk-b", [{"kind": "domain", "value": "lab.example.vn"}])
    with psycopg.connect(os.environ["OPT_ADMIN_DATABASE_URL"]) as owner:
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            owner.execute("INSERT INTO scope_rule (tenant_id, engagement_id, kind, value) "
                          "VALUES ('demo-a', %s, 'domain', 'evil.vn')", (eid,))
