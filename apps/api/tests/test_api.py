from fastapi.testclient import TestClient

from opt_api.main import app

client = TestClient(app)


def test_healthz_needs_no_database():
    assert client.get("/healthz").json() == {"status": "ok"}


def test_tenant_header_alone_is_not_accepted():
    # Sprint 1's X-OPT-Tenant header no longer grants anything.
    r = client.get("/api/v1/whoami", headers={"X-OPT-Tenant": "demo-a"})
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"
