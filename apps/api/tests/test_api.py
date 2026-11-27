from fastapi.testclient import TestClient

from opt_api.main import app

client = TestClient(app)


def test_healthz_needs_no_database():
    assert client.get("/healthz").json() == {"status": "ok"}


def test_tenant_header_validated_before_database():
    assert client.get("/api/v1/whoami", headers={"X-OPT-Tenant": "../etc"}).status_code == 400
    assert client.get("/api/v1/whoami").status_code == 422
