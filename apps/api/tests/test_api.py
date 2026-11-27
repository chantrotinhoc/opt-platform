from fastapi.testclient import TestClient

from opt_api.main import app

client = TestClient(app)


def test_healthz():
    assert client.get("/healthz").json() == {"status": "ok"}


def test_tenant_header_validated():
    assert client.get("/api/v1/whoami", headers={"X-OPT-Tenant": "itstar"}).json() == {"tenant": "itstar"}
    assert client.get("/api/v1/whoami", headers={"X-OPT-Tenant": "../etc"}).status_code == 400
    assert client.get("/api/v1/whoami").status_code == 422
