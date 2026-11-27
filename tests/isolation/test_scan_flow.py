"""Recon -> findings -> report for one tenant, through the API, with fake tools
(no network). Also checks that scans respect scope, verification and RBAC."""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from opt_api import recon
from opt_api.main import app

pytestmark = pytest.mark.db
NOW = datetime.now(timezone.utc)


@pytest.fixture
def client(monkeypatch):
    calls = []

    def dns(target, ctx):
        calls.append(("dns", target))
        return recon.StepOutput({"addresses": ["10.10.0.5"]})

    def http(target, ctx):
        calls.append(("http", target))
        return recon.StepOutput({"reachable": True}, [
            recon.NewFinding("Dịch vụ web chỉ chạy HTTP, không có HTTPS", "medium", "no-https", cwe="CWE-319"),
            recon.NewFinding("Lộ phiên bản phần mềm máy chủ", "info", "server-version", evidence={"server": "nginx/1.27.4"})])
    monkeypatch.setitem(recon.BUILTIN, "builtin_dns", dns)
    monkeypatch.setitem(recon.BUILTIN, "builtin_http", http)
    with TestClient(app) as c:
        c.calls = calls
        yield c


def _engagement(client, headers, rules=None):
    body = {"name": "scan-flow", "roe_valid_from": (NOW - timedelta(days=1)).isoformat(),
            "roe_valid_to": (NOW + timedelta(days=30)).isoformat(),
            "rules": rules or [{"kind": "domain", "value": "lab.example.vn"}]}
    r = client.post("/api/v1/engagements", json=body, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_recon_to_report_end_to_end(client, token):
    lead, tester, viewer = token("demo-a"), token("demo-a", "opt-tester"), token("demo-a", "opt-viewer")
    eid = _engagement(client, lead)
    r = client.post(f"/api/v1/engagements/{eid}/scans", json={"target": "juice.lab.example.vn"}, headers=tester)
    assert r.status_code == 202, r.text
    sid = r.json()["id"]
    scan = client.get(f"/api/v1/scans/{sid}", headers=viewer).json()  # TestClient runs the task before returning
    assert scan["status"] == "done", scan
    assert [s["step"] for s in scan["steps"] if s.get("ok")] == ["resolve", "http_probe"]
    assert client.calls == [("dns", "juice.lab.example.vn"), ("http", "juice.lab.example.vn")]
    findings = client.get(f"/api/v1/engagements/{eid}/findings", headers=viewer).json()
    assert {f["severity"] for f in findings} == {"medium", "info"}
    md = client.get(f"/api/v1/scans/{sid}/report", headers=viewer)
    assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown")
    assert "Dịch vụ web chỉ chạy HTTP" in md.text and "| Trung bình | 1 |" in md.text
    assert client.get("/api/v1/audit/verify", headers=viewer).json() == {"chain_valid": True}


def test_rescan_updates_findings_instead_of_duplicating(client, token):
    lead = token("demo-a")
    eid = _engagement(client, lead)
    for _ in range(2):
        client.post(f"/api/v1/engagements/{eid}/scans", json={"target": "juice.lab.example.vn"}, headers=lead)
    assert len(client.get(f"/api/v1/engagements/{eid}/findings", headers=lead).json()) == 2


@pytest.mark.parametrize("target,reason", [
    ("other.lab.example.vn", "verified"),        # in scope but not verified
    ("google.com", "verified"),                  # out of scope and not verified
    ("dvwa.lab.example.vn", "verified"),         # verified only for tenant B
])
def test_scan_refused_without_verified_in_scope_target(client, token, target, reason):
    lead = token("demo-a")
    eid = _engagement(client, lead)
    r = client.post(f"/api/v1/engagements/{eid}/scans", json={"target": target}, headers=lead)
    assert r.status_code == 403 and reason in r.json()["detail"]
    assert client.calls == []


def test_excluded_target_is_refused_even_if_verified(client, token):
    lead = token("demo-a")
    eid = _engagement(client, lead, [{"kind": "domain", "value": "lab.example.vn"},
                                     {"kind": "domain", "value": "juice.lab.example.vn", "exclude": True}])
    r = client.post(f"/api/v1/engagements/{eid}/scans", json={"target": "juice.lab.example.vn"}, headers=lead)
    assert r.status_code == 403 and client.calls == []


def test_other_tenant_cannot_see_or_start_scans(client, token):
    a, b = token("demo-a"), token("demo-b")
    eid = _engagement(client, a)
    sid = client.post(f"/api/v1/engagements/{eid}/scans", json={"target": "juice.lab.example.vn"}, headers=a).json()["id"]
    assert client.get(f"/api/v1/scans/{sid}", headers=b).status_code == 404
    assert client.get(f"/api/v1/scans/{sid}/report", headers=b).status_code == 404
    assert client.get(f"/api/v1/engagements/{eid}/findings", headers=b).json() == []
    assert client.post(f"/api/v1/engagements/{eid}/scans", json={"target": "juice.lab.example.vn"},
                       headers=b).status_code == 404
