"""Built-in recon steps and the report, without network or database."""
import asyncio
import time
from datetime import datetime, timezone

import httpx
import pytest

from opt_api import recon, report


def fake_clients(monkeypatch, handler):
    real = httpx.AsyncClient

    def factory(**kw):
        kw.pop("verify", None)
        return real(transport=httpx.MockTransport(lambda req: handler(req, kw)), **kw)
    monkeypatch.setattr(recon.httpx, "AsyncClient", factory)


def test_http_only_service_reports_missing_tls_and_headers(monkeypatch):
    def handler(req, _):
        if req.url.scheme == "https":
            raise httpx.ConnectError("refused", request=req)
        return httpx.Response(200, headers={"server": "nginx/1.27.4", "content-type": "text/html"},
                              text="<html><title>Lab</title></html>")
    fake_clients(monkeypatch, handler)
    out = recon._builtin_http("juice.lab.example.vn", {})
    keys = {f.key for f in out.findings}
    assert {"no-https", "server-version", "missing-header-content-security-policy"} <= keys
    assert "missing-header-strict-transport-security" not in keys  # HSTS only matters over HTTPS
    assert out.data["http"]["title"] == "Lab"


def test_hardened_https_service_has_no_findings(monkeypatch):
    def handler(req, _):
        if req.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://app.lab.example.vn/"})
        return httpx.Response(200, headers={
            "strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff", "server": "web"})
    fake_clients(monkeypatch, handler)
    assert recon._builtin_http("app.lab.example.vn", {}).findings == []


def test_probe_never_follows_redirects(monkeypatch):
    seen = []

    def handler(req, kw):
        seen.append(str(req.url))
        assert kw["follow_redirects"] is False
        return httpx.Response(302, headers={"location": "https://evil.example.com/"})
    fake_clients(monkeypatch, handler)
    recon._builtin_http("app.lab.example.vn", {})
    assert all("evil.example.com" not in u for u in seen)


def test_unreachable_host_is_not_an_error(monkeypatch):
    def handler(req, _):
        raise httpx.ConnectError("refused", request=req)
    fake_clients(monkeypatch, handler)
    out = recon._builtin_http("down.lab.example.vn", {})
    assert out.data["reachable"] is False and out.findings == []


@pytest.mark.parametrize("bad", ["../etc/passwd", "lab-recon", "LAB-recon-v1", "nope-v9"])
def test_engine_ids_are_validated(bad):
    with pytest.raises(ValueError):
        recon.load_engine(bad)


def test_lab_engine_uses_only_builtin_tools():
    eng = recon.load_engine("lab-recon-v1")
    assert {s["tool"] for s in eng["steps"]} <= set(recon.BUILTIN)


def test_report_orders_by_severity_and_escapes_tables():
    now = datetime(2026, 12, 12, 2, 0, tzinfo=timezone.utc)
    md = report.render_markdown(
        "demo-a", {"name": "Lab | Q4", "roe_valid_from": now, "roe_valid_to": now},
        {"target": "juice.lab.example.vn", "engine": "lab-recon-v1", "status": "done", "requested_by": "alice",
         "created_at": now, "finished_at": now, "steps": [{"step": "resolve", "ok": True},
                                                          {"step": "x", "skipped": "out of scope"}]},
        [{"title": "Info item", "severity": "info", "target": "t", "source_tool": "builtin_http"},
         {"title": "Medium item", "severity": "medium", "target": "t", "source_tool": "builtin_http", "cwe": "CWE-319"}])
    assert md.index("Medium item") < md.index("Info item")
    assert "Lab \\| Q4" in md and "| Trung bình | 1 |" in md and "bỏ qua: out of scope" in md


def test_engines_dir_from_environment_needs_no_repository_layout(monkeypatch, tmp_path):
    # In the container the package sits at /app/opt_api, with no repository parents.
    (tmp_path / "lab-recon-v1.yaml").write_text("id: lab-recon-v1\nsteps: []\n")
    monkeypatch.setenv("OPT_ENGINES_DIR", str(tmp_path))
    monkeypatch.setattr(recon, "__file__", "/app/opt_api/recon.py")
    assert recon.load_engine("lab-recon-v1")["id"] == "lab-recon-v1"


@pytest.mark.parametrize("location,ok", [
    ("https://app.lab.example.vn/", True),
    ("https://APP.lab.example.vn./login", True),
    ("https://app.lab.example.vn.evil.com/", False),   # prefix match would accept this
    ("https://app.lab.example.vn@evil.com/", False),
    ("http://app.lab.example.vn/", False),
])
def test_https_redirect_check_compares_hosts(monkeypatch, location, ok):
    def handler(req, _):
        if req.url.scheme == "http":
            return httpx.Response(301, headers={"location": location})
        return httpx.Response(200, headers={"content-security-policy": "frame-ancestors 'none'",
                                            "strict-transport-security": "max-age=1", "x-content-type-options": "nosniff"})
    fake_clients(monkeypatch, handler)
    keys = {f.key for f in recon._builtin_http("app.lab.example.vn", {}).findings}
    assert ("no-https-redirect" not in keys) == ok


def test_ipv6_targets_are_bracketed(monkeypatch):
    seen = []

    def handler(req, _):
        seen.append(req.url.host)
        return httpx.Response(200)
    fake_clients(monkeypatch, handler)
    recon._builtin_http("fd00::5", {})
    assert seen and set(seen) == {"fd00::5"}


def test_body_read_is_bounded(monkeypatch):
    def handler(req, _):
        return httpx.Response(200, headers={"content-type": "text/html"},
                              content=b"<title>t</title>" + b"x" * (5 * recon.MAX_BODY))
    fake_clients(monkeypatch, handler)
    out = recon._builtin_http("big.lab.example.vn", {})
    assert out.data["http"]["title"] == "t"


def test_probe_stops_when_total_budget_is_spent(monkeypatch):
    calls = []

    def handler(req, _):
        calls.append(req.url.scheme)
        raise httpx.ConnectError("refused", request=req)
    fake_clients(monkeypatch, handler)
    monkeypatch.setattr(recon, "TOTAL_BUDGET", 0)
    recon._builtin_http("slow.lab.example.vn", {})
    assert calls == []


class _Trickle(httpx.AsyncByteStream):
    """A body that sends one byte per interval, forever."""
    def __init__(self, interval):
        self.interval = interval

    async def __aiter__(self):
        while True:
            await asyncio.sleep(self.interval)
            yield b"x"


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_deadline_holds_against_slow_servers(monkeypatch, phase):
    """Each read stays under the per-operation timeout, but the probe still ends on time."""
    async def handler(req, _):
        if phase == "headers":
            await asyncio.sleep(30)
        return httpx.Response(200, stream=_Trickle(0.05))
    fake_clients(monkeypatch, handler)
    monkeypatch.setattr(recon, "TOTAL_BUDGET", 0.5)
    started = time.monotonic()
    out = recon._builtin_http("slow.lab.example.vn", {})
    assert time.monotonic() - started < 2
    assert out.data["reachable"] is False
