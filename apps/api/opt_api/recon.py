"""MVP scan runner: executes an engine's built-in steps for one target.

Sprint 4 moves execution to Temporal workers in gVisor sandboxes. Until then
the API runs the two built-in, low-impact steps itself (DNS resolution and a
plain HTTP probe) so a tenant can go from recon to findings to report.

Safety rules kept from the design:
- the engine must allow the target (verified target when `requires_verified_target`);
- every step is re-checked by the Scope Guard right before it runs;
- HIGH-risk steps never run here (they need approval, which lands in S6);
- the HTTP probe follows no redirects, so it never leaves the approved host.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

import httpx
import yaml

from opt_api import audit, db
from opt_api.guard import decide
from opt_api.scope import Risk, needs_approval

log = logging.getLogger("opt.recon")

_ENGINE_ID_RE = re.compile(r"^[a-z0-9-]+-v[0-9]+$")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_VERSION_RE = re.compile(r"\d+\.\d+")
HTTP_TIMEOUT = 5.0     # per request
TOTAL_BUDGET = 15.0    # all requests of one probe together
MAX_BODY = 65536       # bytes of body kept from any response


def engines_dir() -> Path:
    if env := os.environ.get("OPT_ENGINES_DIR"):
        return Path(env)
    return Path(__file__).resolve().parents[3] / "engines"  # repository checkout


def load_engine(engine_id: str) -> dict:
    if not _ENGINE_ID_RE.fullmatch(engine_id):
        raise ValueError("invalid engine id")
    path = engines_dir() / f"{engine_id}.yaml"
    if not path.is_file():
        raise ValueError(f"unknown engine {engine_id}")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@dataclass
class NewFinding:
    title: str
    severity: str
    key: str                     # stable part of the fingerprint
    description: str = ""
    cwe: str | None = None
    evidence: dict = field(default_factory=dict)


@dataclass
class StepOutput:
    data: dict
    findings: list[NewFinding] = field(default_factory=list)


def _builtin_dns(target: str, _ctx: dict) -> StepOutput:
    infos = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
    addresses = sorted({i[4][0] for i in infos})
    return StepOutput({"addresses": addresses})


@dataclass
class Probe:
    """What the probe keeps from one response: never more than MAX_BODY bytes of body."""
    status: int
    headers: httpx.Headers
    url: str
    body: str

    @property
    def is_redirect(self) -> bool:
        return self.status in (301, 302, 303, 307, 308) and "location" in self.headers


def _authority(target: str) -> str:
    """Bracket IPv6 literals so the URL authority parses per RFC 3986."""
    return f"[{target}]" if ":" in target else target


async def _read(client: httpx.AsyncClient, url: str) -> Probe:
    async with client.stream("GET", url) as r:
        body = b""
        async for chunk in r.aiter_bytes():
            body += chunk
            if len(body) >= MAX_BODY:
                break
        return Probe(r.status_code, r.headers, str(r.url), body[:MAX_BODY].decode("utf-8", "replace"))


async def _get(client: httpx.AsyncClient, url: str, deadline: float) -> Probe | None:
    """One GET, cancelled outright at the probe deadline.

    httpx timeouts bound each network operation, not the request: a server that
    trickles headers or body bytes could hold a read open indefinitely. The
    wall-clock limit is therefore enforced around connect, headers and body together.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    try:
        return await asyncio.wait_for(_read(client, url), timeout=remaining)
    except (httpx.HTTPError, asyncio.TimeoutError):
        return None


def _redirects_to_https(probe: Probe, target: str) -> bool:
    if not probe.is_redirect:
        return False
    loc = httpx.URL(probe.headers["location"])
    return loc.scheme == "https" and (loc.host or "").lower().rstrip(".") == target.lower()


async def _probe(host: str, headers: dict) -> tuple[Probe | None, Probe | None, bool]:
    """HTTPS (strict, then unverified), then HTTP, all within TOTAL_BUDGET seconds."""
    deadline = time.monotonic() + TOTAL_BUDGET
    opts = {"timeout": HTTP_TIMEOUT, "follow_redirects": False, "headers": headers}
    async with httpx.AsyncClient(**opts) as strict:
        https = await _get(strict, f"https://{host}/", deadline)
    untrusted_tls = False
    if https is None:
        # Lab services often use self-signed certificates: retry without verification
        # and report it, rather than missing the service.
        async with httpx.AsyncClient(**opts, verify=False) as lax:
            https = await _get(lax, f"https://{host}/", deadline)
        untrusted_tls = https is not None
    async with httpx.AsyncClient(**opts) as client:
        http = await _get(client, f"http://{host}/", deadline)
    return https, http, untrusted_tls


def _builtin_http(target: str, _ctx: dict) -> StepOutput:
    findings: list[NewFinding] = []
    headers = {"User-Agent": "OPT-recon/0.2 (+authorised test, see RoE)"}
    host = _authority(target)
    https, http, untrusted_tls = asyncio.run(_probe(host, headers))

    def summary(r: Probe | None) -> dict | None:
        if r is None:
            return None
        m = _TITLE_RE.search(r.body) if "html" in r.headers.get("content-type", "") else None
        return {"status": r.status, "server": r.headers.get("server"),
                "location": r.headers.get("location"), "title": m.group(1).strip()[:200] if m else None}

    data = {"https": summary(https), "http": summary(http)}
    if https is None and http is None:
        return StepOutput({**data, "reachable": False})

    if untrusted_tls:
        findings.append(NewFinding("Chứng chỉ TLS không được tin cậy", "low", "tls-untrusted",
                                   "Máy chủ dùng chứng chỉ tự ký hoặc không hợp lệ.", "CWE-295"))
    if http is not None:
        redirects_to_https = _redirects_to_https(http, target)
        if https is None:
            findings.append(NewFinding("Dịch vụ web chỉ chạy HTTP, không có HTTPS", "medium", "no-https",
                                       "Dữ liệu và phiên đăng nhập truyền không mã hóa.", "CWE-319",
                                       {"http_status": http.status}))
        elif not redirects_to_https:
            findings.append(NewFinding("HTTP không chuyển hướng sang HTTPS", "low", "no-https-redirect",
                                       "Người dùng gõ http:// vẫn dùng kênh không mã hóa.", "CWE-319",
                                       {"http_status": http.status}))

    main = https or http
    h = main.headers
    missing = []
    if https is not None and "strict-transport-security" not in h:
        missing.append("Strict-Transport-Security")
    if "content-security-policy" not in h:
        missing.append("Content-Security-Policy")
    if "x-content-type-options" not in h:
        missing.append("X-Content-Type-Options")
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        missing.append("X-Frame-Options")
    for name in missing:
        findings.append(NewFinding(f"Thiếu header bảo mật {name}", "low" if name != "X-Content-Type-Options" else "info",
                                   f"missing-header-{name.lower()}", "Header phòng thủ phía trình duyệt chưa được bật.",
                                   "CWE-693", {"url": main.url}))
    server = h.get("server", "")
    if _VERSION_RE.search(server):
        findings.append(NewFinding("Lộ phiên bản phần mềm máy chủ", "info", "server-version",
                                   "Header Server tiết lộ phiên bản, giúp kẻ tấn công chọn lỗ hổng.", "CWE-200",
                                   {"server": server}))
    return StepOutput({**data, "reachable": True}, findings)


BUILTIN: dict[str, Callable[[str, dict], StepOutput]] = {
    "builtin_dns": _builtin_dns,
    "builtin_http": _builtin_http,
}


def _fingerprint(tool: str, target: str, key: str) -> str:
    return hashlib.sha256(f"{tool}|{target}|{key}".encode()).hexdigest()


def _save_findings(conn, tenant: str, engagement_id, scan_id, tool: str, target: str,
                   findings: list[NewFinding]) -> None:
    for f in findings:
        row = conn.execute(
            "INSERT INTO finding (tenant_id, engagement_id, scan_id, target, title, severity, description, cwe, "
            "evidence, fingerprint, source_tool) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (tenant_id, engagement_id, fingerprint) DO UPDATE SET scan_id = EXCLUDED.scan_id, "
            "evidence = EXCLUDED.evidence, severity = EXCLUDED.severity RETURNING id",
            (tenant, engagement_id, scan_id, target, f.title, f.severity, f.description, f.cwe,
             json.dumps(f.evidence), _fingerprint(tool, target, f.key), tool)).fetchone()
        conn.execute("INSERT INTO scan_finding (tenant_id, scan_id, finding_id) VALUES (%s, %s, %s) "
                     "ON CONFLICT DO NOTHING", (tenant, scan_id, row["id"]))


def run_scan(tenant: str, scan_id: UUID | str) -> None:
    """Runs a queued scan to completion. Never raises: failures end in status 'failed'."""
    try:
        _run(tenant, scan_id)
    except Exception:  # noqa: BLE001 - background task: record, do not crash the worker thread
        log.exception("scan %s failed", scan_id)
        with db.tenant_tx(tenant) as conn:
            conn.execute("UPDATE scan SET status = 'failed', finished_at = now() WHERE id = %s", (scan_id,))
            audit.append(conn, tenant, "system", "scan.failed", str(scan_id), {})


def _run(tenant: str, scan_id: UUID | str) -> None:
    with db.tenant_tx(tenant) as conn:
        s = conn.execute("UPDATE scan SET status = 'running' WHERE id = %s AND status = 'queued' "
                         "RETURNING engagement_id, target, engine", (scan_id,)).fetchone()
    if s is None:
        return
    engine = load_engine(s["engine"])
    results: list[dict] = []
    failed: set[str] = set()
    ctx: dict = {}
    for step in engine["steps"]:
        sid, risk = step["id"], Risk(step["risk"])
        if failed.intersection(step.get("needs", [])):
            results.append({"step": sid, "skipped": "a required step failed"})
            failed.add(sid)
            continue
        with db.tenant_tx(tenant) as conn:
            target, decision = decide(conn, tenant, s["engagement_id"], s["target"], risk)
            audit.append(conn, tenant, "system", "scope.check", str(s["engagement_id"]),
                         {"scan": str(scan_id), "step": sid, "target": target, "risk": risk.value,
                          "allowed": decision.allowed, "reason": decision.reason})
        if not decision.allowed:
            results.append({"step": sid, "skipped": decision.reason})
            break
        if needs_approval(risk, requested_by_agent=False):
            results.append({"step": sid, "skipped": "needs approval (not available before S6)"})
            break
        fn = BUILTIN.get(step["tool"])
        if fn is None:
            results.append({"step": sid, "skipped": f"tool {step['tool']} runs on workers from S4"})
            continue
        try:
            out = fn(target, ctx)
        except Exception as exc:  # noqa: BLE001 - a failing tool ends that step, not the scan
            results.append({"step": sid, "error": type(exc).__name__})
            failed.add(sid)
            continue
        ctx[sid] = out.data
        with db.tenant_tx(tenant) as conn:
            _save_findings(conn, tenant, s["engagement_id"], scan_id, step["tool"], target, out.findings)
            audit.append(conn, tenant, "system", "scan.step", str(scan_id),
                         {"step": sid, "tool": step["tool"], "findings": len(out.findings)})
        results.append({"step": sid, "ok": True, "data": out.data, "findings": len(out.findings)})
    with db.tenant_tx(tenant) as conn:
        conn.execute("UPDATE scan SET status = 'done', steps = %s, finished_at = now() WHERE id = %s",
                     (json.dumps(results), scan_id))
        audit.append(conn, tenant, "system", "scan.done", str(scan_id), {"steps": len(results)})
