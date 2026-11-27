"""OPT API: tenant context from Keycloak tokens, RBAC, engagements, Scope Guard,
scans, findings, reports and audit."""
from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, model_validator

from opt_api import audit, db, recon, report
from opt_api.auth import Principal, Role, require
from opt_api.guard import EngagementNotFound, decide, target_verified
from opt_api.scope import Risk, needs_approval, normalize_target


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    db.close()


app = FastAPI(title="OPT API", version="0.2.0", lifespan=lifespan)


def _member(role: Role):
    """Authenticated principal with at least `role`, whose tenant exists."""
    def dependency(p: Principal = Depends(require(role))) -> Principal:
        with db.tenant_tx(p.tenant) as conn:
            # RLS on `tenant` returns the row only for the tenant itself.
            if conn.execute("SELECT 1 FROM tenant").fetchone() is None:
                raise HTTPException(status_code=403, detail="unknown tenant")
        return p
    return dependency


viewer = _member(Role.VIEWER)
tester = _member(Role.TESTER)
lead = _member(Role.LEAD)


class RuleIn(BaseModel):
    kind: Literal["domain", "cidr"]
    value: str = Field(min_length=1, max_length=253)
    exclude: bool = False


class EngagementIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    roe_valid_from: datetime
    roe_valid_to: datetime
    sensitivity: Literal["public", "internal", "restricted"] = "internal"
    rules: list[RuleIn] = Field(min_length=1)

    @model_validator(mode="after")
    def _dates(self):
        if self.roe_valid_from.tzinfo is None or self.roe_valid_to.tzinfo is None:
            raise ValueError("RoE dates must include a timezone")
        if self.roe_valid_from >= self.roe_valid_to:
            raise ValueError("roe_valid_from must be before roe_valid_to")
        return self


class ScopeCheckIn(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    risk: Risk
    requested_by_agent: bool = False


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
def readyz() -> dict[str, str]:
    with db.pool().connection() as conn:
        conn.execute("SELECT 1")
    return {"status": "ready"}


@app.get("/api/v1/whoami")
def whoami(p: Principal = Depends(viewer)) -> dict[str, str]:
    return {"tenant": p.tenant, "username": p.username, "role": f"opt-{p.role.name.lower()}"}


@app.post("/api/v1/engagements", status_code=201)
def create_engagement(body: EngagementIn, p: Principal = Depends(lead)) -> dict:
    tenant = p.tenant
    with db.tenant_tx(tenant) as conn:
        row = conn.execute(
            "INSERT INTO engagement (tenant_id, name, status, roe_valid_from, roe_valid_to, sensitivity) "
            "VALUES (%s, %s, 'active', %s, %s, %s) RETURNING id",
            (tenant, body.name, body.roe_valid_from, body.roe_valid_to, body.sensitivity)).fetchone()
        for r in body.rules:
            conn.execute(
                "INSERT INTO scope_rule (tenant_id, engagement_id, kind, value, exclude) VALUES (%s, %s, %s, %s, %s)",
                (tenant, row["id"], r.kind, r.value.strip().lower(), r.exclude))
        audit.append(conn, tenant, p.username, "engagement.create", str(row["id"]), body.model_dump())
    return {"id": str(row["id"])}


@app.get("/api/v1/engagements")
def list_engagements(p: Principal = Depends(viewer)) -> list[dict]:
    with db.tenant_tx(p.tenant) as conn:
        rows = conn.execute(
            "SELECT id, name, status, roe_valid_from, roe_valid_to, sensitivity FROM engagement ORDER BY name").fetchall()
    return [{**r, "id": str(r["id"])} for r in rows]


@app.post("/api/v1/engagements/{engagement_id}/scope-check")
def scope_check(engagement_id: UUID, body: ScopeCheckIn, p: Principal = Depends(tester)) -> dict:
    with db.tenant_tx(p.tenant) as conn:
        try:
            _, decision = decide(conn, p.tenant, engagement_id, body.target, body.risk)
        except EngagementNotFound:
            raise HTTPException(status_code=404, detail="engagement not found") from None
        result = {"allowed": decision.allowed, "reason": decision.reason,
                  "needs_approval": decision.allowed and needs_approval(body.risk, body.requested_by_agent)}
        audit.append(conn, p.tenant, ("agent:" if body.requested_by_agent else "") + p.username, "scope.check",
                     str(engagement_id), {"target": body.target, "risk": body.risk.value, **result})
    return result


class ScanIn(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    engine: str = Field(default="lab-recon-v1", max_length=64)


@app.post("/api/v1/engagements/{engagement_id}/scans", status_code=202)
def start_scan(engagement_id: UUID, body: ScanIn, background: BackgroundTasks,
               p: Principal = Depends(tester)) -> dict:
    try:
        engine = recon.load_engine(body.engine)
        target = normalize_target(body.target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    first_risk = Risk(engine["steps"][0]["risk"])
    with db.tenant_tx(p.tenant) as conn:
        try:
            _, decision = decide(conn, p.tenant, engagement_id, target, first_risk)
        except EngagementNotFound:
            raise HTTPException(status_code=404, detail="engagement not found") from None
        if engine.get("requires_verified_target", True) and not target_verified(conn, target):
            decision_reason = "engine requires a verified target"
        elif not decision.allowed:
            decision_reason = decision.reason
        else:
            decision_reason = None
        if decision_reason:
            # Recorded and committed before the 403 below, so denials stay in the audit log.
            audit.append(conn, p.tenant, p.username, "scan.denied", str(engagement_id),
                         {"target": target, "engine": body.engine, "reason": decision_reason})
        else:
            row = conn.execute(
                "INSERT INTO scan (tenant_id, engagement_id, target, engine, requested_by) "
                "VALUES (%s, %s, %s, %s, %s) RETURNING id",
                (p.tenant, engagement_id, target, body.engine, p.username)).fetchone()
            audit.append(conn, p.tenant, p.username, "scan.queued", str(row["id"]),
                         {"engagement": str(engagement_id), "target": target, "engine": body.engine})
    if decision_reason:
        raise HTTPException(status_code=403, detail=decision_reason)
    background.add_task(recon.run_scan, p.tenant, row["id"])
    return {"id": str(row["id"]), "status": "queued"}


def _scan(conn, scan_id: UUID) -> dict:
    s = conn.execute(
        "SELECT id, engagement_id, target, engine, status, requested_by, steps, created_at, finished_at "
        "FROM scan WHERE id = %s", (scan_id,)).fetchone()
    if s is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return s


def _findings(conn, where: str, arg) -> list[dict]:
    return conn.execute(
        "SELECT id, scan_id, target, title, severity, cwe, description, evidence, status, source_tool, created_at "
        f"FROM finding WHERE {where} ORDER BY created_at", (arg,)).fetchall()


def _json(row: dict) -> dict:
    return {k: (str(v) if isinstance(v, UUID) else v) for k, v in row.items()}


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: UUID, p: Principal = Depends(viewer)) -> dict:
    with db.tenant_tx(p.tenant) as conn:
        return _json(_scan(conn, scan_id))


@app.get("/api/v1/engagements/{engagement_id}/findings")
def list_findings(engagement_id: UUID, p: Principal = Depends(viewer)) -> list[dict]:
    with db.tenant_tx(p.tenant) as conn:
        return [_json(f) for f in _findings(conn, "engagement_id = %s", engagement_id)]


@app.get("/api/v1/scans/{scan_id}/report")
def scan_report(scan_id: UUID, format: Literal["md", "json"] = Query(default="md"),
                p: Principal = Depends(viewer)):
    with db.tenant_tx(p.tenant) as conn:
        s = _scan(conn, scan_id)
        e = conn.execute("SELECT name, roe_valid_from, roe_valid_to FROM engagement WHERE id = %s",
                         (s["engagement_id"],)).fetchone()
        findings = _findings(conn, "id IN (SELECT finding_id FROM scan_finding WHERE scan_id = %s)", scan_id)
        audit.append(conn, p.tenant, p.username, "report.view", str(scan_id), {"format": format})
    if format == "json":
        return {"scan": _json(s), "findings": [_json(f) for f in findings]}
    return PlainTextResponse(report.render_markdown(p.tenant, e, s, findings), media_type="text/markdown")


@app.get("/api/v1/audit/verify")
def audit_verify(p: Principal = Depends(viewer)) -> dict[str, bool]:
    with db.tenant_tx(p.tenant) as conn:
        return {"chain_valid": audit.verify_chain(conn, p.tenant)}
