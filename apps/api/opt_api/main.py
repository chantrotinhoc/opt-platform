"""OPT API (sprint 1): tenant context, engagements, Scope Guard, audit."""
from __future__ import annotations

import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, model_validator

from opt_api import audit, db
from opt_api.scope import Engagement, Risk, ScopeRule, evaluate, needs_approval, normalize_target

_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    db.close()


app = FastAPI(title="OPT API", version="0.1.0", lifespan=lifespan)


def tenant_context(x_opt_tenant: str = Header(...)) -> str:
    """Sprint 1 placeholder: the tenant comes from a header. From S2 it comes from
    a verified Keycloak token claim and this header is ignored."""
    if not _TENANT_RE.fullmatch(x_opt_tenant):
        raise HTTPException(status_code=400, detail="invalid tenant id")
    return x_opt_tenant


def existing_tenant(tenant: str = Depends(tenant_context)) -> str:
    with db.tenant_tx(tenant) as conn:
        # RLS on `tenant` returns the row only for the tenant itself.
        if conn.execute("SELECT 1 FROM tenant").fetchone() is None:
            raise HTTPException(status_code=403, detail="unknown tenant")
    return tenant


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
def whoami(tenant: str = Depends(existing_tenant)) -> dict[str, str]:
    return {"tenant": tenant}


@app.post("/api/v1/engagements", status_code=201)
def create_engagement(body: EngagementIn, tenant: str = Depends(existing_tenant)) -> dict:
    with db.tenant_tx(tenant) as conn:
        row = conn.execute(
            "INSERT INTO engagement (tenant_id, name, status, roe_valid_from, roe_valid_to, sensitivity) "
            "VALUES (%s, %s, 'active', %s, %s, %s) RETURNING id",
            (tenant, body.name, body.roe_valid_from, body.roe_valid_to, body.sensitivity)).fetchone()
        for r in body.rules:
            conn.execute(
                "INSERT INTO scope_rule (tenant_id, engagement_id, kind, value, exclude) VALUES (%s, %s, %s, %s, %s)",
                (tenant, row["id"], r.kind, r.value.strip().lower(), r.exclude))
        audit.append(conn, tenant, "api", "engagement.create", str(row["id"]), body.model_dump())
    return {"id": str(row["id"])}


@app.get("/api/v1/engagements")
def list_engagements(tenant: str = Depends(existing_tenant)) -> list[dict]:
    with db.tenant_tx(tenant) as conn:
        rows = conn.execute(
            "SELECT id, name, status, roe_valid_from, roe_valid_to, sensitivity FROM engagement ORDER BY name").fetchall()
    return [{**r, "id": str(r["id"])} for r in rows]


@app.post("/api/v1/engagements/{engagement_id}/scope-check")
def scope_check(engagement_id: UUID, body: ScopeCheckIn, tenant: str = Depends(existing_tenant)) -> dict:
    now = datetime.now(timezone.utc)
    with db.tenant_tx(tenant) as conn:
        e = conn.execute(
            "SELECT status, roe_valid_from, roe_valid_to FROM engagement WHERE id = %s",
            (engagement_id,)).fetchone()
        if e is None:  # also the answer for another tenant's engagement (RLS)
            raise HTTPException(status_code=404, detail="engagement not found")
        rules = [ScopeRule(r["kind"], r["value"], r["exclude"]) for r in conn.execute(
            "SELECT kind, value, exclude FROM scope_rule WHERE engagement_id = %s", (engagement_id,))]
        try:
            target = normalize_target(body.target)
            verified = conn.execute(
                "SELECT 1 FROM target WHERE value = %s AND verified_at > now() - interval '30 days'",
                (target,)).fetchone() is not None
        except ValueError:
            target, verified = body.target, False
        eng = Engagement(tenant, e["roe_valid_from"], e["roe_valid_to"], rules,
                         locked=e["status"] in ("locked", "closed"))
        decision = evaluate(eng, target, body.risk, now, verified)
        result = {"allowed": decision.allowed, "reason": decision.reason,
                  "needs_approval": decision.allowed and needs_approval(body.risk, body.requested_by_agent)}
        audit.append(conn, tenant, "agent" if body.requested_by_agent else "api", "scope.check",
                     str(engagement_id), {"target": body.target, "risk": body.risk.value, **result})
    return result


@app.get("/api/v1/audit/verify")
def audit_verify(tenant: str = Depends(existing_tenant)) -> dict[str, bool]:
    with db.tenant_tx(tenant) as conn:
        return {"chain_valid": audit.verify_chain(conn, tenant)}
