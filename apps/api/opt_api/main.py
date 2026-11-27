"""OPT API entrypoint. Sprint 1 ships health and the tenant context only."""
from __future__ import annotations

import re

from fastapi import Depends, FastAPI, Header, HTTPException

app = FastAPI(title="OPT API", version="0.1.0")

_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")


def tenant_context(x_opt_tenant: str = Header(...)) -> str:
    """Placeholder until Keycloak tokens land (S2): the tenant comes from a
    verified token claim, never from a client header, in production. The value is
    set as `app.tenant_id` on the DB session so PostgreSQL RLS applies."""
    if not _TENANT_RE.fullmatch(x_opt_tenant):
        raise HTTPException(status_code=400, detail="invalid tenant id")
    return x_opt_tenant


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/whoami")
def whoami(tenant: str = Depends(tenant_context)) -> dict[str, str]:
    return {"tenant": tenant}
