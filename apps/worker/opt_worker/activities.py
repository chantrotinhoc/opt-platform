"""Activities are stubs in sprint 1; real tool adapters arrive in S4."""
from __future__ import annotations

from temporalio import activity


@activity.defn
async def check_scope(engagement_id: str, target: str, risk: str) -> dict:
    raise NotImplementedError("S3: call API Scope Guard")


@activity.defn
async def run_tool(step: dict, target: str) -> dict:
    raise NotImplementedError("S4: launch sandboxed tool pod and normalise output")
