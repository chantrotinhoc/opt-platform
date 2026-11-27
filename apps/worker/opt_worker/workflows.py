"""Temporal workflow that runs a scan engine step by step (S4).

Each step is an activity executed in a gVisor sandbox pod inside the tenant's
namespace. Before every step the workflow asks the API's Scope Guard again,
because RoE validity and scan windows can change during a long scan.
High-risk steps, and medium-risk steps proposed by an agent, wait up to 24h for
an `approve` signal; scope is checked again after approval.
"""
from __future__ import annotations

import asyncio
from datetime import timedelta

from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from opt_worker.activities import check_scope, run_tool


@workflow.defn
class ScanEngineWorkflow:
    def __init__(self) -> None:
        self._approved: set[str] = set()

    @workflow.signal
    def approve(self, step_id: str) -> None:
        self._approved.add(step_id)

    async def _scope(self, engagement_id: str, target: str, risk: str) -> dict:
        return await workflow.execute_activity(
            check_scope, args=[engagement_id, target, risk],
            start_to_close_timeout=timedelta(seconds=30))

    @workflow.run
    async def run(self, engine: dict, engagement_id: str, target: str, by_agent: bool) -> list[dict]:
        results: list[dict] = []
        for step in engine["steps"]:
            decision = await self._scope(engagement_id, target, step["risk"])
            if not decision["allowed"]:
                results.append({"step": step["id"], "skipped": decision["reason"]})
                break
            if needs_approval(step["risk"], by_agent):
                try:
                    await workflow.wait_condition(lambda s=step["id"]: s in self._approved,
                                                  timeout=timedelta(hours=24))
                except asyncio.TimeoutError:
                    results.append({"step": step["id"], "skipped": "approval timed out after 24h"})
                    break
                # RoE or the scan window may have changed while waiting.
                decision = await self._scope(engagement_id, target, step["risk"])
                if not decision["allowed"]:
                    results.append({"step": step["id"], "skipped": decision["reason"]})
                    break
            results.append(await workflow.execute_activity(
                run_tool, args=[step, target],
                start_to_close_timeout=timedelta(hours=2)))
        return results


def needs_approval(risk: str, by_agent: bool) -> bool:
    """Same rule as opt_api.scope.needs_approval: high risk always, medium when an agent asked."""
    return risk == "high" or (by_agent and risk == "medium")
