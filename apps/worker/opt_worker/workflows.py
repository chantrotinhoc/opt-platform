"""Temporal workflow that runs a scan engine step by step (S4).

Each step is an activity executed in a gVisor sandbox pod inside the tenant's
namespace. Before every step the workflow asks the API's Scope Guard again,
because RoE validity and scan windows can change during a long scan.
Agent-initiated medium/high risk steps wait for an `approve` signal.
"""
from __future__ import annotations

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

    @workflow.run
    async def run(self, engine: dict, engagement_id: str, target: str, by_agent: bool) -> list[dict]:
        results: list[dict] = []
        for step in engine["steps"]:
            decision = await workflow.execute_activity(
                check_scope, args=[engagement_id, target, step["risk"]],
                start_to_close_timeout=timedelta(seconds=30))
            if not decision["allowed"]:
                results.append({"step": step["id"], "skipped": decision["reason"]})
                break
            if by_agent and step["risk"] in ("medium", "high"):
                await workflow.wait_condition(lambda s=step["id"]: s in self._approved,
                                              timeout=timedelta(hours=24))
            results.append(await workflow.execute_activity(
                run_tool, args=[step, target],
                start_to_close_timeout=timedelta(hours=2)))
        return results
