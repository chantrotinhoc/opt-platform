"""Runs the scan workflow in Temporal's time-skipping test server with fake activities."""
import os
import uuid

import pytest

pytest.importorskip("temporalio")
from temporalio import activity  # noqa: E402
from temporalio.testing import WorkflowEnvironment  # noqa: E402
from temporalio.worker import Worker  # noqa: E402

from opt_worker.workflows import ScanEngineWorkflow  # noqa: E402

ENGINE = {"steps": [{"id": "probe", "tool": "httpx", "risk": "low"},
                    {"id": "vulns", "tool": "nuclei", "risk": "medium"}]}


def make_activities(scope_answers):
    calls = {"run": []}

    @activity.defn(name="check_scope")
    async def check_scope(engagement_id: str, target: str, risk: str) -> dict:
        return scope_answers.pop(0) if scope_answers else {"allowed": True, "reason": "allowed"}

    @activity.defn(name="run_tool")
    async def run_tool(step: dict, target: str) -> dict:
        calls["run"].append(step["id"])
        return {"step": step["id"], "ok": True}

    return [check_scope, run_tool], calls


async def _run(env, scope_answers, by_agent, approve=None):
    acts, calls = make_activities(scope_answers)
    async with Worker(env.client, task_queue="q", workflows=[ScanEngineWorkflow], activities=acts):
        handle = await env.client.start_workflow(
            ScanEngineWorkflow.run, args=[ENGINE, "e1", "app.example.vn", by_agent],
            id=str(uuid.uuid4()), task_queue="q")
        if approve:
            await env.sleep(60)
            await handle.signal(ScanEngineWorkflow.approve, approve)
        return await handle.result(), calls


@pytest.fixture
async def env():
    try:
        e = await WorkflowEnvironment.start_time_skipping()
    except Exception as exc:  # e.g. the test server binary cannot be downloaded
        if os.environ.get("OPT_REQUIRE_TEMPORAL"):
            raise
        pytest.skip(f"Temporal test server unavailable: {exc}")
    async with e:
        yield e


async def test_agent_medium_step_times_out_without_approval(env):
    result, calls = await _run(env, [], by_agent=True)
    assert calls["run"] == ["probe"]
    assert result[-1] == {"step": "vulns", "skipped": "approval timed out after 24h"}


async def test_scope_rechecked_after_approval(env):
    answers = [{"allowed": True, "reason": "ok"}, {"allowed": True, "reason": "ok"},
               {"allowed": False, "reason": "RoE not valid at this time"}]
    result, calls = await _run(env, answers, by_agent=True, approve="vulns")
    assert calls["run"] == ["probe"]
    assert result[-1] == {"step": "vulns", "skipped": "RoE not valid at this time"}


async def test_user_medium_step_runs_without_approval(env):
    result, calls = await _run(env, [], by_agent=False)
    assert calls["run"] == ["probe", "vulns"]
