import pytest

from opt_agent.router import Residency, Sensitivity, Target, Task, fallback, route


@pytest.mark.parametrize("task", list(Task))
@pytest.mark.parametrize("sens", list(Sensitivity))
def test_local_only_never_reaches_cloud(task, sens):
    d = route(task, sens, Residency.LOCAL_ONLY)
    assert d.target is not Target.CLOUD
    assert fallback(d).target is not Target.CLOUD


@pytest.mark.parametrize("task", list(Task))
def test_restricted_never_reaches_cloud(task):
    assert route(task, Sensitivity.RESTRICTED, Residency.CLOUD_OK).target is not Target.CLOUD


def test_internal_planning_goes_to_cloud_redacted():
    d = route(Task.PLAN, Sensitivity.INTERNAL, Residency.CLOUD_OK)
    assert d.target is Target.CLOUD and d.redact


def test_cloud_falls_back_to_local():
    d = route(Task.REPORT, Sensitivity.PUBLIC, Residency.CLOUD_OK)
    assert fallback(d).target is Target.LOCAL_LARGE
