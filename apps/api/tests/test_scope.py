from datetime import datetime, time, timedelta, timezone

import pytest

from opt_api.scope import (Engagement, Risk, ScanWindow, ScopeRule, evaluate,
                           in_scope, needs_approval, normalize_target)

NOW = datetime(2026, 12, 2, 3, 0, tzinfo=timezone.utc)  # Wed 10:00 in Vietnam


def eng(**kw):
    base = dict(tenant_id="itstar", roe_valid_from=NOW - timedelta(days=1),
                roe_valid_to=NOW + timedelta(days=30),
                rules=[ScopeRule("domain", "example.vn"),
                       ScopeRule("domain", "pay.example.vn", exclude=True),
                       ScopeRule("cidr", "203.0.113.0/24")])
    base.update(kw)
    return Engagement(**base)


def test_scope_matching():
    e = eng()
    assert in_scope(e, "app.example.vn")
    assert in_scope(e, "203.0.113.7")
    assert not in_scope(e, "pay.example.vn")
    assert not in_scope(e, "api.pay.example.vn")
    assert not in_scope(e, "evil-example.vn")
    assert not in_scope(e, "198.51.100.1")


def test_out_of_scope_denied():
    assert not evaluate(eng(), "google.com", Risk.PASSIVE, NOW, True).allowed


def test_expired_roe_denied():
    e = eng(roe_valid_to=NOW - timedelta(minutes=1))
    assert evaluate(e, "app.example.vn", Risk.PASSIVE, NOW, True).reason == "RoE not valid at this time"


def test_active_scan_requires_verification_but_passive_does_not():
    assert evaluate(eng(), "app.example.vn", Risk.PASSIVE, NOW, False).allowed
    assert not evaluate(eng(), "app.example.vn", Risk.LOW, NOW, False).allowed


def test_scan_window_uses_vietnam_time():
    night = [ScanWindow(frozenset(range(7)), time(22), time(23, 59))]
    assert not evaluate(eng(windows=night), "app.example.vn", Risk.LOW, NOW, True).allowed
    day = [ScanWindow(frozenset({2}), time(9), time(11))]
    assert evaluate(eng(windows=day), "app.example.vn", Risk.LOW, NOW, True).allowed


def test_locked_engagement_denied():
    assert not evaluate(eng(locked=True), "app.example.vn", Risk.PASSIVE, NOW, True).allowed


def test_approval_rules():
    assert needs_approval(Risk.MEDIUM, requested_by_agent=True)
    assert not needs_approval(Risk.LOW, requested_by_agent=True)
    assert not needs_approval(Risk.MEDIUM, requested_by_agent=False)
    assert needs_approval(Risk.HIGH, requested_by_agent=False)


@pytest.mark.parametrize("bad", ["https://app.example.vn", "app.example.vn:8443", "app.example.vn/x",
                                 "*.example.vn", "app example.vn", "", "app.example.vn\x00"])
def test_malformed_targets_denied(bad):
    assert not in_scope(eng(), bad)
    assert not evaluate(eng(), bad, Risk.PASSIVE, NOW, True).allowed


def test_target_normalised():
    assert normalize_target(" App.Example.VN. ") == "app.example.vn"
    assert in_scope(eng(), "APP.EXAMPLE.VN.")


def test_wildcard_rule_excludes_apex():
    e = eng(rules=[ScopeRule("domain", "*.example.vn")])
    assert in_scope(e, "a.example.vn")
    assert not in_scope(e, "example.vn")
