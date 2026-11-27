"""Scope Guard (application-side mirror of policies/scope.rego).

Every job, whether started by a schedule, a user or an AI agent, is checked
here before it is queued. The egress gateway enforces the same scope again at
network level, so a compromised worker still cannot leave scope.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, time
from enum import Enum
from zoneinfo import ZoneInfo

VN_TZ = ZoneInfo("Asia/Ho_Chi_Minh")


class Risk(str, Enum):
    PASSIVE = "passive"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class ScopeRule:
    kind: str          # "domain" | "cidr"
    value: str
    exclude: bool = False


@dataclass(frozen=True)
class ScanWindow:
    weekdays: frozenset[int]   # 0 = Monday
    start: time
    end: time


@dataclass
class Engagement:
    tenant_id: str
    roe_valid_from: datetime
    roe_valid_to: datetime
    rules: list[ScopeRule]
    windows: list[ScanWindow] = field(default_factory=list)
    locked: bool = False


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalize_target(raw: str) -> str:
    """Accept only a bare hostname or IP address. URLs, ports, paths, wildcards
    and whitespace are rejected so that scope matching cannot be tricked."""
    value = raw.strip().lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if not _HOST_RE.fullmatch(value):
        raise ValueError(f"invalid target: {raw!r}")
    return value


def _match(rule: ScopeRule, target: str) -> bool:
    if rule.kind == "cidr":
        try:
            return ipaddress.ip_address(target) in ipaddress.ip_network(rule.value, strict=False)
        except ValueError:
            return False
    value = rule.value.lower().rstrip(".")
    if value.startswith("*."):          # "*.example.vn": subdomains only
        return target.endswith(value[1:])
    return target == value or target.endswith("." + value)  # apex + subdomains


def in_scope(engagement: Engagement, target: str) -> bool:
    try:
        target = normalize_target(target)
    except ValueError:
        return False
    if any(r.exclude and _match(r, target) for r in engagement.rules):
        return False
    return any(not r.exclude and _match(r, target) for r in engagement.rules)


def _in_window(engagement: Engagement, now: datetime) -> bool:
    if not engagement.windows:
        return True
    local = now.astimezone(VN_TZ)
    return any(local.weekday() in w.weekdays and w.start <= local.time() < w.end
               for w in engagement.windows)


def evaluate(engagement: Engagement, target: str, risk: Risk, now: datetime,
             target_verified: bool) -> Decision:
    if engagement.locked:
        return Decision(False, "engagement locked")
    try:
        target = normalize_target(target)
    except ValueError as exc:
        return Decision(False, str(exc))
    if not (engagement.roe_valid_from <= now <= engagement.roe_valid_to):
        return Decision(False, "RoE not valid at this time")
    if not in_scope(engagement, target):
        return Decision(False, "target out of scope")
    if risk is not Risk.PASSIVE and not target_verified:
        return Decision(False, "active scan needs verified target ownership")
    if risk is not Risk.PASSIVE and not _in_window(engagement, now):
        return Decision(False, "outside allowed scan window")
    return Decision(True, "allowed")


def needs_approval(risk: Risk, requested_by_agent: bool) -> bool:
    """High-risk steps (exploitation) always need a Lead's approval; medium-risk
    steps need one when an AI agent proposed them."""
    if risk is Risk.HIGH:
        return True
    return requested_by_agent and risk is Risk.MEDIUM
