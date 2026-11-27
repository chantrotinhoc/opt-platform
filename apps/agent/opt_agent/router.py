"""Model router: chooses cloud or local LLM for each agent call.

Hard rule: data that is sensitive, or belongs to a tenant/engagement marked
local_only, never goes to a cloud model, whatever the task difficulty.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Residency(str, Enum):
    CLOUD_OK = "cloud_ok"
    LOCAL_ONLY = "local_only"


class Sensitivity(str, Enum):
    PUBLIC = "public"          # OSINT, public recon output
    INTERNAL = "internal"      # findings on customer systems, redactable
    RESTRICTED = "restricted"  # credentials, PII, internal configs, OT data


class Task(str, Enum):
    PLAN = "plan"              # attack planning, vulnerability chaining
    TRIAGE = "triage"          # classify, dedupe, summarise tool output
    REPORT = "report"          # executive / technical report drafting


class Target(str, Enum):
    CLOUD = "cloud"
    LOCAL_LARGE = "local_large"
    LOCAL_SMALL = "local_small"


@dataclass(frozen=True)
class RouteDecision:
    target: Target
    redact: bool
    reason: str


def route(task: Task, sensitivity: Sensitivity, residency: Residency) -> RouteDecision:
    if residency is Residency.LOCAL_ONLY:
        small = task is Task.TRIAGE
        return RouteDecision(
            Target.LOCAL_SMALL if small else Target.LOCAL_LARGE, False,
            "tenant or engagement is local_only")
    if sensitivity is Sensitivity.RESTRICTED:
        return RouteDecision(Target.LOCAL_LARGE, False, "restricted data stays on-prem")
    if task is Task.TRIAGE:
        return RouteDecision(Target.LOCAL_SMALL, False, "high-volume task, local is cheaper")
    # PLAN / REPORT on public or internal data: cloud, redacted unless public
    return RouteDecision(Target.CLOUD, sensitivity is not Sensitivity.PUBLIC,
                         "complex reasoning on redactable data")


def fallback(decision: RouteDecision) -> RouteDecision:
    """When the chosen model fails. Cloud may fall back to local; never the reverse."""
    if decision.target is Target.CLOUD:
        return RouteDecision(Target.LOCAL_LARGE, False, "cloud unavailable, fell back to local")
    return decision
