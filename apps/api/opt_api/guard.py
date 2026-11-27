"""Loads an engagement from the database and asks the Scope Guard for a decision.

Used by the scope-check endpoint and, before every step, by the scan runner,
so a step is re-checked against the RoE at the moment it runs.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import psycopg

from opt_api.scope import Decision, Engagement, Risk, ScopeRule, evaluate, normalize_target


class EngagementNotFound(LookupError):
    pass


def target_verified(conn: psycopg.Connection, target: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM target WHERE value = %s AND verified_at > now() - interval '30 days'",
        (target,)).fetchone() is not None


def decide(conn: psycopg.Connection, tenant: str, engagement_id: UUID | str, raw_target: str,
           risk: Risk, now: datetime | None = None) -> tuple[str, Decision]:
    """Returns (normalised target or the raw value if malformed, decision)."""
    now = now or datetime.now(timezone.utc)
    e = conn.execute(
        "SELECT status, roe_valid_from, roe_valid_to FROM engagement WHERE id = %s",
        (engagement_id,)).fetchone()
    if e is None:  # also the answer for another tenant's engagement (RLS)
        raise EngagementNotFound(str(engagement_id))
    rules = [ScopeRule(r["kind"], r["value"], r["exclude"]) for r in conn.execute(
        "SELECT kind, value, exclude FROM scope_rule WHERE engagement_id = %s", (engagement_id,))]
    try:
        target = normalize_target(raw_target)
        verified = target_verified(conn, target)
    except ValueError:
        target, verified = raw_target, False
    eng = Engagement(tenant, e["roe_valid_from"], e["roe_valid_to"], rules,
                     locked=e["status"] in ("locked", "closed"))
    return target, evaluate(eng, target, risk, now, verified)
