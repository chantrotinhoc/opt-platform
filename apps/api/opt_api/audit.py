"""Append-only, hash-chained audit log (per tenant)."""
from __future__ import annotations

import hashlib
import json

import psycopg

GENESIS = "0" * 64


def append(conn: psycopg.Connection, tenant_id: str, actor: str, action: str,
           obj: str, payload: dict) -> str:
    # Serialise writers of the same tenant so the chain has no forks.
    conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (tenant_id,))
    row = conn.execute(
        "SELECT payload_hash FROM audit_event WHERE tenant_id = %s ORDER BY seq DESC LIMIT 1",
        (tenant_id,)).fetchone()
    prev = row["payload_hash"] if row else GENESIS
    body = json.dumps({"actor": actor, "action": action, "object": obj, "payload": payload},
                      sort_keys=True, ensure_ascii=False, default=str)
    digest = hashlib.sha256((prev + body).encode()).hexdigest()
    conn.execute(
        "INSERT INTO audit_event (tenant_id, actor, action, object, payload_hash, prev_hash) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (tenant_id, actor, action, obj, digest, prev))
    return digest


def verify_chain(conn: psycopg.Connection, tenant_id: str) -> bool:
    """True when every event points at the previous event's hash."""
    prev = GENESIS
    for row in conn.execute(
            "SELECT payload_hash, prev_hash FROM audit_event WHERE tenant_id = %s ORDER BY seq",
            (tenant_id,)):
        if row["prev_hash"] != prev:
            return False
        prev = row["payload_hash"]
    return True
