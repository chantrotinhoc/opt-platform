"""PostgreSQL access with Row-Level Security bound to the current tenant.

Every request runs in its own transaction that first sets `app.tenant_id`
(transaction-local). The API connects as `opt_app`, which has no BYPASSRLS,
so a query that forgets a tenant filter still cannot see another tenant's rows.
"""
from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

_pool: ConnectionPool | None = None


def database_url() -> str:
    url = os.environ.get("OPT_DATABASE_URL")
    if not url:
        raise RuntimeError("OPT_DATABASE_URL is not set")
    return url


def pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(database_url(), min_size=1, max_size=10,
                               kwargs={"row_factory": dict_row}, open=True)
    return _pool


def close() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


@contextmanager
def tenant_tx(tenant_id: str) -> Iterator[psycopg.Connection]:
    with pool().connection() as conn:
        with conn.transaction():
            conn.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))
            yield conn
