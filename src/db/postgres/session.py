"""Tenant-scoped Postgres transactions (T10).

Every unit of work runs as ``fintech_app`` inside ``tenant_transaction(conn, tenant)``,
which sets ``app.tenant_id`` with ``set_config(..., is_local => true)``, the
parameterisable form of ``SET LOCAL``. The setting dies with the transaction, so a
pooled connection never carries one tenant's context into the next request, and code
that forgets the context manager sees zero rows (the policies compare against NULL).

Works with any DB-API-like connection exposing psycopg 3's ``transaction()`` and
``info.transaction_status``; psycopg is not imported here (optional dependency:
``pip install '.[postgres]'``).

Threat model:
  * Tenant bleed on pooled connections: the setting is transaction-local and nesting is
    refused, so one request's tenant cannot leak into the next.
  * Injection into the setting: the tenant must match ``^[a-z0-9_]{3,64}$`` and is passed
    as a bound parameter.
  * Not covered: the connection must log in as a member of ``fintech_app``. Owners and
    superusers bypass RLS.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

TENANT_ID_RE = re.compile(r"^[a-z0-9_]{3,64}$")   # matches the tenants.tenant_id CHECK
SET_TENANT_SQL = "SELECT set_config('app.tenant_id', %s, true)"


@contextmanager
def tenant_transaction(conn: Any, tenant_id: str) -> Iterator[Any]:
    """Open a transaction bound to ``tenant_id``. Refuses to nest: a nested call would
    become a savepoint and silently re-scope the *outer* transaction."""
    if not isinstance(tenant_id, str) or not TENANT_ID_RE.match(tenant_id):
        raise ValueError("invalid tenant_id")
    if getattr(conn.info.transaction_status, "name", "IDLE") != "IDLE":
        raise RuntimeError("tenant_transaction must start on an idle connection")
    with conn.transaction():
        conn.execute(SET_TENANT_SQL, (tenant_id,))
        yield conn
