"""Postgres backend pieces (T10): RLS schema and the tenant-scoped session helper."""
from pathlib import Path

SCHEMA_SQL = Path(__file__).with_name("001_schema_rls.sql")
