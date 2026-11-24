"""Per-tool telemetry recorder (T23) and the Workbench dashboard read model (T24).

``instrument_tool`` wraps an MCP handler and records one ``ToolCallRecord`` per call:
latency, the decision the handler wrote to the audit ledger, and that row's reason
code. The decision is taken from the audit write itself (``observe_outcome``), not
re-derived from the response, so telemetry and evidence cannot disagree. Arguments,
return values, identities and tokens never reach the recorder; it sees only the
handler's registered name, a clock, and the audited decision/code.

Recording is best effort: a telemetry failure is logged without data and never
changes the tool's result.
"""
from __future__ import annotations

import functools
import logging
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import ParamSpec, TypeVar

from src.db import telemetry as store
from src.db.audit import observe_outcome
from src.domain import telemetry as rules

_log = logging.getLogger(__name__)

P = ParamSpec("P")
R = TypeVar("R")


def _emit(tool: str, decision: str | None, code: str | None, start_ns: int) -> None:
    try:
        store.insert_record(rules.make_record(tool=tool, decision=decision, reason_code=code,
                                              elapsed_ns=time.perf_counter_ns() - start_ns))
    except (sqlite3.Error, rules.TelemetryError, OSError):
        _log.warning("telemetry record dropped for tool %s", tool)  # tool names are constants


def instrument_tool(fn: Callable[P, R]) -> Callable[P, R]:
    """Record latency + audited decision + reason code for every call of ``fn``.

    ``functools.wraps`` keeps ``__wrapped__``, so the MCP SDK still derives the tool's
    schema from the original signature.
    """
    tool = fn.__name__
    if not rules.TOOL_NAME.match(tool):
        raise rules.TelemetryError("INVALID_TOOL_NAME")

    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        start = time.perf_counter_ns()
        with observe_outcome() as outcome:
            try:
                result = fn(*args, **kwargs)
            except BaseException:
                _emit(tool, "ERROR", rules.UNHANDLED_EXCEPTION, start)
                raise
        _emit(tool, outcome.decision, outcome.code, start)
        return result

    return wrapper


def record_sdk_rejection(tool: str, start_ns: int) -> None:
    """The SDK refused the arguments before the handler ran (the handler's own
    telemetry never fired). The caller writes the matching audit row."""
    _emit(tool, "BLOCK", rules.SDK_ARGS_REJECTED, start_ns)


# ─── T24 read model ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Dashboard:
    window: int                                  # tool calls aggregated
    latency: list[rules.LatencySummary]          # all tenants: no tenant column exists
    blocked: list[tuple[str, int]]               # (reason code, count), all tenants
    turnaround: rules.TurnaroundSummary | None   # the given tenant only
    expiry_rate: Decimal | None                  # the given tenant only, in [0, 1]
    terminal_approvals: int


def dashboard(tenant_id: str, window: int = store.DEFAULT_WINDOW) -> Dashboard:
    records = store.recent_records(window)
    counts = store.approval_status_counts(tenant_id)
    return Dashboard(
        window=len(records),
        latency=rules.latency_by_tool(records),
        blocked=rules.blocked_by_reason(records),
        turnaround=rules.turnaround_summary(store.approval_turnaround_pairs(tenant_id)),
        expiry_rate=rules.expiry_rate(counts),
        terminal_approvals=sum(counts[s] for s in rules.TERMINAL_STATUSES),
    )
