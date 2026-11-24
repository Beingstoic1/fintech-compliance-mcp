"""Operational telemetry rules (T23/T24). Pure: no I/O, no clocks, no floats.

A ``ToolCallRecord`` holds exactly four things: the tool name, the audited decision,
the block reason code, and the latency. There is no field that could hold tool
arguments, identities, tokens, or free text: names and codes must match fixed
patterns (the same shapes the audit ledger accepts), and anything else is replaced
by a fixed placeholder (fail closed) instead of being stored.

Latency is kept as integer microseconds and reported as ``Decimal`` milliseconds,
so every aggregate is exact. Percentiles use the nearest-rank method (p50 is the
lower median for an even count), which never interpolates a value that was not
observed.

Threat model:
  * Side channel: telemetry cannot carry arguments, identities, tokens or free text,
    because those fields do not exist and codes must match fixed patterns.
  * Rounding drift: integer microseconds and ``Decimal`` output, no floats.
  * Not covered: telemetry is operational data, not evidence. It has no HMAC and no
    tenant column, and an unauthenticated caller can add ``unknown`` BLOCK records.
"""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

from src.domain.ledger import DECISIONS

TOOL_NAME = re.compile(r"^[a-z][a-z_]{1,63}$")
REASON_CODE = re.compile(r"^[A-Z][A-Z_]{1,63}$")

INVALID_CODE = "INVALID_CODE"              # a code that is not code-shaped (fail closed)
NO_AUDIT_OUTCOME = "NO_AUDIT_OUTCOME"      # the handler returned without writing an audit row
UNHANDLED_EXCEPTION = "UNHANDLED_EXCEPTION"
SDK_ARGS_REJECTED = "SDK_ARGS_REJECTED"    # the MCP SDK refused the arguments before the handler ran
UNSPECIFIED = "UNSPECIFIED"                # a BLOCK audited without a code

# Approval statuses that end a request's life; the expiry rate is measured over these.
TERMINAL_STATUSES = ("CONSUMED", "REJECTED", "EXPIRED")

_US_PER_MS = Decimal(1000)
_US_PER_S = Decimal(1_000_000)


class TelemetryError(ValueError):
    """A telemetry value has the wrong shape (for example a bad tool name)."""


@dataclass(frozen=True)
class ToolCallRecord:
    """One tool call: name, audited decision, reason code, latency in µs. Nothing else."""
    tool: str
    decision: str
    reason_code: str | None
    latency_us: int

    @property
    def latency_ms(self) -> Decimal:
        """Latency in milliseconds as ``Decimal``."""
        return us_to_ms(self.latency_us)


def _int(value: object, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TelemetryError(code)
    return value


def sanitize_code(code: object) -> str | None:
    """A reason code passes only if it is code-shaped; anything else becomes INVALID_CODE."""
    if code is None:
        return None
    return code if isinstance(code, str) and REASON_CODE.match(code) else INVALID_CODE


def make_record(*, tool: str, decision: str | None, reason_code: object, elapsed_ns: int) -> ToolCallRecord:
    """Build a record from a handler outcome.

    ``tool`` is the registered handler name (a constant, never caller input) and must
    be name-shaped. A missing or unknown decision is recorded as ``ERROR`` /
    ``NO_AUDIT_OUTCOME`` so a handler that skips its audit row shows up instead of
    disappearing.
    """
    if not isinstance(tool, str) or not TOOL_NAME.match(tool):
        raise TelemetryError("INVALID_TOOL_NAME")
    ns = _int(elapsed_ns, "INVALID_LATENCY")
    if decision is None or decision not in DECISIONS:
        decision, reason_code = "ERROR", NO_AUDIT_OUTCOME
    return ToolCallRecord(tool=tool, decision=decision, reason_code=sanitize_code(reason_code),
                          latency_us=ns // 1000)


def us_to_ms(us: int) -> Decimal:
    """Exact conversion from integer µs to ``Decimal`` ms."""
    return Decimal(_int(us, "INVALID_LATENCY")) / _US_PER_MS


def nearest_rank(values: Sequence[int], pct: int) -> int | None:
    """The ``pct``-th percentile (1..100) by nearest rank; ``None`` for no data."""
    if isinstance(pct, bool) or not isinstance(pct, int) or not 1 <= pct <= 100:
        raise TelemetryError("INVALID_PERCENTILE")
    if not values:
        return None
    ordered = sorted(values)
    rank = -(-pct * len(ordered) // 100)  # ceil without floats
    return ordered[rank - 1]


# ─── T24 aggregates ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LatencySummary:
    """Call count and nearest-rank p50/p95 latency for one tool."""
    tool: str
    calls: int
    p50_ms: Decimal
    p95_ms: Decimal


def latency_by_tool(records: Iterable[ToolCallRecord]) -> list[LatencySummary]:
    """p50/p95 latency per tool, sorted by tool name."""
    by_tool: dict[str, list[int]] = {}
    for r in records:
        by_tool.setdefault(r.tool, []).append(r.latency_us)
    out = []
    for tool in sorted(by_tool):
        lat = by_tool[tool]
        p50, p95 = nearest_rank(lat, 50), nearest_rank(lat, 95)
        if p50 is not None and p95 is not None:  # always true: lat is never empty
            out.append(LatencySummary(tool, len(lat), us_to_ms(p50), us_to_ms(p95)))
    return out


def blocked_by_reason(records: Iterable[ToolCallRecord]) -> list[tuple[str, int]]:
    """BLOCK counts per reason code, most frequent first (ties by code)."""
    counts = Counter(r.reason_code or UNSPECIFIED for r in records if r.decision == "BLOCK")
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


@dataclass(frozen=True)
class TurnaroundSummary:
    """Count and median/p95 Four-Eyes turnaround in seconds."""
    count: int
    median_s: Decimal
    p95_s: Decimal


def turnaround_us(created_at: str, consumed_at: str) -> int:
    """Microseconds from staging to execution. Timestamps are ISO-8601 with an offset."""
    start, end = datetime.fromisoformat(created_at), datetime.fromisoformat(consumed_at)
    if start.tzinfo is None or end.tzinfo is None:
        raise TelemetryError("NAIVE_TIMESTAMP")
    delta = end - start
    us = (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds
    if us < 0:
        raise TelemetryError("NEGATIVE_TURNAROUND")
    return us


def turnaround_summary(pairs: Iterable[tuple[str, str]]) -> TurnaroundSummary | None:
    """Four-Eyes turnaround (``consumed_at - created_at``) over consumed approvals."""
    spans = [turnaround_us(c, d) for c, d in pairs]
    p50, p95 = nearest_rank(spans, 50), nearest_rank(spans, 95)
    if p50 is None or p95 is None:
        return None
    return TurnaroundSummary(len(spans), Decimal(p50) / _US_PER_S, Decimal(p95) / _US_PER_S)


def expiry_rate(status_counts: Mapping[str, int]) -> Decimal | None:
    """Share of terminal approvals that expired unexecuted, in [0, 1]; ``None`` if none ended."""
    counts = {s: _int(status_counts.get(s, 0), "INVALID_COUNT") for s in TERMINAL_STATUSES}
    total = sum(counts.values())
    if total == 0:
        return None
    return Decimal(counts["EXPIRED"]) / Decimal(total)
