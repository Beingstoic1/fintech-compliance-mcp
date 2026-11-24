"""Outbound ports. Adapters (fake, Stripe test mode) implement these in T25.

Threat model:
  * Live-money mistakes: ``require_test_mode_key`` refuses any key that does not start
    with ``sk_test_`` (live, restricted, publishable, padded or empty keys).
  * Leaking provider data: adapters raise ``GatewayError(code, http_status)`` only, never
    the provider body or the key.
  * Not wired: no port is called from the Four-Eyes execute path yet.
"""
from __future__ import annotations

from typing import NamedTuple, Protocol

from src.domain.money import Money


class GatewayRefund(NamedTuple):
    """Provider reference and status of a refund the gateway accepted."""
    provider_ref: str
    status: str


class PaymentsGateway(Protocol):
    """A payment processor that can issue refunds idempotently."""

    name: str

    def refund(self, *, original_ref: str, amount: Money, idempotency_key: str) -> GatewayRefund:
        """Refund ``amount`` of ``original_ref`` once per ``idempotency_key``."""
        ...


class GatewayError(RuntimeError):
    """A refused or failed gateway call. ``code`` is a fixed code, safe to log and audit;
    provider response bodies are never carried."""

    def __init__(self, code: str, *, http_status: int | None = None):
        super().__init__(code)
        self.code = code
        self.http_status = http_status


class LiveKeyRefused(ValueError):
    """A non-test payments key was supplied."""


def require_test_mode_key(key: str) -> str:
    """Sandbox adapters must call this on their API key: live keys are refused outright."""
    if not isinstance(key, str) or not key.startswith("sk_test_"):
        raise LiveKeyRefused("LIVE_OR_INVALID_KEY_REFUSED")
    return key
