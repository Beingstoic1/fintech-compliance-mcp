"""Outbound ports. Adapters (fake, Stripe test mode) implement these in T25."""
from __future__ import annotations

from typing import NamedTuple, Protocol

from src.domain.money import Money


class GatewayRefund(NamedTuple):
    provider_ref: str
    status: str


class PaymentsGateway(Protocol):
    """A payment processor that can issue refunds idempotently."""

    name: str

    def refund(self, *, original_ref: str, amount: Money, idempotency_key: str) -> GatewayRefund:
        ...


class GatewayError(RuntimeError):
    """A refused or failed gateway call. ``code`` is a fixed code, safe to log and audit;
    provider response bodies are never carried."""

    def __init__(self, code: str, *, http_status: int | None = None):
        super().__init__(code)
        self.code = code
        self.http_status = http_status


class LiveKeyRefused(ValueError):
    pass


def require_test_mode_key(key: str) -> str:
    """Sandbox adapters must call this on their API key: live keys are refused outright."""
    if not isinstance(key, str) or not key.startswith("sk_test_"):
        raise LiveKeyRefused("LIVE_OR_INVALID_KEY_REFUSED")
    return key
