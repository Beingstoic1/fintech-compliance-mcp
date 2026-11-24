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


class LiveKeyRefused(ValueError):
    pass


def require_test_mode_key(key: str) -> str:
    """Sandbox adapters must call this on their API key: live keys are refused outright."""
    if not isinstance(key, str) or not key.startswith("sk_test_"):
        raise LiveKeyRefused("LIVE_OR_INVALID_KEY_REFUSED")
    return key
