"""Pure refund rules over ``Money``. No I/O; callers supply facts from storage.

Threat model:
  * Amount abuse: zero, negative, float and bool amounts, over-refund (cumulative
    refunds above the original), refund-of-a-refund, and currency mixing are refused
    with a stable code that is safe to return and log.
  * Not covered: stale facts. The rule is only as current as the refunded total the
    caller passes in; the DAL re-runs it inside ``BEGIN IMMEDIATE`` at execute time.
"""
from __future__ import annotations

from src.domain.money import Money, MoneyError


class RefundRuleViolation(ValueError):
    """Raised when a refund breaks a business rule. ``code`` is safe to return/log."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def requested_amount(minor: object, currency: str) -> Money:
    """Boundary conversion: integer minor units -> Money (bool/float/str rejected)."""
    try:
        return Money.from_minor(minor, currency)
    except MoneyError:
        raise RefundRuleViolation("INVALID_AMOUNT_TYPE") from None


def check_refund(
    requested: Money,
    *,
    original: Money,
    already_refunded: Money,
    original_txn_type: str,
) -> Money:
    """Validate a refund against its original transaction. Returns ``requested``."""
    if requested.currency != original.currency or already_refunded.currency != original.currency:
        raise RefundRuleViolation("CURRENCY_MISMATCH")
    if not requested.is_positive():
        raise RefundRuleViolation("REFUND_AMOUNT_NOT_POSITIVE")
    if original_txn_type == "refund":
        raise RefundRuleViolation("CANNOT_REFUND_A_REFUND")
    if requested + already_refunded > original:
        raise RefundRuleViolation("REFUND_EXCEEDS_REFUNDABLE_BALANCE")
    return requested
