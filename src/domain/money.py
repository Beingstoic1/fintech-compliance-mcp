"""Decimal money value object. Floats are rejected everywhere.

Storage keeps integer minor units (paise/cents); the domain reasons in ``Money``.

Threat model:
  * Rounding and precision loss: floats and bools are refused; amounts below the
    currency's minor unit are refused instead of rounded.
  * Currency confusion: arithmetic and comparison across currencies raise.
  * Unknown currencies: only ``CURRENCY_EXPONENT`` codes are accepted.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

# ISO 4217 minor-unit exponents for currencies this system accepts.
CURRENCY_EXPONENT: dict[str, int] = {"INR": 2, "USD": 2, "EUR": 2, "GBP": 2, "SGD": 2, "JPY": 0}


class MoneyError(ValueError):
    """A money rule was broken. The message is a stable code."""


@dataclass(frozen=True)
class Money:
    """An exact amount in one currency. Construct from ``Decimal`` or ``from_minor``; never float."""
    amount: Decimal
    currency: str

    def __post_init__(self) -> None:
        if not isinstance(self.amount, Decimal):  # bool/int/float are not Decimal
            raise MoneyError("AMOUNT_MUST_BE_DECIMAL")
        if not self.amount.is_finite():
            raise MoneyError("AMOUNT_NOT_FINITE")
        exp = CURRENCY_EXPONENT.get(self.currency)
        if exp is None:
            raise MoneyError("UNSUPPORTED_CURRENCY")
        if self.amount != self.amount.quantize(Decimal(1).scaleb(-exp)):
            raise MoneyError("SUB_MINOR_UNIT_PRECISION")

    # ── construction / conversion ────────────────────────────────────────────
    @classmethod
    def from_minor(cls, minor: object, currency: str) -> Money:
        """Build from integer minor units (paise, cents)."""
        if isinstance(minor, bool) or not isinstance(minor, int):
            raise MoneyError("MINOR_UNITS_MUST_BE_INT")
        exp = CURRENCY_EXPONENT.get(currency)
        if exp is None:
            raise MoneyError("UNSUPPORTED_CURRENCY")
        return cls(Decimal(minor).scaleb(-exp), currency)

    @classmethod
    def zero(cls, currency: str) -> Money:
        """Zero in ``currency``."""
        return cls.from_minor(0, currency)

    def to_minor(self) -> int:
        """Integer minor units for storage."""
        return int(self.amount.scaleb(CURRENCY_EXPONENT[self.currency]))

    # ── arithmetic (same currency only) ──────────────────────────────────────
    def _same(self, other: Money) -> None:
        if not isinstance(other, Money):
            raise TypeError("Money operations require Money")
        if other.currency != self.currency:
            raise MoneyError("CURRENCY_MISMATCH")

    def __add__(self, other: Money) -> Money:
        self._same(other)
        return Money(self.amount + other.amount, self.currency)

    def __sub__(self, other: Money) -> Money:
        self._same(other)
        return Money(self.amount - other.amount, self.currency)

    def __lt__(self, other: Money) -> bool:
        self._same(other)
        return self.amount < other.amount

    def __le__(self, other: Money) -> bool:
        self._same(other)
        return self.amount <= other.amount

    def __gt__(self, other: Money) -> bool:
        self._same(other)
        return self.amount > other.amount

    def __ge__(self, other: Money) -> bool:
        self._same(other)
        return self.amount >= other.amount

    def is_positive(self) -> bool:
        """True when the amount is greater than zero."""
        return self.amount > 0
