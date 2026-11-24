"""``PaymentsGateway`` adapters (T25): an in-memory fake and a Stripe **test-mode** adapter.

Both enforce the same request rules (``_check_request``) so a contract test passes
or fails identically against either. Neither is wired into the Four-Eyes execute
path yet; ledger refunds remain internal until that integration ticket.

Stripe safety rails, in order:
  1. ``require_test_mode_key`` at construction: any key not starting ``sk_test_``
     raises ``LiveKeyRefused`` before a transport exists, so a live key never
     leaves the process.
  2. The original charge / PaymentIntent is fetched first; a ``livemode`` object or
     a currency other than the requested ``Money`` currency is refused before the
     refund POST.
  3. The refund response must be ``livemode: false`` and echo the exact amount.
The key is never logged, echoed in errors, or shown by ``repr``. Provider error
bodies are reduced to a fixed code plus the HTTP status. Stdlib only (``urllib``):
no new dependency.
"""
from __future__ import annotations

import json
import os
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from src.domain.money import Money
from src.domain.ports import GatewayError, GatewayRefund, PaymentsGateway, require_test_mode_key
from src.domain.refunds import RefundRuleViolation, check_refund

_REF = re.compile(r"^(ch|pi)_[A-Za-z0-9]{1,250}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9_.:-]{1,255}$")  # Stripe caps keys at 255 chars


def _check_request(original_ref: str, amount: Money, idempotency_key: str) -> None:
    if not isinstance(original_ref, str) or not _REF.match(original_ref):
        raise GatewayError("INVALID_ORIGINAL_REF")
    if not isinstance(amount, Money):
        raise GatewayError("AMOUNT_MUST_BE_MONEY")
    if not amount.is_positive():
        raise GatewayError("REFUND_AMOUNT_NOT_POSITIVE")
    if not isinstance(idempotency_key, str) or not _IDEMPOTENCY_KEY.match(idempotency_key):
        raise GatewayError("INVALID_IDEMPOTENCY_KEY")


# ─── Fake ────────────────────────────────────────────────────────────────────

class FakePaymentsGateway:
    """Deterministic in-memory gateway for tests and the dev build.

    Charges are registered with ``add_charge``. Refunds apply the domain refund rules
    (``check_refund``), are idempotent per key (same key + same request returns the
    original refund; same key + different request raises ``IDEMPOTENCY_KEY_REUSED``),
    and are thread-safe.
    """

    name = "fake"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._charges: dict[str, Money] = {}
        self._refunded: dict[str, Money] = {}
        self._by_key: dict[str, tuple[str, Money, GatewayRefund]] = {}
        self.refund_count = 0  # refunds actually created (replays excluded)

    def add_charge(self, original_ref: str, amount: Money) -> None:
        if not _REF.match(original_ref) or not amount.is_positive():
            raise GatewayError("INVALID_CHARGE")
        with self._lock:
            self._charges[original_ref] = amount
            self._refunded[original_ref] = Money.zero(amount.currency)

    def refunded_total(self, original_ref: str) -> Money:
        with self._lock:
            if original_ref not in self._refunded:
                raise GatewayError("CHARGE_NOT_FOUND")
            return self._refunded[original_ref]

    def refund(self, *, original_ref: str, amount: Money, idempotency_key: str) -> GatewayRefund:
        _check_request(original_ref, amount, idempotency_key)
        with self._lock:
            prior = self._by_key.get(idempotency_key)
            if prior is not None:
                if (prior[0], prior[1]) != (original_ref, amount):
                    raise GatewayError("IDEMPOTENCY_KEY_REUSED")
                return prior[2]
            charge = self._charges.get(original_ref)
            if charge is None:
                raise GatewayError("CHARGE_NOT_FOUND")
            try:
                check_refund(amount, original=charge, already_refunded=self._refunded[original_ref],
                             original_txn_type="charge")
            except RefundRuleViolation as e:
                raise GatewayError(e.code) from None
            self.refund_count += 1
            result = GatewayRefund(provider_ref=f"re_fake{self.refund_count:08d}", status="succeeded")
            self._refunded[original_ref] = self._refunded[original_ref] + amount
            self._by_key[idempotency_key] = (original_ref, amount, result)
            return result


# ─── Stripe test mode ────────────────────────────────────────────────────────

STRIPE_API = "https://api.stripe.com/v1"
STRIPE_KEY_ENV = "STRIPE_TEST_KEY"

# (method, url, headers, body) -> (http status, response body)
Transport = Callable[[str, str, Mapping[str, str], bytes | None], tuple[int, bytes]]


def urllib_transport(method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> tuple[int, bytes]:
    if not url.startswith(STRIPE_API + "/"):
        raise GatewayError("UNEXPECTED_URL")
    req = urllib.request.Request(url, data=body, headers=dict(headers), method=method)  # noqa: S310 - fixed https host
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed https host
            return int(resp.status), resp.read()
    except urllib.error.HTTPError as e:
        return int(e.code), e.read()
    except (urllib.error.URLError, TimeoutError, OSError):
        raise GatewayError("GATEWAY_UNREACHABLE") from None


class StripeTestModeGateway:
    """Refunds through Stripe's API in test mode only. Construction refuses live keys."""

    name = "stripe_test"

    def __init__(self, api_key: str, *, transport: Transport | None = None):
        self.__key = require_test_mode_key(api_key)  # raises before anything else exists
        self._transport: Transport = transport or urllib_transport

    @classmethod
    def from_env(cls, *, transport: Transport | None = None) -> StripeTestModeGateway:
        return cls(os.environ.get(STRIPE_KEY_ENV, ""), transport=transport)

    def __repr__(self) -> str:
        return "StripeTestModeGateway(key=<sk_test redacted>)"

    def _call(self, method: str, path: str, form: Mapping[str, str] | None = None,
              idempotency_key: str | None = None) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self.__key}"}
        body = None
        if form is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = urllib.parse.urlencode(form).encode()
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        status, raw = self._transport(method, f"{STRIPE_API}{path}", headers, body)
        if status >= 400:
            raise GatewayError("GATEWAY_REQUEST_REJECTED", http_status=status)
        try:
            data = json.loads(raw, parse_float=Decimal)  # never a binary float
        except ValueError:
            raise GatewayError("GATEWAY_BAD_RESPONSE", http_status=status) from None
        if not isinstance(data, dict):
            raise GatewayError("GATEWAY_BAD_RESPONSE", http_status=status)
        if data.get("livemode") is not False:
            raise GatewayError("LIVEMODE_RESPONSE_REFUSED")
        return data

    def refund(self, *, original_ref: str, amount: Money, idempotency_key: str) -> GatewayRefund:
        _check_request(original_ref, amount, idempotency_key)
        kind = "charges" if original_ref.startswith("ch_") else "payment_intents"
        original = self._call("GET", f"/{kind}/{original_ref}")
        if str(original.get("currency", "")).upper() != amount.currency:
            raise GatewayError("CURRENCY_MISMATCH")

        minor = amount.to_minor()
        param = "charge" if kind == "charges" else "payment_intent"
        data = self._call("POST", "/refunds", {param: original_ref, "amount": str(minor)}, idempotency_key)
        if type(data.get("amount")) is not int or data["amount"] != minor:
            raise GatewayError("AMOUNT_MISMATCH")
        ref, status = data.get("id"), data.get("status")
        if not isinstance(ref, str) or not ref.startswith("re_") or not isinstance(status, str):
            raise GatewayError("GATEWAY_BAD_RESPONSE")
        return GatewayRefund(provider_ref=ref, status=status)


if TYPE_CHECKING:  # mypy proves both adapters satisfy the port
    _fake: PaymentsGateway = FakePaymentsGateway()
    _stripe: PaymentsGateway = StripeTestModeGateway("sk_test_typecheck")
