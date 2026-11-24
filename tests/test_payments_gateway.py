"""T25: PaymentsGateway adapters.

* ``require_test_mode_key`` refuses every key that does not start ``sk_test_``,
  before any transport exists.
* The Stripe adapter is exercised offline through a recording transport.
* One contract runs against the fake and, when ``STRIPE_TEST_KEY`` is set, against
  live Stripe test mode (skipped otherwise).
"""
import json
import os
import urllib.parse
import urllib.request
import uuid
from decimal import Decimal

import pytest

from src.adapters.payments import FakePaymentsGateway, StripeTestModeGateway
from src.domain.money import Money
from src.domain.ports import GatewayError, LiveKeyRefused, require_test_mode_key

USD = "USD"


def usd(minor: int) -> Money:
    return Money.from_minor(minor, USD)


# ─── key guard ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("key", [
    "sk_live_51Habc", "rk_live_51Habc", "rk_test_51Habc", "pk_test_51Habc", "pk_live_51Habc",
    "", " sk_test_51Habc", "SK_TEST_51Habc", "sk_tes", None, b"sk_test_51Habc", 123,
])
def test_non_test_keys_are_refused_before_any_request(key):
    calls = []

    def transport(*a):
        calls.append(a)
        return 200, b"{}"

    with pytest.raises(LiveKeyRefused, match="LIVE_OR_INVALID_KEY_REFUSED"):
        require_test_mode_key(key)
    with pytest.raises(LiveKeyRefused):
        StripeTestModeGateway(key, transport=transport)
    assert calls == []


def test_from_env_refuses_missing_or_live_key(monkeypatch):
    monkeypatch.delenv("STRIPE_TEST_KEY", raising=False)
    with pytest.raises(LiveKeyRefused):
        StripeTestModeGateway.from_env()
    monkeypatch.setenv("STRIPE_TEST_KEY", "sk_live_51Habc")
    with pytest.raises(LiveKeyRefused):
        StripeTestModeGateway.from_env()
    monkeypatch.setenv("STRIPE_TEST_KEY", "sk_test_51Habc")
    assert StripeTestModeGateway.from_env().name == "stripe_test"


def test_key_never_appears_in_repr_or_errors():
    key = "sk_test_SECRETVALUE123"
    gw = StripeTestModeGateway(key, transport=lambda *a: (402, b'{"error":{"message":"' + key.encode() + b'"}}'))
    assert key not in repr(gw) and key not in str(gw)
    with pytest.raises(GatewayError) as ei:
        gw.refund(original_ref="ch_123", amount=usd(100), idempotency_key="k1")
    assert ei.value.code == "GATEWAY_REQUEST_REJECTED" and ei.value.http_status == 402
    assert key not in str(ei.value) and key not in repr(ei.value)


# ─── Stripe adapter, offline ─────────────────────────────────────────────────

class RecordingStripe:
    """Minimal Stripe stand-in: records requests, answers like test mode."""

    def __init__(self, currency="usd", livemode=False, refund_amount=None):
        self.requests = []
        self.currency, self.livemode, self.refund_amount = currency, livemode, refund_amount

    def __call__(self, method, url, headers, body):
        self.requests.append((method, url, dict(headers), body))
        if method == "GET":
            return 200, json.dumps({"id": url.rsplit("/", 1)[1], "currency": self.currency,
                                    "livemode": self.livemode}).encode()
        form = dict(urllib.parse.parse_qsl(body.decode()))
        amount = self.refund_amount if self.refund_amount is not None else int(form["amount"])
        return 200, json.dumps({"id": "re_test123", "object": "refund", "amount": amount,
                                "status": "succeeded", "livemode": self.livemode}).encode()


def test_stripe_request_shape_uses_minor_units_and_idempotency_key():
    fake = RecordingStripe()
    gw = StripeTestModeGateway("sk_test_abc", transport=fake)
    out = gw.refund(original_ref="pi_3Nabc", amount=Money(Decimal("12.34"), USD), idempotency_key="appr-1")
    assert (out.provider_ref, out.status) == ("re_test123", "succeeded")

    (m1, u1, _h1, b1), (m2, u2, h2, b2) = fake.requests
    assert (m1, u1, b1) == ("GET", "https://api.stripe.com/v1/payment_intents/pi_3Nabc", None)
    assert (m2, u2) == ("POST", "https://api.stripe.com/v1/refunds")
    assert dict(urllib.parse.parse_qsl(b2.decode())) == {"payment_intent": "pi_3Nabc", "amount": "1234"}
    assert h2["Idempotency-Key"] == "appr-1" and h2["Authorization"] == "Bearer sk_test_abc"


@pytest.mark.parametrize(("stripe", "code", "posts"), [
    (RecordingStripe(currency="eur"), "CURRENCY_MISMATCH", 0),
    (RecordingStripe(livemode=True), "LIVEMODE_RESPONSE_REFUSED", 0),
    (RecordingStripe(refund_amount=99999), "AMOUNT_MISMATCH", 1),
])
def test_stripe_adapter_refuses_mismatched_or_live_objects(stripe, code, posts):
    gw = StripeTestModeGateway("sk_test_abc", transport=stripe)
    with pytest.raises(GatewayError, match=code):
        gw.refund(original_ref="ch_1", amount=usd(500), idempotency_key="k")
    assert sum(1 for r in stripe.requests if r[0] == "POST") == posts


@pytest.mark.parametrize(("kwargs", "code"), [
    ({"original_ref": "ch_1/../../v1/payouts", "amount": usd(1), "idempotency_key": "k"}, "INVALID_ORIGINAL_REF"),
    ({"original_ref": "acct_1", "amount": usd(1), "idempotency_key": "k"}, "INVALID_ORIGINAL_REF"),
    ({"original_ref": "ch_1", "amount": 100, "idempotency_key": "k"}, "AMOUNT_MUST_BE_MONEY"),
    ({"original_ref": "ch_1", "amount": usd(0), "idempotency_key": "k"}, "REFUND_AMOUNT_NOT_POSITIVE"),
    ({"original_ref": "ch_1", "amount": usd(1), "idempotency_key": "k" * 256}, "INVALID_IDEMPOTENCY_KEY"),
    ({"original_ref": "ch_1", "amount": usd(1), "idempotency_key": "a\nInjected: 1"}, "INVALID_IDEMPOTENCY_KEY"),
])
def test_both_adapters_reject_bad_requests_identically(kwargs, code):
    stripe = RecordingStripe()
    for gw in (FakePaymentsGateway(), StripeTestModeGateway("sk_test_abc", transport=stripe)):
        with pytest.raises(GatewayError, match=code):
            gw.refund(**kwargs)
    assert stripe.requests == []


# ─── fake ────────────────────────────────────────────────────────────────────

def test_fake_applies_domain_refund_rules(fake_gateway):
    fake_gateway.add_charge("ch_fee1", usd(1000))
    with pytest.raises(GatewayError, match="CHARGE_NOT_FOUND"):
        fake_gateway.refund(original_ref="ch_nope", amount=usd(1), idempotency_key="k0")
    with pytest.raises(GatewayError, match="CURRENCY_MISMATCH"):
        fake_gateway.refund(original_ref="ch_fee1", amount=Money.from_minor(1, "INR"), idempotency_key="k1")
    fake_gateway.refund(original_ref="ch_fee1", amount=usd(600), idempotency_key="k2")
    with pytest.raises(GatewayError, match="REFUND_EXCEEDS_REFUNDABLE_BALANCE"):
        fake_gateway.refund(original_ref="ch_fee1", amount=usd(401), idempotency_key="k3")
    fake_gateway.refund(original_ref="ch_fee1", amount=usd(400), idempotency_key="k4")
    assert fake_gateway.refunded_total("ch_fee1") == usd(1000)
    assert fake_gateway.refund_count == 2


def test_fake_idempotency(fake_gateway):
    fake_gateway.add_charge("ch_fee2", usd(1000))
    first = fake_gateway.refund(original_ref="ch_fee2", amount=usd(100), idempotency_key="same")
    again = fake_gateway.refund(original_ref="ch_fee2", amount=usd(100), idempotency_key="same")
    assert first == again and fake_gateway.refund_count == 1
    with pytest.raises(GatewayError, match="IDEMPOTENCY_KEY_REUSED"):
        fake_gateway.refund(original_ref="ch_fee2", amount=usd(200), idempotency_key="same")
    assert fake_gateway.refunded_total("ch_fee2") == usd(100)


# ─── shared contract: fake always, live Stripe test mode when keyed ──────────

def _stripe_test_charge(key: str, minor: int) -> str:
    """Create a confirmed test-mode PaymentIntent with Stripe's `pm_card_visa` test card."""
    body = urllib.parse.urlencode({
        "amount": str(minor), "currency": "usd", "payment_method": "pm_card_visa", "confirm": "true",
        "automatic_payment_methods[enabled]": "true", "automatic_payment_methods[allow_redirects]": "never",
    }).encode()
    req = urllib.request.Request("https://api.stripe.com/v1/payment_intents", data=body, method="POST",
                                 headers={"Authorization": f"Bearer {require_test_mode_key(key)}"})
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed https host
        data = json.loads(resp.read())
    assert data["livemode"] is False and data["status"] == "succeeded"
    return str(data["id"])


@pytest.fixture(params=["fake", "stripe_test_live"])
def gateway_and_charge(request, fake_gateway):
    if request.param == "fake":
        fake_gateway.add_charge("pi_contract", usd(1500))
        return fake_gateway, "pi_contract"
    key = os.environ.get("STRIPE_TEST_KEY")
    if not key:
        pytest.skip("STRIPE_TEST_KEY not set: live Stripe test-mode contract skipped")
    return StripeTestModeGateway(key), _stripe_test_charge(key, 1500)


def test_gateway_contract_partial_refund_is_idempotent(gateway_and_charge):
    gw, ref = gateway_and_charge
    key = f"t25-{uuid.uuid4()}"
    first = gw.refund(original_ref=ref, amount=usd(500), idempotency_key=key)
    again = gw.refund(original_ref=ref, amount=usd(500), idempotency_key=key)
    assert first.provider_ref.startswith("re_") and first.status in {"succeeded", "pending"}
    assert again.provider_ref == first.provider_ref
    with pytest.raises(GatewayError):  # more than the remaining balance
        gw.refund(original_ref=ref, amount=usd(1001), idempotency_key=f"t25-{uuid.uuid4()}")
