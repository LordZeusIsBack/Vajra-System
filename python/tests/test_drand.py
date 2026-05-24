"""tests/test_drand.py — Unit tests for the drand Layer A integration.

What this exercises:
  • Round arithmetic: round_at_or_after, publish_time
  • AAD derivation determinism
  • Multi-relay fetch:
      - all agree              → success
      - majority agrees + 1 disagrees → success with warning
      - tie / no majority      → failure
      - all relays down        → failure
  • Policy gate (`verify_round_published`):
      - now < publish_time     → DrandError, no network call
      - now ≥ publish_time + relays agree → success

What this skips:
  • Live drand network. All relay responses are mocked with httpx.MockTransport.
  • BLS signature verification (not implemented in this prototype).

Run with:
    cd python && pytest tests/test_drand.py -v
"""

import os
import secrets

import pytest

# Need a real HMAC secret before importing modules that load config
os.environ.setdefault("MANIFEST_HMAC_SECRET", secrets.token_hex(32))

import httpx  # noqa: E402
from config import settings  # noqa: E402
from drand_client import (  # noqa: E402
    DrandError,
    derive_aad,
    fetch_round,
    publish_time,
    round_at_or_after,
    verify_round_published,
)


# ── Pure arithmetic ───────────────────────────────────────────────────────────

class TestRoundArithmetic:
    GENESIS = 1595431050   # League of Entropy mainnet (30s chained)
    PERIOD  = 30

    def test_round_1_at_genesis_plus_period(self) -> None:
        assert round_at_or_after(self.GENESIS + 30, self.GENESIS, self.PERIOD) == 1

    def test_round_2_one_second_after_round_1(self) -> None:
        # Anything strictly after round 1's publish time pushes us to round 2
        assert round_at_or_after(self.GENESIS + 31, self.GENESIS, self.PERIOD) == 2

    def test_round_1_when_target_before_genesis(self) -> None:
        assert round_at_or_after(self.GENESIS - 100, self.GENESIS, self.PERIOD) == 1
        assert round_at_or_after(0, self.GENESIS, self.PERIOD) == 1

    def test_exact_period_boundary(self) -> None:
        # Target exactly at round N publish_time → round N
        for r in (1, 2, 5, 10, 1000):
            t = self.GENESIS + r * self.PERIOD
            assert round_at_or_after(t, self.GENESIS, self.PERIOD) == r

    def test_one_second_before_round_boundary(self) -> None:
        # Target at publish_time(R) - 1 → still round R (ceiling)
        for r in (2, 5, 100):
            t = self.GENESIS + r * self.PERIOD - 1
            assert round_at_or_after(t, self.GENESIS, self.PERIOD) == r

    def test_publish_time_is_inverse(self) -> None:
        for r in (1, 7, 100, 999999):
            t = publish_time(r, self.GENESIS, self.PERIOD)
            assert round_at_or_after(t, self.GENESIS, self.PERIOD) == r

    def test_publish_time_rejects_zero(self) -> None:
        with pytest.raises(ValueError):
            publish_time(0, self.GENESIS, self.PERIOD)

    def test_round_at_or_after_rejects_zero_period(self) -> None:
        with pytest.raises(ValueError):
            round_at_or_after(123456789, self.GENESIS, 0)


# ── AAD determinism ───────────────────────────────────────────────────────────

class TestAAD:
    CHAIN = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"

    def test_aad_is_deterministic(self) -> None:
        a = derive_aad(12345, self.CHAIN)
        b = derive_aad(12345, self.CHAIN)
        assert a == b
        assert len(a) == 32

    def test_aad_changes_with_round(self) -> None:
        assert derive_aad(1, self.CHAIN) != derive_aad(2, self.CHAIN)

    def test_aad_changes_with_chain(self) -> None:
        other_chain = "11" * 32
        assert derive_aad(1, self.CHAIN) != derive_aad(1, other_chain)

    def test_aad_rejects_short_chain_hash(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            derive_aad(1, "ab" * 16)  # 16 bytes

    def test_aad_rejects_non_hex_chain(self) -> None:
        with pytest.raises(ValueError):
            derive_aad(1, "not hex at all")


# ── Multi-relay fetch (mocked) ────────────────────────────────────────────────

def _mock_handler(per_relay_response: dict[str, dict | int | Exception]):
    """Build an httpx.MockTransport handler returning per-relay-host responses.

    `per_relay_response` maps host (e.g. "api.drand.sh") to:
        - dict  → returned as JSON body with status 200
        - int   → returned as the HTTP status code (empty body)
        - Exception → raised to simulate a network error
    """
    def _handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        resp = per_relay_response.get(host)
        if isinstance(resp, Exception):
            raise resp
        if isinstance(resp, int):
            return httpx.Response(status_code=resp)
        if isinstance(resp, dict):
            return httpx.Response(status_code=200, json=resp)
        return httpx.Response(status_code=500)
    return _handler


# To intercept the AsyncClient that drand_client creates internally, we monkey-
# patch httpx.AsyncClient to inject a MockTransport. Cleaner than mocking
# `_fetch_round_one` directly because it tests the actual HTTP wiring.

@pytest.fixture
def mock_relays(monkeypatch):
    def _install(per_host: dict):
        transport = httpx.MockTransport(_mock_handler(per_host))
        original = httpx.AsyncClient

        def patched(*args, **kwargs):
            kwargs["transport"] = transport
            return original(*args, **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", patched)
    return _install


def _round_payload(round_num: int, *, signature: str = "abcd" * 24,
                   randomness: str = "ee" * 32) -> dict:
    return {"round": round_num, "signature": signature, "randomness": randomness}


@pytest.mark.asyncio
async def test_fetch_all_relays_agree(mock_relays) -> None:
    payload = _round_payload(42)
    mock_relays({
        "api.drand.sh":       payload,
        "api2.drand.sh":      payload,
        "api3.drand.sh":      payload,
        "drand.cloudflare.com": payload,
    })
    info = await fetch_round(42, min_agreement=2)
    assert info.round == 42
    assert info.signature == payload["signature"]
    assert info.randomness == payload["randomness"]


@pytest.mark.asyncio
async def test_fetch_majority_agrees_one_disagrees(mock_relays) -> None:
    # 3 relays agree, 1 returns a different signature. Majority should win.
    good = _round_payload(7, signature="aa" * 48)
    bad  = _round_payload(7, signature="bb" * 48)
    mock_relays({
        "api.drand.sh":       good,
        "api2.drand.sh":      good,
        "api3.drand.sh":      good,
        "drand.cloudflare.com": bad,
    })
    info = await fetch_round(7, min_agreement=2)
    assert info.signature == "aa" * 48


@pytest.mark.asyncio
async def test_fetch_no_majority_fails(mock_relays) -> None:
    # 4 relays, 4 different signatures → no group reaches min_agreement=2 (each is 1)
    mock_relays({
        "api.drand.sh":       _round_payload(7, signature="aa" * 48),
        "api2.drand.sh":      _round_payload(7, signature="bb" * 48),
        "api3.drand.sh":      _round_payload(7, signature="cc" * 48),
        "drand.cloudflare.com": _round_payload(7, signature="dd" * 48),
    })
    with pytest.raises(DrandError, match="agreement failed"):
        await fetch_round(7, min_agreement=2)


@pytest.mark.asyncio
async def test_fetch_all_relays_down_fails(mock_relays) -> None:
    mock_relays({
        "api.drand.sh":       httpx.ConnectError("down"),
        "api2.drand.sh":      503,
        "api3.drand.sh":      httpx.TimeoutException("slow"),
        "drand.cloudflare.com": 404,
    })
    with pytest.raises(DrandError, match="All .* drand relays failed"):
        await fetch_round(7, min_agreement=2)


@pytest.mark.asyncio
async def test_fetch_rejects_wrong_round_response(mock_relays) -> None:
    # All relays return the WRONG round number — _fetch_round_one rejects each
    wrong = _round_payload(99)  # asked for 7, returned 99
    mock_relays({
        "api.drand.sh":       wrong,
        "api2.drand.sh":      wrong,
        "api3.drand.sh":      wrong,
        "drand.cloudflare.com": wrong,
    })
    with pytest.raises(DrandError):
        await fetch_round(7, min_agreement=2)


# ── Policy gate ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_policy_gate_refuses_before_publish(mock_relays) -> None:
    """Manifest claims a round in the future → refuse, no network call needed."""
    # If verify_round_published makes a network call, this would 500 anyway,
    # but the point is the clock check should short-circuit.
    mock_relays({
        "api.drand.sh":       500,
        "api2.drand.sh":      500,
        "api3.drand.sh":      500,
        "drand.cloudflare.com": 500,
    })

    # A round so far in the future its publish time can't have happened yet.
    # publish_time(R) = genesis + 30*R. R = 10^9 → ~30 billion seconds → ~951 years
    future_round = 10**9
    with pytest.raises(DrandError, match="not yet open"):
        await verify_round_published(future_round)


@pytest.mark.asyncio
async def test_policy_gate_accepts_past_round(mock_relays) -> None:
    """Round 1 publishes at genesis+30 — long in the past. Relays agree → OK."""
    payload = _round_payload(1)
    mock_relays({
        "api.drand.sh":       payload,
        "api2.drand.sh":      payload,
        "api3.drand.sh":      payload,
        "drand.cloudflare.com": payload,
    })
    info = await verify_round_published(1)
    assert info.round == 1


@pytest.mark.asyncio
async def test_policy_gate_explicit_now_unix(mock_relays) -> None:
    """now_unix can be passed for deterministic testing."""
    payload = _round_payload(100)
    mock_relays({
        "api.drand.sh":       payload,
        "api2.drand.sh":      payload,
        "api3.drand.sh":      payload,
        "drand.cloudflare.com": payload,
    })

    pub_100 = publish_time(100, settings.drand_genesis, settings.drand_period)
    # now = exactly publish_time(100) → should accept
    info = await verify_round_published(100, now_unix=pub_100)
    assert info.round == 100

    # now = publish_time(100) - 1 → should refuse
    with pytest.raises(DrandError):
        await verify_round_published(100, now_unix=pub_100 - 1)
