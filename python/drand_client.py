"""drand_client.py — Multi-relay drand beacon client (Layer A).

DRAND IN ONE PARAGRAPH
  drand is a publicly-auditable distributed randomness beacon operated by the
  League of Entropy (Cloudflare, Protocol Labs, EPFL, …). A new threshold-BLS
  signed random value is published every `period` seconds on a known chain.
  Round R's signature cannot exist before R's `publish_time = genesis + R*period`,
  because it requires t-of-n nodes to cooperate at the scheduled time. Anyone
  can later verify the signature against the chain's public key.

WHAT VAJRA USES IT FOR (LAYER A)
  1. Cryptographic round-binding via AES-GCM AAD:
        aad = SHA256(b"vajra-v1" || target_round_be_u64 || chain_hash_bytes)
     The same AAD is supplied to both AES-GCM layers (inner Rust around PDF,
     outer Python around locked.json). Tampering with target_round in the
     manifest → AAD mismatch → AES-GCM auth tag rejection. Cryptographic,
     not policy.

  2. Policy time-gate (this module's `verify_round_published`):
     Before invoking `vajra solve`, reconstruct.py checks that the target
     round has actually published — by current clock AND by fetching from
     ≥2 relays that must agree on signature + randomness.

HONEST LIMITATIONS — READ BEFORE PITCHING
  • The policy gate runs in reconstruct.py. An attacker who has the manifest,
    the data_key (from k shards), and puzzle.json can bypass it by calling
    `vajra solve` directly. The AES-GCM AAD does NOT prevent this — the AAD
    only binds *which* round, not *whether* it has published.
  • Closing this gap requires full timelock encryption (TLE) against drand,
    where decryption itself is mathematically impossible until R publishes.
    That's Layer B (drand `tlock`, BLS-IBE). Not implemented here.
  • If a relay returns a forged signature, multi-relay agreement catches it
    *only* if a majority of relays aren't colluding. The proper defence is
    verifying the BLS signature against the chain's public key (planned
    upgrade — `py_ecc` or `blspy`). Skipped here to keep scope tight.

Reference: https://docs.drand.love/dev-guide/API%20Documentation%20v2/drand-http-api/
"""

from __future__ import annotations

import asyncio
import hashlib
from collections import Counter
from dataclasses import dataclass

import httpx

from config import settings

# ── Public types ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RoundInfo:
    """A successful response for one round from one relay."""
    round: int
    randomness: str  # hex
    signature: str   # hex


class DrandError(RuntimeError):
    """Raised on any drand fetch / agreement failure. Message is safe to surface."""


# ── Round arithmetic (pure, no I/O) ───────────────────────────────────────────


def round_at_or_after(target_unix: int, genesis: int, period: int) -> int:
    """Return the smallest drand round R such that R's publish_time ≥ target_unix.

    Drand convention: round R publishes at  genesis + R * period.
    """
    if period <= 0:
        raise ValueError("period must be positive")
    delta = target_unix - genesis
    if delta <= 0:
        return 1
    # Ceiling division
    return (delta + period - 1) // period


def publish_time(round_num: int, genesis: int, period: int) -> int:
    """Unix-seconds publish time of `round_num`."""
    if round_num < 1:
        raise ValueError("round_num must be ≥ 1")
    return genesis + round_num * period


# ── AAD derivation (used by both lock and unlock; must be byte-identical) ─────


def derive_aad(target_round: int, chain_hash_hex: str) -> bytes:
    """Compute the AES-GCM AAD that binds a lock to a specific drand round.

        aad = SHA256(b"vajra-v1" || target_round_be_u64 || chain_hash_bytes)

    32 bytes, deterministic. Both lock_pipeline.py and reconstruct.py must
    derive this identically from manifest fields (target_round, chain_hash).
    """
    try:
        chain_bytes = bytes.fromhex(chain_hash_hex)
    except ValueError as exc:
        raise ValueError(f"Bad chain_hash hex: {exc}") from exc
    if len(chain_bytes) != 32:
        raise ValueError(f"chain_hash must be 32 bytes (got {len(chain_bytes)})")

    return hashlib.sha256(
        b"vajra-v1" + target_round.to_bytes(8, "big") + chain_bytes
    ).digest()


# ── Single-relay fetch ────────────────────────────────────────────────────────


async def _fetch_round_one(
    relay: str,
    chain_hash: str,
    round_num: int,
    *,
    client: httpx.AsyncClient,
) -> RoundInfo:
    """Fetch a specific round from one relay. Raises DrandError on any failure."""
    url = f"{relay.rstrip('/')}/{chain_hash}/public/{round_num}"
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        raise DrandError(f"{relay}: network error: {exc}") from exc

    if resp.status_code != 200:
        # 404 typically means "round not yet published" on this chain
        raise DrandError(f"{relay}: HTTP {resp.status_code} for round {round_num}")

    try:
        data = resp.json()
    except ValueError as exc:
        raise DrandError(f"{relay}: response is not JSON: {exc}") from exc

    if "round" not in data or "randomness" not in data or "signature" not in data:
        raise DrandError(f"{relay}: malformed round response (missing fields)")
    if int(data["round"]) != round_num:
        raise DrandError(
            f"{relay}: returned round {data['round']}, expected {round_num}"
        )

    return RoundInfo(
        round=int(data["round"]),
        randomness=str(data["randomness"]),
        signature=str(data["signature"]),
    )


# ── Multi-relay fetch with agreement check ────────────────────────────────────


async def fetch_round(
    round_num: int,
    *,
    chain_hash: str | None = None,
    relays: list[str] | None = None,
    timeout: float | None = None,
    min_agreement: int | None = None,
) -> RoundInfo:
    """Fetch `round_num` from all configured relays in parallel; require agreement.

    A "round" returned by ≥ `min_agreement` relays — agreeing on both signature
    and randomness — wins. Any single relay returning something different is
    logged and skipped, NOT trusted to override the majority.

    Defaults come from `settings`:
        chain_hash      → settings.drand_chain_hash
        relays          → settings.drand_relay_list
        timeout         → settings.drand_timeout_secs
        min_agreement   → settings.drand_agreement_threshold

    Raises:
        DrandError: Fewer than `min_agreement` relays returned an agreeing answer.
    """
    chain_hash    = chain_hash    or settings.drand_chain_hash
    relays        = relays        or settings.drand_relay_list
    timeout       = timeout       or float(settings.drand_timeout_secs)
    min_agreement = min_agreement or settings.drand_agreement_threshold

    if not relays:
        raise DrandError("No drand relays configured")

    async with httpx.AsyncClient(timeout=timeout) as client:
        tasks = [
            _fetch_round_one(r, chain_hash, round_num, client=client)
            for r in relays
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    successes: list[tuple[str, RoundInfo]] = []
    errors: list[str] = []
    for relay, res in zip(relays, results):
        if isinstance(res, RoundInfo):
            successes.append((relay, res))
        else:
            errors.append(f"{relay}: {res}")

    if not successes:
        raise DrandError(
            f"All {len(relays)} drand relays failed for round {round_num}:\n  "
            + "\n  ".join(errors)
        )

    # Group by (signature, randomness). The most-agreeing group wins, IF it
    # meets min_agreement. Else fail.
    by_value: Counter[tuple[str, str]] = Counter()
    by_value_examples: dict[tuple[str, str], RoundInfo] = {}
    for _relay, info in successes:
        key = (info.signature, info.randomness)
        by_value[key] += 1
        by_value_examples.setdefault(key, info)

    (winning_key, winning_count) = by_value.most_common(1)[0]

    if winning_count < min_agreement:
        # Either everyone disagrees, or not enough relays responded
        details = ", ".join(
            f"sig={sig[:12]}… × {n}" for (sig, _rand), n in by_value.most_common()
        )
        raise DrandError(
            f"drand relay agreement failed for round {round_num}: "
            f"need ≥ {min_agreement} agreeing, got top group of {winning_count} "
            f"out of {len(successes)} responses ({details})"
        )

    if len(by_value) > 1:
        # Majority succeeded but some relay disagreed — surface it loudly via stderr.
        # We still trust the majority, but the operator should know.
        import sys
        print(
            f"⚠  drand: {len(by_value)} distinct signatures returned for round "
            f"{round_num}; trusting {winning_count}-relay majority. Errors: {errors}",
            file=sys.stderr,
        )

    return by_value_examples[winning_key]


# ── Policy gate (used by reconstruct.py) ──────────────────────────────────────


async def verify_round_published(
    target_round: int,
    *,
    chain_hash: str | None = None,
    now_unix: int | None = None,
) -> RoundInfo:
    """Refuse unless `target_round` has provably published.

    Two checks, in order:
      1. Clock check (cheap, offline): refuse if current_unix < publish_time(target_round).
         This is a fast fail when the operator runs `reconstruct.py` too early.
      2. Network check: fetch target_round from ≥ min_agreement relays. If they
         agree, the round has demonstrably published (drand cannot pre-emit).

    Returns the agreed RoundInfo on success. Raises DrandError on either failure.
    """
    import time

    chain_hash = chain_hash or settings.drand_chain_hash
    genesis = settings.drand_genesis
    period  = settings.drand_period

    now = now_unix if now_unix is not None else int(time.time())
    pub = publish_time(target_round, genesis, period)

    if now < pub:
        wait = pub - now
        raise DrandError(
            f"Refusing to reconstruct: drand round {target_round} publishes "
            f"at unix {pub}, current time is {now} (wait {wait}s). "
            f"This is the wall-clock anchor — the exam is not yet open."
        )

    # Round should now be available from relays. If not, something is wrong
    # (chain outage, wrong chain_hash, manifest tampered) — fail closed.
    info = await fetch_round(target_round, chain_hash=chain_hash)
    return info
