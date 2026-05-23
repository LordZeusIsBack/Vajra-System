"""tests/test_roundtrip.py — Core crypto round-trip without IPFS or Rust.

What this exercises:
  • Shamir split → reconstruct (with and without enough shares)
  • Outer AES-GCM wrap of a fake "locked.json" → unwrap
  • Manifest build_and_sign → verify (and tamper detection)

What this deliberately skips:
  • The RSW puzzle itself (that's tested by `cargo test` on the Rust side)
  • IPFS upload/fetch (mock or run a local Kubo daemon for that)
  • The full FastAPI lock endpoint (needs a test client + Rust binary)

Run with:
    cd python && pytest tests/ -v
"""

import os
import secrets

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Set a real HMAC secret BEFORE importing anything that loads config
os.environ.setdefault(
    "MANIFEST_HMAC_SECRET",
    secrets.token_hex(32),  # fresh per test session
)

from shamir import split as shamir_split, reconstruct as shamir_reconstruct  # noqa: E402
from manifest import build_and_sign, verify as verify_manifest  # noqa: E402


# ── Shamir ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("n,k", [(3, 2), (5, 3), (10, 8), (20, 15), (50, 25)])
def test_shamir_roundtrip(n: int, k: int) -> None:
    secret = secrets.token_bytes(32)
    shares = shamir_split(secret, n, k)
    assert len(shares) == n
    assert all(len(s) == 33 for s in shares)  # 1-byte x + 32-byte secret

    # Exactly k shares
    assert shamir_reconstruct(shares[:k], expected_threshold=k) == secret
    # More than k shares
    assert shamir_reconstruct(shares, expected_threshold=k) == secret


def test_shamir_rejects_too_few_with_threshold() -> None:
    secret = secrets.token_bytes(32)
    shares = shamir_split(secret, 10, 8)
    with pytest.raises(ValueError, match="at least 8"):
        shamir_reconstruct(shares[:5], expected_threshold=8)


def test_shamir_silent_wrong_without_threshold() -> None:
    """Without the threshold guard, too-few shares yield a (wrong) result with no error.
    This documents the hazard; downstream AES-GCM auth catches it in practice."""
    secret = secrets.token_bytes(32)
    shares = shamir_split(secret, 10, 8)
    wrong = shamir_reconstruct(shares[:5])  # no expected_threshold
    assert wrong != secret  # near-certain; trivially possible to collide


def test_shamir_rejects_duplicate_x() -> None:
    secret = secrets.token_bytes(16)
    shares = shamir_split(secret, 5, 3)
    with pytest.raises(ValueError, match="Duplicate"):
        shamir_reconstruct([shares[0], shares[0], shares[1]])


# ── Outer AES-GCM wrap (data_key layer) ───────────────────────────────────────

def test_outer_wrap_unwrap_roundtrip() -> None:
    fake_locked_json = b'{"nonce":"deadbeef","ciphertext":"cafebabe"}'
    data_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)

    wrapped = AESGCM(data_key).encrypt(nonce, fake_locked_json, None)
    unwrapped = AESGCM(data_key).decrypt(nonce, wrapped, None)
    assert unwrapped == fake_locked_json


def test_outer_wrap_detects_tamper() -> None:
    data_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    wrapped = AESGCM(data_key).encrypt(nonce, b"hello", None)

    tampered = bytearray(wrapped)
    tampered[0] ^= 0x01  # flip one bit
    with pytest.raises(Exception):  # InvalidTag
        AESGCM(data_key).decrypt(nonce, bytes(tampered), None)


def test_outer_wrap_detects_wrong_key() -> None:
    nonce = secrets.token_bytes(12)
    wrapped = AESGCM(secrets.token_bytes(32)).encrypt(nonce, b"hello", None)
    with pytest.raises(Exception):
        AESGCM(secrets.token_bytes(32)).decrypt(nonce, wrapped, None)


# ── Full Shamir + AES-GCM chain (what reconstruct.py does mid-pipeline) ───────

def test_shamir_plus_aesgcm_chain() -> None:
    """Simulate the heart of reconstruct.py without IPFS or Rust:
    data_key is Shamir-split, then used to wrap a fake locked.json.
    Verify we can re-derive data_key from k shards and unwrap."""
    fake_locked_json = secrets.token_bytes(2048)  # stand-in for real locked.json
    data_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)

    wrapped = AESGCM(data_key).encrypt(nonce, fake_locked_json, None)
    shares = shamir_split(data_key, n=10, k=8)

    # Centers pick any 8 of 10
    chosen = [shares[i] for i in (0, 2, 3, 5, 6, 7, 8, 9)]
    recovered_key = shamir_reconstruct(chosen, expected_threshold=8)
    assert recovered_key == data_key

    recovered_locked = AESGCM(recovered_key).decrypt(nonce, wrapped, None)
    assert recovered_locked == fake_locked_json


# ── Manifest signing ──────────────────────────────────────────────────────────

def _sample_manifest_kwargs(n: int = 10) -> dict:
    return {
        "n": n,
        "k": 8,
        "puzzle_cid": "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        "payload_cid": "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzaa",
        "nonce_hex": "00" * 12,
        "shard_cids": [
            {"cid": f"bafy_shard_{i:03d}", "node_index": i % 3}
            for i in range(n)
        ],
        "exam_id": "11111111-2222-3333-4444-555555555555",
    }


def test_manifest_roundtrip() -> None:
    m = build_and_sign(**_sample_manifest_kwargs())
    assert verify_manifest(m) is True
    assert m["version"] == "1.1"
    assert "hmac" in m
    assert len(m["shard_cids"]) == m["n"]


def test_manifest_detects_tamper_in_puzzle_cid() -> None:
    m = build_and_sign(**_sample_manifest_kwargs())
    m["puzzle_cid"] = "bafyTAMPERED"
    assert verify_manifest(m) is False


def test_manifest_detects_tamper_in_shard_cids() -> None:
    m = build_and_sign(**_sample_manifest_kwargs())
    m["shard_cids"][3]["cid"] = "bafyEVIL"
    assert verify_manifest(m) is False


def test_manifest_rejects_missing_hmac() -> None:
    m = build_and_sign(**_sample_manifest_kwargs())
    m.pop("hmac")
    assert verify_manifest(m) is False


def test_manifest_shard_count_mismatch_raises() -> None:
    kwargs = _sample_manifest_kwargs(n=10)
    kwargs["n"] = 11  # n claims 11 but shard_cids has 10
    with pytest.raises(ValueError, match="Expected 11"):
        build_and_sign(**kwargs)
