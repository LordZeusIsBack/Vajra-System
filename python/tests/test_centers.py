"""tests/test_centers.py — Unit tests for per-center encryption (Step 2).

What this exercises:
  • Keypair generation: 32-byte privkey/pubkey, hex-encoded, distinct each call
  • Registry: load/save round-trip, duplicate detection, malformed entries
  • Encrypt → decrypt with the matching privkey returns plaintext
  • Wrong privkey fails with CentersError (not silent)
  • Tampered ciphertext / nonce / ephemeral pubkey fails
  • Bulk generate produces a consistent (registry, privkeys) pair
  • Plus an integration check that mirrors the full pipeline shape:
      Shamir split → per-center encrypt → per-center decrypt → Shamir reconstruct

Run with:
    cd python && pytest tests/test_centers.py -v
"""

import json
import os
import secrets

import pytest

# Real HMAC secret before importing config-dependent modules
os.environ.setdefault("MANIFEST_HMAC_SECRET", secrets.token_hex(32))

from centers import (  # noqa: E402
    CenterRegistration,
    CentersError,
    EncryptedShard,
    bulk_generate,
    decrypt_share_with_privkey,
    encrypt_share_for_center,
    generate_keypair,
    load_registry,
    save_registry,
)
from shamir import reconstruct as shamir_reconstruct  # noqa: E402
from shamir import split as shamir_split

# ── Keypair generation ───────────────────────────────────────────────────────

class TestKeypair:
    def test_keypair_shape(self) -> None:
        sk, pk = generate_keypair()
        assert isinstance(sk, str) and isinstance(pk, str)
        assert len(sk) == 64  # 32 bytes hex
        assert len(pk) == 64
        # valid hex
        bytes.fromhex(sk)
        bytes.fromhex(pk)

    def test_keypair_is_fresh_each_call(self) -> None:
        keypairs = [generate_keypair() for _ in range(20)]
        privs = {sk for sk, _ in keypairs}
        pubs  = {pk for _, pk in keypairs}
        assert len(privs) == 20
        assert len(pubs)  == 20


# ── Registry I/O ─────────────────────────────────────────────────────────────

class TestRegistry:
    def _make_centers(self, n: int) -> list[CenterRegistration]:
        return [
            CenterRegistration(id=f"CENTER_{i:03d}", pubkey=generate_keypair()[1])
            for i in range(n)
        ]

    def test_save_load_roundtrip(self, tmp_path) -> None:
        original = self._make_centers(5)
        path = tmp_path / "centers.json"
        save_registry(original, path)
        loaded = load_registry(path)
        assert loaded == original

    def test_load_missing_file(self, tmp_path) -> None:
        with pytest.raises(CentersError, match="not found"):
            load_registry(tmp_path / "does_not_exist.json")

    def test_load_bad_json(self, tmp_path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("not json at all {")
        with pytest.raises(CentersError, match="valid JSON"):
            load_registry(p)

    def test_load_missing_centers_key(self, tmp_path) -> None:
        p = tmp_path / "x.json"
        p.write_text(json.dumps({"foo": []}))
        with pytest.raises(CentersError, match="missing 'centers'"):
            load_registry(p)

    def test_load_empty_registry(self, tmp_path) -> None:
        p = tmp_path / "x.json"
        p.write_text(json.dumps({"centers": []}))
        with pytest.raises(CentersError, match="zero centers"):
            load_registry(p)

    def test_load_duplicate_id(self, tmp_path) -> None:
        p = tmp_path / "x.json"
        p.write_text(json.dumps({"centers": [
            {"id": "A", "pubkey": generate_keypair()[1]},
            {"id": "A", "pubkey": generate_keypair()[1]},
        ]}))
        with pytest.raises(CentersError, match="Duplicate center id"):
            load_registry(p)

    def test_load_duplicate_pubkey(self, tmp_path) -> None:
        pk = generate_keypair()[1]
        p = tmp_path / "x.json"
        p.write_text(json.dumps({"centers": [
            {"id": "A", "pubkey": pk},
            {"id": "B", "pubkey": pk},
        ]}))
        with pytest.raises(CentersError, match="Duplicate pubkey"):
            load_registry(p)

    def test_load_malformed_pubkey(self, tmp_path) -> None:
        p = tmp_path / "x.json"
        p.write_text(json.dumps({"centers": [
            {"id": "A", "pubkey": "ab"},  # 1 byte, not 32
        ]}))
        with pytest.raises(CentersError, match="32 bytes"):
            load_registry(p)


# ── Encrypt / decrypt round-trip ──────────────────────────────────────────────

class TestEncryptDecrypt:
    def test_roundtrip_simple(self) -> None:
        sk, pk = generate_keypair()
        share = b"this is a shamir share, 33 bytes."
        assert len(share) == 33  # match the real format
        enc = encrypt_share_for_center(share, pk)
        plain = decrypt_share_with_privkey(enc, sk)
        assert plain == share

    def test_roundtrip_various_sizes(self) -> None:
        sk, pk = generate_keypair()
        for size in (1, 17, 33, 256, 1024, 4096):
            share = secrets.token_bytes(size)
            enc = encrypt_share_for_center(share, pk)
            assert decrypt_share_with_privkey(enc, sk) == share

    def test_encrypt_empty_share_refused(self) -> None:
        _sk, pk = generate_keypair()
        with pytest.raises(CentersError, match="empty share"):
            encrypt_share_for_center(b"", pk)

    def test_each_encrypt_uses_fresh_ephemeral(self) -> None:
        """Two encrypts of the same plaintext to the same pubkey must produce
        different ephemeral pubkeys (and hence different ciphertexts)."""
        _sk, pk = generate_keypair()
        share = b"x" * 33
        e1 = encrypt_share_for_center(share, pk)
        e2 = encrypt_share_for_center(share, pk)
        assert e1.eph_pubkey != e2.eph_pubkey
        assert e1.ciphertext != e2.ciphertext
        assert e1.nonce      != e2.nonce  # fresh random nonce each time too

    def test_wrong_privkey_fails(self) -> None:
        sk_right, pk = generate_keypair()
        sk_wrong, _  = generate_keypair()
        enc = encrypt_share_for_center(b"secret share data here", pk)
        # Right key works
        decrypt_share_with_privkey(enc, sk_right)
        # Wrong key fails
        with pytest.raises(CentersError, match="decryption failed"):
            decrypt_share_with_privkey(enc, sk_wrong)

    def test_tampered_ciphertext_fails(self) -> None:
        sk, pk = generate_keypair()
        enc = encrypt_share_for_center(b"hello world hello world hello wo", pk)
        # Flip one byte in the ciphertext
        ct_bytes = bytearray.fromhex(enc.ciphertext)
        ct_bytes[0] ^= 0x01
        tampered = EncryptedShard(
            eph_pubkey=enc.eph_pubkey, nonce=enc.nonce, ciphertext=ct_bytes.hex(),
        )
        with pytest.raises(CentersError, match="decryption failed"):
            decrypt_share_with_privkey(tampered, sk)

    def test_tampered_ephemeral_pubkey_fails(self) -> None:
        sk, pk = generate_keypair()
        enc = encrypt_share_for_center(b"data data data data data data dat", pk)
        # Swap eph_pubkey for a totally different point
        _, other_pk = generate_keypair()
        tampered = EncryptedShard(
            eph_pubkey=other_pk, nonce=enc.nonce, ciphertext=enc.ciphertext,
        )
        with pytest.raises(CentersError, match="decryption failed"):
            decrypt_share_with_privkey(tampered, sk)

    def test_malformed_eph_pubkey_size(self) -> None:
        sk, _ = generate_keypair()
        bad = EncryptedShard(eph_pubkey="ab" * 5, nonce="00" * 12, ciphertext="00" * 20)
        with pytest.raises(CentersError, match="Ephemeral pubkey"):
            decrypt_share_with_privkey(bad, sk)

    def test_malformed_nonce_size(self) -> None:
        sk, _ = generate_keypair()
        bad = EncryptedShard(eph_pubkey="ab" * 32, nonce="00" * 5, ciphertext="00" * 20)
        with pytest.raises(CentersError, match="Nonce must be 12 bytes"):
            decrypt_share_with_privkey(bad, sk)

    def test_to_from_dict_roundtrip(self) -> None:
        _sk, pk = generate_keypair()
        enc = encrypt_share_for_center(b"x" * 33, pk)
        d = enc.to_dict()
        assert "eph_pubkey_hex" in d
        assert "nonce_hex" in d
        assert "ciphertext_hex" in d
        round_tripped = EncryptedShard.from_dict(d)
        assert round_tripped == enc


# ── Bulk generation ───────────────────────────────────────────────────────────

class TestBulk:
    def test_bulk_basic(self) -> None:
        registry, privkeys = bulk_generate(5)
        assert len(registry) == 5
        assert len(privkeys) == 5
        # IDs match between the two lists
        assert [r.id for r in registry] == [cid for cid, _ in privkeys]
        # All pubkeys distinct
        assert len({r.pubkey for r in registry}) == 5
        # All privkeys distinct
        assert len({pk for _, pk in privkeys}) == 5
        # Privkey/pubkey are a real pair: encrypt to pubkey, decrypt with privkey
        for reg, (cid, sk) in zip(registry, privkeys):
            assert reg.id == cid
            enc = encrypt_share_for_center(b"test test test test test test te", reg.pubkey)
            assert decrypt_share_with_privkey(enc, sk) == b"test test test test test test te"

    def test_bulk_id_prefix(self) -> None:
        registry, _ = bulk_generate(3, id_prefix="DELHI")
        assert [r.id for r in registry] == ["DELHI_000", "DELHI_001", "DELHI_002"]

    def test_bulk_rejects_zero(self) -> None:
        with pytest.raises(CentersError):
            bulk_generate(0)

    def test_bulk_rejects_too_many(self) -> None:
        with pytest.raises(CentersError):
            bulk_generate(1000)


# ── Full integration: Shamir × per-center (what the pipeline actually does) ───

class TestPipelineIntegration:
    def test_full_chain_n10_k8(self) -> None:
        """Mirror the entire shard half of the lock pipeline + reconstruct:
        Shamir-split a secret, encrypt each share to a different center's
        pubkey, then decrypt k of them and Shamir-combine. Must equal secret."""
        secret = secrets.token_bytes(32)
        registry, privkeys = bulk_generate(10)

        # Lock-side
        shares = shamir_split(secret, n=10, k=8)
        encrypted = [
            encrypt_share_for_center(share, reg.pubkey)
            for share, reg in zip(shares, registry)
        ]

        # Reconstruct-side: cooperators 0, 2, 3, 5, 6, 7, 8, 9 (= 8 = k)
        cooperating = [0, 2, 3, 5, 6, 7, 8, 9]
        decrypted_shares = [
            decrypt_share_with_privkey(encrypted[i], privkeys[i][1])
            for i in cooperating
        ]

        recovered = shamir_reconstruct(decrypted_shares, expected_threshold=8)
        assert recovered == secret

    def test_full_chain_too_few_cooperators_fails(self) -> None:
        """Fewer than k decrypted shares + expected_threshold guard → ValueError."""
        secret = secrets.token_bytes(32)
        registry, privkeys = bulk_generate(10)
        shares = shamir_split(secret, n=10, k=8)
        encrypted = [encrypt_share_for_center(s, r.pubkey) for s, r in zip(shares, registry)]

        # Only 7 cooperators (< k=8)
        decrypted = [
            decrypt_share_with_privkey(encrypted[i], privkeys[i][1])
            for i in range(7)
        ]
        with pytest.raises(ValueError, match="at least 8"):
            shamir_reconstruct(decrypted, expected_threshold=8)

    def test_full_chain_wrong_privkey_swap(self) -> None:
        """If a center somehow uses center 5's privkey on center 3's shard,
        decryption should fail loudly."""
        registry, privkeys = bulk_generate(10)
        shares = shamir_split(secrets.token_bytes(32), n=10, k=8)
        enc_3 = encrypt_share_for_center(shares[3], registry[3].pubkey)
        wrong_sk = privkeys[5][1]
        with pytest.raises(CentersError, match="decryption failed"):
            decrypt_share_with_privkey(enc_3, wrong_sk)
