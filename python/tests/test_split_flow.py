"""tests/test_split_flow.py — Tests for the decentralized reconstruction CLIs.

What this exercises:
  • Share-file load/save round-trip and rejection of malformed share files
  • Coordinator catches: missing fields, wrong manifest_cid, duplicate indices,
    wrong center_id at a given index, too few shares
  • The full split-flow chain WITHOUT any per-machine separation actually being
    enforced (this is a unit test, not a deployment test — but we can still
    verify each machine "would" only see what it should)

What this skips:
  • Live IPFS (uses an in-memory fake)
  • Live drand network (uses --skip-drand-check)
  • The Rust `vajra solve` step (mocked — we test the python pipeline, not
    the puzzle solver; that's tested in the Rust integration test)

Run with:
    cd python && pytest tests/test_split_flow.py -v
"""

from __future__ import annotations

import json
import os
import secrets

import pytest

# Real HMAC secret before importing modules that load config
os.environ.setdefault("MANIFEST_HMAC_SECRET", secrets.token_hex(32))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

from centers import (  # noqa: E402
    bulk_generate,
    encrypt_share_for_center,
)
from drand_client import derive_aad  # noqa: E402
from manifest import build_and_sign  # noqa: E402
from reconstruct import ReconstructError  # noqa: E402
from shamir import split as shamir_split  # noqa: E402
from vajra_coordinator import _load_share_file, coordinate  # noqa: E402
from vajra_center import decrypt_my_share  # noqa: E402


# ── A minimal in-memory IPFSClient fake ───────────────────────────────────────
# We don't import IPFSClient and monkey-patch httpx because it's simpler to
# pass our own object to the functions under test — they only call methods,
# not constructors.


class FakeIPFSClient:
    """Just enough of IPFSClient to satisfy reconstruct/coordinator/center.

    Stores blobs (bytes) and JSONs in two dicts keyed by CID. CIDs are
    deterministic SHA-256-based strings so tests can predict them.
    """

    def __init__(self) -> None:
        self._json: dict[str, dict]  = {}
        self._raw:  dict[str, bytes] = {}
        self.node_count = 4  # match production default

    # --- store ---

    def put_json(self, cid: str, obj: dict) -> None:
        self._json[cid] = obj

    def put_raw(self, cid: str, data: bytes) -> None:
        self._raw[cid] = data

    # --- API expected by the code under test ---

    async def cat_json(self, cid: str, *, node_index: int = 0) -> dict:
        if cid not in self._json:
            from ipfs_client import IPFSError
            raise IPFSError(f"fake: no JSON at CID {cid}")
        return self._json[cid]

    async def cat(self, cid: str, *, node_index: int = 0) -> bytes:
        if cid not in self._raw:
            from ipfs_client import IPFSError
            raise IPFSError(f"fake: no raw at CID {cid}")
        return self._raw[cid]


# ── Test scaffolding: build a complete lock-state in memory ───────────────────


def _build_locked_exam(n: int = 5, k: int = 3) -> dict:
    """Build a valid locked exam in memory (no IPFS, no Rust, no drand).

    Returns a dict with:
        ipfs:            FakeIPFSClient pre-populated with payload + shards
        manifest_cid:    CID to feed into the coordinator/center
        manifest:        The signed manifest (also pinned at manifest_cid)
        registry:        list[CenterRegistration]
        privkeys:        list[(id, privkey_hex)]
        data_key:        the random data_key (for sanity-checking)
        locked_bytes:    fake "locked.json" plaintext (so we can verify
                         coordinator unwraps correctly)
    """
    ipfs = FakeIPFSClient()
    registry, privkeys = bulk_generate(n)

    # Pick a drand round + chain hash for AAD purposes (any will do here)
    chain_hash   = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
    target_round = 99999
    publish_t    = 1595431050 + 30 * target_round
    aad          = derive_aad(target_round, chain_hash)

    # Stand-in for the real Rust output. We don't run vajra solve in this test
    # — the coordinator's combine_shares_to_pdf will eventually shell out, and
    # that fails because vajra isn't installed. So we'll explicitly avoid
    # calling combine_shares_to_pdf in tests that go end-to-end; instead we
    # stop at "Shamir reconstructed data_key matches" and check the AES-GCM
    # unwrap separately.
    fake_locked_json = b'{"this is the fake inner locked.json contents"}'
    data_key = secrets.token_bytes(32)
    nonce    = secrets.token_bytes(12)
    payload  = AESGCM(data_key).encrypt(nonce, fake_locked_json, aad)

    # Shamir-split, encrypt per-center
    shares    = shamir_split(data_key, n, k)
    encrypted = [encrypt_share_for_center(s, r.pubkey) for s, r in zip(shares, registry)]

    # Pin payload + each shard at deterministic CIDs
    payload_cid = "bafy_payload_test"
    puzzle_cid  = "bafy_puzzle_test"
    ipfs.put_raw(payload_cid, payload)
    ipfs.put_raw(puzzle_cid, b'{"fake puzzle"}')

    shard_cid_entries = []
    for i, enc in enumerate(encrypted):
        shard_cid = f"bafy_shard_{i:03d}_test"
        shard_obj = {
            "shard_index":    i,
            "center_id":      registry[i].id,
            "center_pubkey":  registry[i].pubkey,
            "eph_pubkey_hex": enc.eph_pubkey,
            "nonce_hex":      enc.nonce,
            "ciphertext_hex": enc.ciphertext,
            "payload_cid":    payload_cid,
            "outer_nonce_hex": nonce.hex(),
            "puzzle_cid":     puzzle_cid,
        }
        ipfs.put_json(shard_cid, shard_obj)
        shard_cid_entries.append({"cid": shard_cid, "node_index": i % ipfs.node_count})

    # Build + pin manifest
    manifest = build_and_sign(
        n=n, k=k,
        puzzle_cid=puzzle_cid,
        payload_cid=payload_cid,
        nonce_hex=nonce.hex(),
        shard_cids=shard_cid_entries,
        centers=[
            {"index": i, "id": r.id, "pubkey": r.pubkey}
            for i, r in enumerate(registry)
        ],
        drand={
            "chain_hash":   chain_hash,
            "target_round": target_round,
            "publish_time": publish_t,
        },
    )
    manifest_cid = "bafy_manifest_test"
    ipfs.put_json(manifest_cid, manifest)

    return {
        "ipfs":         ipfs,
        "manifest_cid": manifest_cid,
        "manifest":     manifest,
        "registry":     registry,
        "privkeys":     privkeys,
        "data_key":     data_key,
        "locked_bytes": fake_locked_json,
        "aad":          aad,
        "nonce":        nonce,
    }


# ── Center-side: decrypt_my_share writes a correct share file ─────────────────


class TestCenterDecrypt:
    @pytest.mark.asyncio
    async def test_decrypt_my_share_writes_valid_share_file(self, tmp_path) -> None:
        state = _build_locked_exam(n=5, k=3)
        # CENTER_002 decrypts their shard
        cid_str, sk_hex = state["privkeys"][2]
        kp_path = tmp_path / "my_keypair.json"
        kp_path.write_text(json.dumps({
            "id": cid_str,
            "privkey": sk_hex,
            "pubkey": state["registry"][2].pubkey,
        }))

        out_path = tmp_path / "share_002.json"
        await decrypt_my_share(
            state["manifest_cid"], kp_path, out_path, state["ipfs"],
        )

        # Validate the share file
        share = json.loads(out_path.read_text())
        assert share["center_id"]    == cid_str
        assert share["center_index"] == 2
        assert share["manifest_cid"] == state["manifest_cid"]
        # share_hex is a real 33-byte Shamir share (1 byte x + 32 bytes f_b(x))
        share_bytes = bytes.fromhex(share["share_hex"])
        assert len(share_bytes) == 33
        # x-coord is in 1..n (Shamir uses 1-indexed x)
        assert 1 <= share_bytes[0] <= 5

    @pytest.mark.asyncio
    async def test_decrypt_my_share_wrong_keypair_for_exam(self, tmp_path) -> None:
        """A keypair generated for a different bulk-gen run should be rejected
        because its center_id won't appear in the manifest."""
        state = _build_locked_exam(n=5, k=3)
        # Use a keypair generated independently (id won't match)
        other_registry, other_privs = bulk_generate(1, id_prefix="OTHER")
        kp_path = tmp_path / "wrong.json"
        kp_path.write_text(json.dumps({
            "id": other_registry[0].id,
            "privkey": other_privs[0][1],
            "pubkey": other_registry[0].pubkey,
        }))

        out_path = tmp_path / "should_not_exist.json"
        with pytest.raises(ReconstructError, match="not in the manifest"):
            await decrypt_my_share(
                state["manifest_cid"], kp_path, out_path, state["ipfs"],
            )
        assert not out_path.exists()

    @pytest.mark.asyncio
    async def test_decrypt_my_share_corrupted_privkey_fails_cleanly(self, tmp_path) -> None:
        """A keypair with the right id but a wrong privkey should fail at
        decryption time (not silently produce garbage)."""
        state = _build_locked_exam(n=5, k=3)
        cid_str, _sk_hex = state["privkeys"][2]
        # Right id, wrong privkey
        kp_path = tmp_path / "evil.json"
        kp_path.write_text(json.dumps({
            "id": cid_str,
            "privkey": secrets.token_hex(32),
            "pubkey": state["registry"][2].pubkey,
        }))

        out_path = tmp_path / "should_not_exist.json"
        with pytest.raises(ReconstructError, match="Cannot decrypt shard"):
            await decrypt_my_share(
                state["manifest_cid"], kp_path, out_path, state["ipfs"],
            )
        assert not out_path.exists()

    @pytest.mark.asyncio
    async def test_decrypt_my_share_rejects_tampered_manifest(
        self, tmp_path, monkeypatch
    ) -> None:
        """If the manifest fetched from IPFS fails HMAC, refuse to decrypt
        — protects against a malicious coordinator serving a fake manifest
        with the same CID as a legit one (impossible on real IPFS but worth
        modelling)."""
        from vajra_center import ManifestVerificationError
        state = _build_locked_exam(n=5, k=3)
        # Tamper: swap manifest's HMAC field for garbage
        tampered = dict(state["manifest"])
        tampered["hmac"] = "00" * 32
        state["ipfs"].put_json(state["manifest_cid"], tampered)

        cid_str, sk_hex = state["privkeys"][0]
        kp_path = tmp_path / "kp.json"
        kp_path.write_text(json.dumps({
            "id": cid_str, "privkey": sk_hex,
            "pubkey": state["registry"][0].pubkey,
        }))

        with pytest.raises(ManifestVerificationError):
            await decrypt_my_share(
                state["manifest_cid"], kp_path, tmp_path / "x.json", state["ipfs"],
            )


# ── Share file format ─────────────────────────────────────────────────────────


class TestShareFile:
    def test_load_share_file_roundtrip(self, tmp_path) -> None:
        p = tmp_path / "s.json"
        p.write_text(json.dumps({
            "manifest_cid": "bafy_test",
            "center_id": "CENTER_001",
            "center_index": 1,
            "share_hex": "01" + "ab" * 32,
            "exam_id": "e1",
        }))
        loaded = _load_share_file(p, "bafy_test")
        assert loaded["center_id"] == "CENTER_001"
        assert loaded["center_index"] == 1
        assert len(loaded["share_bytes"]) == 33

    def test_load_share_file_wrong_manifest_cid(self, tmp_path) -> None:
        p = tmp_path / "s.json"
        p.write_text(json.dumps({
            "manifest_cid": "bafy_other_exam",
            "center_id": "CENTER_001",
            "center_index": 1,
            "share_hex": "01" + "ab" * 32,
            "exam_id": "e1",
        }))
        with pytest.raises(ReconstructError, match="not 'bafy_target'"):
            _load_share_file(p, "bafy_target")

    def test_load_share_file_missing_fields(self, tmp_path) -> None:
        p = tmp_path / "s.json"
        p.write_text(json.dumps({"manifest_cid": "bafy_x"}))  # missing share_hex etc.
        with pytest.raises(ReconstructError, match="missing fields"):
            _load_share_file(p, "bafy_x")

    def test_load_share_file_bad_hex(self, tmp_path) -> None:
        p = tmp_path / "s.json"
        p.write_text(json.dumps({
            "manifest_cid": "bafy_x",
            "center_id": "C",
            "center_index": 0,
            "share_hex": "not hex !",
        }))
        with pytest.raises(ReconstructError, match="invalid hex"):
            _load_share_file(p, "bafy_x")


# ── Coordinator: refuses bad collections of share files ───────────────────────


def _write_share(
    path,
    *,
    manifest_cid: str,
    center_id: str,
    center_index: int,
    share_hex: str,
) -> None:
    path.write_text(json.dumps({
        "manifest_cid": manifest_cid,
        "center_id":    center_id,
        "center_index": center_index,
        "share_hex":    share_hex,
        "exam_id":      "any",
    }))


class TestCoordinatorValidation:
    @pytest.mark.asyncio
    async def test_too_few_shares(self, tmp_path) -> None:
        state = _build_locked_exam(n=5, k=3)
        # Only write 2 shares (< k=3)
        for i in range(2):
            _write_share(
                tmp_path / f"share_{i}.json",
                manifest_cid=state["manifest_cid"],
                center_id=state["registry"][i].id,
                center_index=i,
                share_hex="01" + "00" * 32,
            )
        with pytest.raises(ReconstructError, match="Need ≥ 3"):
            await coordinate(
                state["manifest_cid"],
                [str(tmp_path / f"share_{i}.json") for i in range(2)],
                vajra_binary="/usr/bin/false",  # never reached
                ipfs=state["ipfs"],
                skip_drand_check=True,
            )

    @pytest.mark.asyncio
    async def test_duplicate_indices_rejected(self, tmp_path) -> None:
        state = _build_locked_exam(n=5, k=3)
        # Three shares but two have the same center_index
        _write_share(tmp_path / "a.json",
                     manifest_cid=state["manifest_cid"],
                     center_id=state["registry"][0].id, center_index=0,
                     share_hex="01" + "00" * 32)
        _write_share(tmp_path / "b.json",
                     manifest_cid=state["manifest_cid"],
                     center_id=state["registry"][0].id, center_index=0,  # dup
                     share_hex="01" + "11" * 32)
        _write_share(tmp_path / "c.json",
                     manifest_cid=state["manifest_cid"],
                     center_id=state["registry"][2].id, center_index=2,
                     share_hex="03" + "22" * 32)
        with pytest.raises(ReconstructError, match="duplicate submission"):
            await coordinate(
                state["manifest_cid"],
                [str(tmp_path / x) for x in ("a.json", "b.json", "c.json")],
                vajra_binary="/usr/bin/false",
                ipfs=state["ipfs"],
                skip_drand_check=True,
            )

    @pytest.mark.asyncio
    async def test_share_with_wrong_center_id_at_index_rejected(self, tmp_path) -> None:
        """A share claiming center_index=2 must have the id that the manifest
        says is at index 2. Otherwise, refuse."""
        state = _build_locked_exam(n=5, k=3)
        _write_share(tmp_path / "a.json",
                     manifest_cid=state["manifest_cid"],
                     center_id=state["registry"][0].id, center_index=0,
                     share_hex="01" + "00" * 32)
        _write_share(tmp_path / "b.json",
                     manifest_cid=state["manifest_cid"],
                     center_id=state["registry"][1].id, center_index=1,
                     share_hex="02" + "11" * 32)
        # Wrong: claims index 2 but uses center 4's id
        _write_share(tmp_path / "c.json",
                     manifest_cid=state["manifest_cid"],
                     center_id=state["registry"][4].id, center_index=2,
                     share_hex="03" + "22" * 32)
        with pytest.raises(ReconstructError, match="Refusing — possibly malicious"):
            await coordinate(
                state["manifest_cid"],
                [str(tmp_path / x) for x in ("a.json", "b.json", "c.json")],
                vajra_binary="/usr/bin/false",
                ipfs=state["ipfs"],
                skip_drand_check=True,
            )


# ── Full split-flow round-trip (everything except `vajra solve`) ──────────────


class TestSplitFlowRoundtrip:
    """The most important test: an end-to-end run of the decentralized flow.

    We stop one step short of `vajra solve` because that requires the Rust
    binary. Instead, we verify that combine_shares_to_pdf would successfully
    recover the data_key + unwrap the outer AES-GCM layer — which is exactly
    what would fail if the split flow were broken at the Python layer."""

    @pytest.mark.asyncio
    async def test_split_flow_recovers_data_key(self, tmp_path) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from shamir import reconstruct as shamir_reconstruct

        state = _build_locked_exam(n=5, k=3)

        # Simulate three centers each running vajra_center decrypt-share on
        # their own machines. Each one only ever holds its own keypair.
        share_paths = []
        for i in (0, 2, 4):  # any k=3 out of n=5
            cid_str, sk_hex = state["privkeys"][i]
            kp_path = tmp_path / f"kp_{i}.json"
            kp_path.write_text(json.dumps({
                "id": cid_str, "privkey": sk_hex,
                "pubkey": state["registry"][i].pubkey,
            }))
            out_path = tmp_path / f"share_{i}.json"
            await decrypt_my_share(
                state["manifest_cid"], kp_path, out_path, state["ipfs"],
            )
            share_paths.append(out_path)

        # Now the coordinator loads them and runs the combine logic up to (but
        # not including) `vajra solve`. We replicate the relevant prefix of
        # combine_shares_to_pdf here so the test doesn't need the Rust binary.
        plaintext_shares = []
        for p in share_paths:
            data = json.loads(p.read_text())
            plaintext_shares.append(bytes.fromhex(data["share_hex"]))

        # Shamir combine
        recovered_data_key = shamir_reconstruct(plaintext_shares, expected_threshold=3)
        assert recovered_data_key == state["data_key"], (
            "Split flow must recover the exact same data_key as was used "
            "at lock time."
        )

        # Outer AES-GCM unwrap with the AAD from the manifest
        unwrapped = AESGCM(recovered_data_key).decrypt(
            state["nonce"],
            state["ipfs"]._raw[state["manifest"]["payload_cid"]],
            associated_data=state["aad"],
        )
        assert unwrapped == state["locked_bytes"]
