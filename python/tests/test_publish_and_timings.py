"""tests/test_publish_and_timings.py — Service upload path and stage measurements.

What this exercises:
  • lock_publish.publish_locked_exam: object placement (control objects on
    node 0, shards round-robin), the number of objects actually created
    (n shards + puzzle + payload + manifest), bytes uploaded, and the
    PublishError raised when a node fails.
  • With the compiled Rust binary (skipped otherwise):
      – run_vajra_pipeline(timings=…) reports per-stage times, the Rust stage
        breakdown, and the peak memory of the Rust subprocesses;
      – the full lock → publish → center decrypt → combine flow, with
        combine_shares_to_pdf(stage_times=…) recording when each stage ended.

Run with:
    cd python && pytest tests/test_publish_and_timings.py -v
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import secrets
from pathlib import Path

import pytest

os.environ.setdefault("MANIFEST_HMAC_SECRET", secrets.token_hex(32))

from centers import bulk_generate, encrypt_share_for_center
from ipfs_client import IPFSError
from lock_publish import PublishError, publish_locked_exam
from manifest import verify as verify_manifest
from reconstruct import (
    combine_shares_to_pdf,
    fetch_and_decrypt_one_shard,
)
from shamir import split as shamir_split

REPO_ROOT = Path(__file__).resolve().parents[2]
_EXE = "vajra.exe" if platform.system() == "Windows" else "vajra"
VAJRA_BIN = REPO_ROOT / "rust" / "target" / "release" / _EXE
needs_rust = pytest.mark.skipif(
    not VAJRA_BIN.exists(), reason="compiled vajra binary not found (make rs-build)"
)


class NodeStore:
    """In-memory multi-node IPFS stand-in with content-derived CIDs."""

    def __init__(self, node_count: int = 3, fail_node: int | None = None) -> None:
        self.node_count = node_count
        self.nodes: list[dict[str, bytes]] = [{} for _ in range(node_count)]
        self.fail_node = fail_node

    async def add_bytes(self, data: bytes, filename: str = "blob", *, node_index: int = 0) -> str:
        node = node_index % self.node_count
        if node == self.fail_node:
            raise IPFSError(f"node {node} refused the upload")
        cid = "fake" + hashlib.sha256(data).hexdigest()[:40]
        self.nodes[node][cid] = data
        return cid

    async def add_json(self, obj: dict, filename: str = "data.json", *, node_index: int = 0) -> str:
        blob = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
        return await self.add_bytes(blob, filename, node_index=node_index)

    async def cat(self, cid: str, *, node_index: int = 0) -> bytes:
        store = self.nodes[node_index % self.node_count]
        if cid not in store:
            raise IPFSError(f"{cid} not on node {node_index}")
        return store[cid]

    async def cat_json(self, cid: str, *, node_index: int = 0) -> dict:
        return json.loads(await self.cat(cid, node_index=node_index))


def _synthetic_outputs(n: int, k: int) -> dict:
    registry, _ = bulk_generate(n)
    shares = shamir_split(secrets.token_bytes(32), n, k)
    return {
        "n": n,
        "k": k,
        "puzzle_params": {"n": "0a", "g": "04", "t_ops": 1, "ref_squarings_per_sec": 1},
        "double_locked": secrets.token_bytes(1000),
        "encrypted_shards": [
            encrypt_share_for_center(s, registry[i].pubkey).to_dict() for i, s in enumerate(shares)
        ],
        "nonce_hex": secrets.token_bytes(12).hex(),
        "drand_info": {
            "chain_hash": "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce",
            "target_round": 99999,
            "publish_time": 1595431050 + 30 * 99999,
        },
        "centers_meta": [{"index": i, "id": r.id, "pubkey": r.pubkey} for i, r in enumerate(registry)],
    }


# ── Publishing ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("n,k,nodes", [(5, 3, 3), (10, 8, 3), (10, 8, 10)])
def test_publish_creates_n_plus_3_objects_with_service_placement(n, k, nodes):
    ipfs = NodeStore(node_count=nodes)
    stats: dict = {}
    manifest_cid, manifest = asyncio.run(
        publish_locked_exam(ipfs, stats=stats, **_synthetic_outputs(n, k))
    )

    assert verify_manifest(manifest)
    assert stats["objects_created"] == n + 3, "n shards + puzzle + payload + manifest"
    stored = sum(len(store) for store in ipfs.nodes)
    assert stored == n + 3
    assert stats["bytes_uploaded"] == sum(len(b) for store in ipfs.nodes for b in store.values())

    # Control objects live on node 0; shard i on node i mod node_count.
    for cid in (manifest_cid, manifest["puzzle_cid"], manifest["payload_cid"]):
        assert cid in ipfs.nodes[0]
    for i, entry in enumerate(manifest["shard_cids"]):
        assert entry["node_index"] == i % nodes
        assert entry["cid"] in ipfs.nodes[i % nodes]

    expected = {node: 0 for node in range(nodes)}
    for i in range(n):
        expected[i % nodes] += 1
    expected[0] += 3
    assert stats["objects_per_node"] == {node: c for node, c in expected.items() if c}
    for key in ("puzzle_upload_sec", "payload_upload_sec", "shards_upload_sec", "manifest_upload_sec"):
        assert stats[key] >= 0


def test_publish_reports_failing_stage():
    ipfs = NodeStore(node_count=3, fail_node=2)
    with pytest.raises(PublishError) as exc:
        asyncio.run(publish_locked_exam(ipfs, **_synthetic_outputs(5, 3)))
    assert exc.value.stage == "objects"


# ── Full flow with the Rust binary ────────────────────────────────────────────


def _lock_and_publish(n: int = 5, k: int = 3, timings: dict | None = None):
    os.environ["VAJRA_BIN"] = str(VAJRA_BIN)
    import config
    from lock_pipeline import run_vajra_pipeline

    config.settings.vajra_binary = str(VAJRA_BIN)
    registry, keypairs = bulk_generate(n)
    pdf = b"%PDF-1.4\n" + secrets.token_bytes(2048) + b"\n%%EOF"
    out = run_vajra_pipeline(pdf, 1, n, k, registry, timings=timings)
    puzzle_params, double_locked, shards, nonce_hex, drand_info, centers_meta = out
    ipfs = NodeStore(node_count=3)
    manifest_cid, manifest = asyncio.run(
        publish_locked_exam(
            ipfs, n=n, k=k, puzzle_params=puzzle_params, double_locked=double_locked,
            encrypted_shards=shards, nonce_hex=nonce_hex, drand_info=drand_info,
            centers_meta=centers_meta,
        )
    )
    return pdf, ipfs, manifest, keypairs


async def _center_shares(manifest, keypairs, ipfs, k):
    return [
        await fetch_and_decrypt_one_shard(manifest, i, keypairs[i][1], ipfs) for i in range(k)
    ]


@needs_rust
def test_pipeline_timings_cover_every_stage():
    timings: dict = {}
    _lock_and_publish(timings=timings)
    for key in (
        "drand_setup_sec", "generate_wall_sec", "lock_wall_sec", "secure_delete_sec",
        "outer_encrypt_sec", "shamir_split_sec", "center_encrypt_sec",
        "generate_primes_sec", "generate_calibration_sec",
        "lock_parse_sec", "lock_keyderiv_sec", "lock_encrypt_sec", "lock_write_sec",
    ):
        assert key in timings and timings[key] >= 0, key
    assert 1.9 < timings["generate_calibration_sec"] < 3.0
    assert timings["generate_peak_rss_bytes"] > 0
    assert timings["lock_peak_rss_bytes"] > 0
    assert timings["child_memory_method"] in {"VmHWM", "peak_wset", "rss-sampled"}


@needs_rust
def test_full_flow_records_stage_times():
    pdf, ipfs, manifest, keypairs = _lock_and_publish()
    shares = asyncio.run(_center_shares(manifest, keypairs, ipfs, 3))
    marks: dict = {}
    recovered = asyncio.run(
        combine_shares_to_pdf(
            manifest, shares, ipfs, VAJRA_BIN, skip_drand_check=True, stage_times=marks,
        )
    )
    assert recovered == pdf
    assert set(marks) >= {"gate_passed", "outer_unwrapped", "solve_started", "pdf_ready"}
    assert marks["gate_passed"] <= marks["outer_unwrapped"] <= marks["solve_started"] <= marks["pdf_ready"]
    # The 1-second puzzle is squared after the gate, so solving takes most of a second.
    assert marks["pdf_ready"] - marks["solve_started"] > 0.5
