"""lock_publish.py — Upload the outputs of the lock pipeline and sign the manifest.

This is the second half of ``POST /api/v1/lock``: after ``run_vajra_pipeline``
has produced the public puzzle, the double-locked payload and the per-center
encrypted shards, they are uploaded to IPFS and an HMAC-signed manifest that
references them is uploaded last.

It lives in its own module so that the experiments can run *exactly* the
service's upload path against a real Kubo cluster or an in-memory stand-in,
and record what was actually created (object count, bytes, upload times).

Placement (unchanged from the service):
  • puzzle.json, payload.bin and manifest.json → node 0
  • shard i → node i mod node_count (round-robin)
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Protocol

import httpx

from ipfs_client import IPFSError
from manifest import build_and_sign

log = logging.getLogger("vajra")


class IPFSWriter(Protocol):
    """The subset of IPFSClient that publishing needs."""

    @property
    def node_count(self) -> int: ...

    async def add_bytes(
        self, data: bytes, filename: str = ..., *, node_index: int = ...
    ) -> str: ...

    async def add_json(
        self, obj: dict, filename: str = ..., *, node_index: int = ...
    ) -> str: ...


class PublishError(RuntimeError):
    """Upload failed. ``stage`` is "objects" (puzzle/payload/shards) or "manifest"."""

    def __init__(self, stage: str, message: str) -> None:
        super().__init__(message)
        self.stage = stage


def _json_size(obj: dict) -> int:
    """Byte length of *obj* as IPFSClient.add_json serialises it."""
    return len(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())


async def publish_locked_exam(
    ipfs: IPFSWriter,
    *,
    n: int,
    k: int,
    puzzle_params: dict,
    double_locked: bytes,
    encrypted_shards: list[dict],
    nonce_hex: str,
    drand_info: dict,
    centers_meta: list[dict],
    exam_id: str | None = None,
    stats: dict[str, Any] | None = None,
) -> tuple[str, dict]:
    """Upload every object, then build, sign and upload the manifest.

    Args:
        ipfs:        IPFSClient (or a compatible stand-in).
        n, k:        Shamir parameters, recorded in the manifest.
        puzzle_params … centers_meta: the outputs of ``run_vajra_pipeline``.
        exam_id:     Optional caller-supplied UUID.
        stats:       Optional dict, filled with what was actually created:
                     ``objects_created`` (including the manifest),
                     ``bytes_uploaded`` (serialised sizes sent to IPFS),
                     ``puzzle_upload_sec``, ``payload_upload_sec``,
                     ``shards_upload_sec``, ``manifest_upload_sec``, and
                     ``objects_per_node`` ({node_index: count}).

    Returns:
        (manifest_cid, manifest)

    Raises:
        PublishError: An upload failed; ``stage`` says which one.
    """
    st: dict[str, Any] = stats if stats is not None else {}
    st.setdefault("objects_created", 0)
    st.setdefault("bytes_uploaded", 0)
    per_node: dict[int, int] = {}

    def _count(node_index: int, size: int) -> None:
        st["objects_created"] += 1
        st["bytes_uploaded"] += size
        node = node_index % ipfs.node_count
        per_node[node] = per_node.get(node, 0) + 1

    try:
        # puzzle.json → always on node 0 (primary, most reliable)
        puzzle_blob = json.dumps(puzzle_params, separators=(",", ":")).encode()
        t0 = time.perf_counter()
        puzzle_cid = await ipfs.add_bytes(puzzle_blob, filename="puzzle.json", node_index=0)
        st["puzzle_upload_sec"] = time.perf_counter() - t0
        _count(0, len(puzzle_blob))
        log.info("puzzle.json → %s (node 0)", puzzle_cid)

        # double-locked payload → node 0 as well (it's big, keep on primary)
        t0 = time.perf_counter()
        payload_cid = await ipfs.add_bytes(double_locked, filename="payload.bin", node_index=0)
        st["payload_upload_sec"] = time.perf_counter() - t0
        _count(0, len(double_locked))
        log.info("payload.bin → %s (node 0)  %d bytes", payload_cid, len(double_locked))

        # Encrypted shards → round-robin across all configured nodes.
        # Each shard's on-IPFS content is the EncryptedShard dict from the
        # pipeline; the plaintext Shamir share never left run_vajra_pipeline.
        shard_cid_entries: list[dict] = []
        t0 = time.perf_counter()
        for idx, enc_shard in enumerate(encrypted_shards):
            node_idx = idx % ipfs.node_count
            shard_obj = {
                "shard_index":    idx,
                "center_id":      centers_meta[idx]["id"],
                "center_pubkey":  centers_meta[idx]["pubkey"],
                # Per-center encryption fields (X25519 ECDH + ChaCha20-Poly1305).
                # Only the holder of the matching center privkey can decrypt.
                "eph_pubkey_hex": enc_shard["eph_pubkey_hex"],
                "nonce_hex":      enc_shard["nonce_hex"],
                "ciphertext_hex": enc_shard["ciphertext_hex"],
                # Convenience pointers so a center only needs the shard CID to
                # know where to fetch the payload and puzzle. These ALSO appear
                # in the signed manifest — these copies are not load-bearing.
                "payload_cid":    payload_cid,
                "outer_nonce_hex": nonce_hex,
                "puzzle_cid":     puzzle_cid,
            }
            cid = await ipfs.add_json(
                shard_obj, filename=f"shard_{idx:03d}.json", node_index=node_idx,
            )
            _count(node_idx, _json_size(shard_obj))
            shard_cid_entries.append({"cid": cid, "node_index": node_idx})
            log.info(
                "shard_%03d.json → %s  (node %d, center %s)",
                idx, cid, node_idx, centers_meta[idx]["id"],
            )
        st["shards_upload_sec"] = time.perf_counter() - t0
    except (IPFSError, httpx.HTTPError) as exc:
        log.error("IPFS upload failed: %s", exc)
        raise PublishError("objects", f"IPFS upload failed: {exc}") from exc

    # ── Build + sign manifest ─────────────────────────────────────────────────
    manifest = build_and_sign(
        n=n,
        k=k,
        puzzle_cid=puzzle_cid,
        payload_cid=payload_cid,
        nonce_hex=nonce_hex,
        shard_cids=shard_cid_entries,
        centers=centers_meta,
        drand={
            "chain_hash":   drand_info["chain_hash"],
            "target_round": drand_info["target_round"],
            "publish_time": drand_info["publish_time"],
        },
        exam_id=exam_id,
    )

    try:
        t0 = time.perf_counter()
        manifest_cid = await ipfs.add_json(manifest, filename="manifest.json", node_index=0)
        st["manifest_upload_sec"] = time.perf_counter() - t0
        _count(0, _json_size(manifest))
        log.info("manifest.json → %s", manifest_cid)
    except (IPFSError, httpx.HTTPError) as exc:
        raise PublishError("manifest", f"Manifest upload failed: {exc}") from exc

    st["objects_per_node"] = dict(sorted(per_node.items()))
    return manifest_cid, manifest
