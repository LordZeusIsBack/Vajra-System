"""manifest.py — Build and verify the signed vault manifest.

MANIFEST STRUCTURE
──────────────────
  {
    "version":      "1.1",
    "exam_id":      "<uuid4>",
    "locked_at":    "<ISO-8601 UTC>",
    "n":            10,
    "k":            8,
    "puzzle_cid":   "bafy…",   ← puzzle.json on IPFS (needed by `vajra solve`)
    "payload_cid":  "bafy…",   ← AES-GCM(data_key, locked.json bytes)
    "nonce":        "<12-byte hex>",
    "shard_cids":   [           ← one per Shamir share, distributed round-robin
      {"cid": "bafy…", "node_index": 0},
      {"cid": "bafy…", "node_index": 1},
      …
    ],
    "hmac":         "<sha256 hex>"   ← HMAC-SHA256 over the rest
  }

SIGNATURE
  HMAC-SHA256 keyed with ``settings.manifest_hmac_secret``.
  Computed over canonical (sort_keys, no whitespace) JSON of the manifest
  *without* the "hmac" field. Any bit flip in puzzle_cid, payload_cid, or
  shard_cids is detected before a center wastes time downloading from IPFS.

  Production upgrade: replace with Ed25519 so verifiers don't need the
  symmetric secret.
"""

import hashlib
import hmac as _hmac
import json
import uuid
from datetime import UTC, datetime

from config import settings


def _canonical(obj: dict) -> bytes:
    """Stable whitespace-free JSON bytes for HMAC input."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _sign(body: bytes) -> str:
    return _hmac.new(
        settings.manifest_hmac_secret.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()


def build_and_sign(
    *,
    n: int,
    k: int,
    puzzle_cid: str,
    payload_cid: str,
    nonce_hex: str,
    shard_cids: list[dict],   # [{"cid": "bafy…", "node_index": 0}, …]
    exam_id: str | None = None,
) -> dict:
    """Construct and HMAC-sign the manifest.

    Args:
        n:           Total shards.
        k:           Reconstruction threshold.
        puzzle_cid:  IPFS CID of puzzle.json (public RSW params).
        payload_cid: IPFS CID of the double-locked payload binary.
        nonce_hex:   12-byte AES-GCM nonce (outer lock) in hex.
        shard_cids:  List of dicts with "cid" and "node_index" keys,
                     one per Shamir share, in shard order.
        exam_id:     Optional caller-supplied UUID; auto-generated if omitted.

    Returns:
        Signed manifest dict ready for JSON serialisation.
    """
    if len(shard_cids) != n:
        raise ValueError(f"Expected {n} shard CIDs, got {len(shard_cids)}")

    manifest: dict = {
        "version":     "1.1",
        "exam_id":     exam_id or str(uuid.uuid4()),
        "locked_at":   datetime.now(UTC).isoformat(),
        "n":           n,
        "k":           k,
        "puzzle_cid":  puzzle_cid,
        "payload_cid": payload_cid,
        "nonce":       nonce_hex,
        "shard_cids":  shard_cids,
    }
    manifest["hmac"] = _sign(_canonical(manifest))
    return manifest


def verify(manifest: dict) -> bool:
    """Verify the manifest HMAC. Returns True iff signature is valid.

    The manifest dict is *not* mutated.
    """
    provided = manifest.get("hmac")
    if not provided:
        return False
    body = {k: v for k, v in manifest.items() if k != "hmac"}
    return _hmac.compare_digest(provided, _sign(_canonical(body)))
