"""manifest.py — Build and verify the signed vault manifest.

MANIFEST STRUCTURE  (v1.3 — adds per-center pubkey block)
─────────────────────────────────────────────────────────
  {
    "version":      "1.3",
    "exam_id":      "<uuid4>",
    "locked_at":    "<ISO-8601 UTC>",
    "n":            10,
    "k":            8,
    "puzzle_cid":   "bafy…",       ← puzzle.json on IPFS
    "payload_cid":  "bafy…",       ← AES-GCM(data_key, locked.json, aad=AAD)
    "nonce":        "<12-byte hex>",
    "shard_cids":   [               ← one per Shamir share, round-robin distributed
      {"cid": "bafy…", "node_index": 0},
      …
    ],
    "centers": [                     ← Step 2: one entry per shard, in shard order
      {"index": 0, "id": "CENTER_000", "pubkey": "<32-byte hex>"},
      …
    ],
    "drand": {                       ← Layer A: time anchor
      "chain_hash":   "<32-byte hex>",
      "target_round": 12345678,
      "publish_time": 1932000000     ← Unix-seconds = genesis + period*round
    },
    "hmac":         "<sha256 hex>"   ← HMAC-SHA256 over the rest
  }

  Each shard file on IPFS (referenced by shard_cids[i].cid) now contains an
  EncryptedShard (eph_pubkey_hex, nonce_hex, ciphertext_hex) instead of a
  plaintext Shamir share. Only the holder of centers[i].pubkey's matching
  private key can decrypt it.

  The AAD used by both AES-GCM layers is computed at reconstruct time as:
      aad = SHA256("vajra-v1" || target_round_be_u64 || chain_hash_bytes)
  No AAD value is stored — it's derived from manifest fields.

SIGNATURE
  HMAC-SHA256 keyed with ``settings.manifest_hmac_secret``.
  Computed over canonical (sort_keys, no whitespace) JSON of the manifest
  *without* the "hmac" field. Tampering with shard_cids, drand fields, OR
  center pubkeys is detected here.

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
    centers: list[dict],      # [{"index": 0, "id": "CENTER_000", "pubkey": "..."}, …]
    drand: dict,              # {"chain_hash": "...", "target_round": int, "publish_time": int}
    exam_id: str | None = None,
) -> dict:
    """Construct and HMAC-sign the manifest.

    Args:
        n:           Total shards.
        k:           Reconstruction threshold.
        puzzle_cid:  IPFS CID of puzzle.json (public RSW params).
        payload_cid: IPFS CID of the double-locked payload binary.
        nonce_hex:   12-byte AES-GCM nonce (outer lock) in hex.
        shard_cids:  One per Shamir share, in shard order. Each shard file on
                     IPFS is an EncryptedShard (not a raw share).
        centers:     One per shard, in shard order. {index, id, pubkey} —
                     tells centers which shard is theirs and lets reconstruction
                     code verify the right private key is being applied.
        drand:       Dict with chain_hash, target_round, publish_time.
        exam_id:     Optional caller-supplied UUID; auto-generated if omitted.

    Returns:
        Signed manifest dict ready for JSON serialisation.
    """
    if len(shard_cids) != n:
        raise ValueError(f"Expected {n} shard CIDs, got {len(shard_cids)}")
    if len(centers) != n:
        raise ValueError(f"Expected {n} centers, got {len(centers)}")

    required_drand = {"chain_hash", "target_round", "publish_time"}
    missing = required_drand - drand.keys()
    if missing:
        raise ValueError(f"drand dict missing required keys: {sorted(missing)}")

    # Validate centers shape: each entry must have index, id, pubkey, and
    # indices must be 0..n-1 in order (defends against accidental reordering).
    required_center = {"index", "id", "pubkey"}
    for i, c in enumerate(centers):
        miss = required_center - c.keys()
        if miss:
            raise ValueError(f"centers[{i}] missing keys: {sorted(miss)}")
        if c["index"] != i:
            raise ValueError(
                f"centers[{i}].index = {c['index']}, expected {i} "
                f"(centers list must be in shard order)"
            )

    manifest: dict = {
        "version":     "1.3",
        "exam_id":     exam_id or str(uuid.uuid4()),
        "locked_at":   datetime.now(UTC).isoformat(),
        "n":           n,
        "k":           k,
        "puzzle_cid":  puzzle_cid,
        "payload_cid": payload_cid,
        "nonce":       nonce_hex,
        "shard_cids":  shard_cids,
        "centers": [
            {"index": int(c["index"]), "id": str(c["id"]), "pubkey": str(c["pubkey"])}
            for c in centers
        ],
        "drand": {
            "chain_hash":   drand["chain_hash"],
            "target_round": int(drand["target_round"]),
            "publish_time": int(drand["publish_time"]),
        },
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