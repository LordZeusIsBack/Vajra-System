"""vajra_center.py — Per-center decryption CLI.

WHAT THIS IS
  The piece of VAJRA that runs on each EXAM CENTER'S machine. Each center
  holds exactly one X25519 keypair (theirs). At reconstruction time, this
  CLI fetches the one shard belonging to that center, decrypts it with the
  center's private key, and writes a "share file" — a small JSON containing
  the plaintext Shamir share, which can then be transmitted to a coordinator.

  A center's machine NEVER sees:
    • any other center's private key
    • any other center's plaintext share
    • the data_key (impossible without ≥k shares)
    • the exam PDF

  The plaintext Shamir share IS visible to this machine briefly. By Shamir's
  information-theoretic security, one share reveals nothing about data_key.
  Even if a center's share file leaks, k-1 of them together still reveal
  nothing.

ONE COMMAND
  python vajra_center.py decrypt-share <manifest_cid> --my-key keypair.json \
      --out share_CENTER_003.json

OUTPUT (share_CENTER_NNN.json)
  {
    "exam_id":      "<uuid from manifest>",
    "manifest_cid": "<input cid, echoed back so the coordinator can verify>",
    "center_id":    "CENTER_003",
    "center_index": 3,
    "share_hex":    "<33-byte plaintext Shamir share, hex>"
  }

  This file is SAFE to send to a coordinator over any channel — by itself it
  reveals nothing about data_key. The coordinator collects ≥k of these and
  runs `vajra_coordinator.py combine`.

HONEST CAVEAT
  This is still policy, not pure crypto. A malicious center COULD share
  their privkey with anyone they wanted — Shamir's threshold only protects
  against UNAUTHORISED key access, not authorised-key-holder betrayal. The
  trust model is: each center independently chooses to participate (or not)
  at reconstruction time; an attacker needs ≥k centers to collude. That's
  the security boundary, and it's the same one every threshold-cryptography
  scheme has.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from ipfs_client import IPFSClient, IPFSError
from manifest import verify as verify_manifest
from reconstruct import (
    ManifestVerificationError,
    ReconstructError,
    fetch_and_decrypt_one_shard,
    load_center_keypair,
    validate_manifest_shape,
)

log = logging.getLogger("vajra-center")


# ── Core operation ────────────────────────────────────────────────────────────


async def decrypt_my_share(
    manifest_cid: str,
    keypair_path: str | Path,
    out_path: str | Path,
    ipfs: IPFSClient,
) -> Path:
    """Fetch + decrypt this center's shard, write a share file.

    Returns the path the share file was written to.

    Raises:
        ManifestVerificationError: HMAC verification failed.
        ReconstructError:          Any other failure (network, decrypt, malformed).
        FileNotFoundError:         Keypair file doesn't exist.
    """
    # ── 1. Load this center's keypair ─────────────────────────────────────────
    center_id, privkey_hex = load_center_keypair(keypair_path)
    log.info("Loaded keypair for center id=%s", center_id)

    # ── 2. Fetch + HMAC-verify the manifest ───────────────────────────────────
    try:
        manifest = await ipfs.cat_json(manifest_cid)
    except IPFSError as exc:
        raise ReconstructError(f"Cannot fetch manifest {manifest_cid}: {exc}") from exc

    if not verify_manifest(manifest):
        raise ManifestVerificationError(
            "Manifest HMAC verification failed — refusing to decrypt my share. "
            "Either the manifest CID is wrong or the manifest has been tampered."
        )
    validate_manifest_shape(manifest)
    log.info(
        "Manifest verified (exam_id=%s, n=%s, k=%s)",
        manifest.get("exam_id"), manifest.get("n"), manifest.get("k"),
    )

    # ── 3. Look up this center's index in the manifest ────────────────────────
    id_to_index = {c["id"]: int(c["index"]) for c in manifest["centers"]}
    if center_id not in id_to_index:
        raise ReconstructError(
            f"This center's id {center_id!r} is not in the manifest's centers "
            f"list. Either the keypair is for a different exam, or this center "
            f"wasn't selected. Manifest knows about: {sorted(id_to_index)}"
        )
    my_index = id_to_index[center_id]

    # ── 4. Fetch + decrypt this center's shard ────────────────────────────────
    log.info("Fetching + decrypting my shard (index %d) …", my_index)
    share_bytes = await fetch_and_decrypt_one_shard(
        manifest, my_index, privkey_hex, ipfs,
    )
    log.info(
        "Shard decrypted: %d bytes (x-coord=%d, payload=%d bytes)",
        len(share_bytes), share_bytes[0], len(share_bytes) - 1,
    )

    # ── 5. Write the share file ───────────────────────────────────────────────
    out_path = Path(out_path)
    share_obj = {
        "exam_id":      manifest.get("exam_id", "unknown"),
        "manifest_cid": manifest_cid,
        "center_id":    center_id,
        "center_index": my_index,
        "share_hex":    share_bytes.hex(),
    }
    out_path.write_text(json.dumps(share_obj, indent=2, sort_keys=True))
    log.info("Share file written → %s", out_path)
    return out_path


# ── CLI ──────────────────────────────────────────────────────────────────────


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="vajra-center",
        description=(
            "VAJRA — per-center decryption CLI. Each exam center runs this on "
            "their own machine at reconstruction time. Decrypts ONLY this "
            "center's shard; produces a share file safe to send to a coordinator."
        ),
    )
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser(
        "decrypt-share",
        help="Fetch and decrypt this center's shard, write a share file.",
    )
    d.add_argument("manifest_cid", help="CID of manifest.json on IPFS")
    d.add_argument(
        "--my-key",
        required=True,
        metavar="KEYPAIR_JSON",
        help="Path to this center's keypair JSON (from vajra_keygen)",
    )
    d.add_argument(
        "--out",
        required=True,
        metavar="SHARE_JSON",
        help="Where to write the share file (e.g. share_CENTER_003.json)",
    )
    d.add_argument("-v", "--verbose", action="store_true")

    return p.parse_args()


async def _main() -> int:
    args = _parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(message)s",
    )

    ipfs = IPFSClient()  # reads settings.ipfs_node_list

    try:
        if args.command == "decrypt-share":
            await decrypt_my_share(
                args.manifest_cid, args.my_key, args.out, ipfs,
            )
        else:
            print(f"Unknown command: {args.command}", file=sys.stderr)
            return 2
    except ManifestVerificationError as exc:
        log.error("Manifest verification failed: %s", exc)
        return 1
    except (ReconstructError, FileNotFoundError) as exc:
        log.error("Decryption failed: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
