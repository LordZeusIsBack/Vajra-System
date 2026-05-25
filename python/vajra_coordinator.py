"""vajra_coordinator.py — Coordinator CLI: combine k share files → exam PDF.

WHAT THIS IS
  The piece of VAJRA that runs on a single COORDINATOR machine at exam time.
  Centers each run `vajra_center decrypt-share` on their own machines and
  transmit the resulting share files. This CLI ingests ≥ k of them, combines
  via Shamir, unwraps both AES-GCM layers, and runs `vajra solve` to produce
  the exam PDF.

  The coordinator NEVER sees:
    • any center's private key
    • the encrypted shards on IPFS (the share files have the plaintext share already)

  The coordinator DOES see:
    • ≥ k plaintext Shamir shares (this is inherent — Shamir combine requires them)
    • the recovered data_key (momentarily)
    • the decrypted PDF (the whole point)

  This means an attacker who compromises the coordinator at the moment of
  reconstruction gets everything for THAT exam. In a real production system
  the combine step would be done via secure MPC so no single machine ever
  holds all k shares — out of scope for this prototype.

ONE COMMAND
  python vajra_coordinator.py combine <manifest_cid> \\
      --share shares/share_CENTER_001.json \\
      --share shares/share_CENTER_003.json \\
      ... (≥ k of these) ...
      --vajra ../rust/target/release/vajra \\
      --out exam.pdf
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
    combine_shares_to_pdf,
    validate_manifest_shape,
)


log = logging.getLogger("vajra-coordinator")


# ── Share file ingestion ─────────────────────────────────────────────────────


def _load_share_file(path: str | Path, manifest_cid: str) -> dict:
    """Load a share file written by vajra_center.decrypt-share.

    Validates:
        • Required fields present
        • manifest_cid matches the one we're reconstructing for
        • share_hex is valid hex of plausible length
        • center_index is non-negative
    """
    p = Path(path)
    if not p.exists():
        raise ReconstructError(f"Share file not found: {p}")
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError as exc:
        raise ReconstructError(f"Share file {p} is not valid JSON: {exc}") from exc

    required = ("manifest_cid", "center_id", "center_index", "share_hex")
    missing = [f for f in required if f not in data]
    if missing:
        raise ReconstructError(f"Share file {p} missing fields: {missing}")

    if data["manifest_cid"] != manifest_cid:
        raise ReconstructError(
            f"Share file {p} is for manifest "
            f"{data['manifest_cid']!r}, not {manifest_cid!r}. "
            f"Wrong exam, or the share is stale."
        )

    try:
        share_bytes = bytes.fromhex(data["share_hex"])
    except ValueError as exc:
        raise ReconstructError(f"Share file {p} has invalid hex: {exc}") from exc

    if len(share_bytes) < 2:
        raise ReconstructError(
            f"Share file {p} is too short ({len(share_bytes)} bytes — expected ≥ 2)"
        )

    if int(data["center_index"]) < 0:
        raise ReconstructError(f"Share file {p} has negative center_index")

    return {
        "center_id":    str(data["center_id"]),
        "center_index": int(data["center_index"]),
        "share_bytes":  share_bytes,
        "path":         str(p),
    }


# ── Coordinator main entry point ──────────────────────────────────────────────


async def coordinate(
    manifest_cid: str,
    share_paths: list[str | Path],
    vajra_binary: str | Path,
    ipfs: IPFSClient,
    *,
    skip_drand_check: bool = False,
) -> bytes:
    """Collect share files, verify, combine, decrypt, solve. Returns the PDF.

    Steps:
        1. Fetch + HMAC-verify the manifest.
        2. Load every share file; refuse if any is for a different manifest.
        3. Check we have ≥ k shares, with no duplicate centers or x-coords.
        4. Delegate to combine_shares_to_pdf (which does the drand gate,
           AAD derivation, Shamir combine, AES-GCM unwrap, and `vajra solve`).

    Raises:
        ManifestVerificationError, ReconstructError.
    """
    # ── 1. Fetch + verify manifest ────────────────────────────────────────────
    try:
        manifest = await ipfs.cat_json(manifest_cid)
    except IPFSError as exc:
        raise ReconstructError(f"Cannot fetch manifest {manifest_cid}: {exc}") from exc

    if not verify_manifest(manifest):
        raise ManifestVerificationError(
            "Manifest HMAC verification failed — refusing to coordinate. "
            "Either the manifest CID is wrong or the manifest has been tampered."
        )
    validate_manifest_shape(manifest)

    n_val = int(manifest["n"])
    k_val = int(manifest["k"])
    log.info(
        "Manifest verified (exam_id=%s, n=%d, k=%d)",
        manifest.get("exam_id"), n_val, k_val,
    )

    # ── 2. Load all share files ───────────────────────────────────────────────
    if not share_paths:
        raise ReconstructError(
            "No --share files given. Need ≥ k from cooperating centers."
        )

    parsed = [_load_share_file(p, manifest_cid) for p in share_paths]
    log.info("Loaded %d share files", len(parsed))

    # ── 3. Sanity-check the collection ────────────────────────────────────────
    if len(parsed) < k_val:
        raise ReconstructError(
            f"Need ≥ {k_val} shares (k from manifest), got {len(parsed)}. "
            f"Wait for more centers, then re-run."
        )

    # Check each share's center_index is valid and unique
    centers_block = manifest["centers"]
    seen_indices: set[int] = set()
    for sh in parsed:
        idx = sh["center_index"]
        if idx < 0 or idx >= n_val:
            raise ReconstructError(
                f"Share from {sh['path']} has center_index {idx}, "
                f"out of range [0, {n_val})."
            )
        if idx in seen_indices:
            raise ReconstructError(
                f"Two share files claim center_index {idx} — duplicate submission."
            )
        seen_indices.add(idx)

        # Cross-check center_id against the manifest. A malicious center can't
        # impersonate another center's index without ALSO matching the
        # manifest's id for that index (and they'd have needed that center's
        # privkey to produce a valid share, which is the whole point of the
        # per-center encryption).
        manifest_id = centers_block[idx]["id"]
        if sh["center_id"] != manifest_id:
            raise ReconstructError(
                f"Share from {sh['path']} claims center_id={sh['center_id']!r} "
                f"at index {idx}, but manifest says centers[{idx}].id="
                f"{manifest_id!r}. Refusing — possibly malicious."
            )

    log.info(
        "%d distinct centers submitting (indices: %s)",
        len(parsed), sorted(seen_indices),
    )

    # ── 4. Combine + solve ────────────────────────────────────────────────────
    plaintext_shares = [sh["share_bytes"] for sh in parsed]
    return await combine_shares_to_pdf(
        manifest, plaintext_shares, ipfs, vajra_binary,
        skip_drand_check=skip_drand_check,
    )


# ── CLI ──────────────────────────────────────────────────────────────────────


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="vajra-coordinator",
        description=(
            "VAJRA — coordinator CLI. Collects share files from k cooperating "
            "centers and reconstructs the exam PDF. The coordinator never "
            "sees any center's private key — it only handles plaintext "
            "Shamir shares that the centers have already decrypted locally."
        ),
    )
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("combine", help="Combine k share files into the exam PDF")
    c.add_argument("manifest_cid", help="CID of manifest.json on IPFS")
    c.add_argument(
        "--share",
        action="append",
        default=[],
        metavar="SHARE_JSON",
        help=(
            "Path to a share file (from vajra_center). Pass once per "
            "cooperating center. Must provide ≥ k of them."
        ),
    )
    c.add_argument(
        "--vajra",
        required=True,
        help="Path to the compiled vajra Rust binary",
    )
    c.add_argument("--out", default="exam.pdf", help="Output PDF path")
    c.add_argument(
        "--skip-drand-check",
        action="store_true",
        help=(
            "Bypass the drand publish-time gate (Layer A policy check). "
            "The AAD is still verified cryptographically. Offline testing only."
        ),
    )
    c.add_argument("-v", "--verbose", action="store_true")

    return p.parse_args()


async def _main() -> int:
    args = _parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(message)s",
    )

    ipfs = IPFSClient()  # reads settings.ipfs_node_list

    try:
        pdf = await coordinate(
            args.manifest_cid,
            args.share,
            args.vajra,
            ipfs,
            skip_drand_check=args.skip_drand_check,
        )
    except ManifestVerificationError as exc:
        log.error("Manifest verification failed: %s", exc)
        return 1
    except ReconstructError as exc:
        log.error("Reconstruction failed: %s", exc)
        return 1

    Path(args.out).write_bytes(pdf)
    log.info("Wrote %s (%d bytes)", args.out, len(pdf))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
