"""reconstruct.py — Recover the original PDF from a VAJRA manifest CID.

USAGE (as a library, from Python):
    pdf_bytes = await reconstruct_pdf(manifest_cid, ipfs, "/path/to/vajra")

USAGE (as a CLI, for an exam center):
    python reconstruct.py <manifest_cid> --shards 0,2,3,5,6,7,8,9 \\
        --vajra ../rust/target/release/vajra --out exam.pdf

PIPELINE
  1. Fetch + HMAC-verify manifest.
  2. Fetch k shards in parallel (any reachable node serves each CID).
  3. Reconstruct data_key via Shamir.
  4. Fetch payload.bin and undo the outer AES-GCM wrap → locked.json bytes.
  5. Fetch puzzle.json.
  6. Run `vajra solve --puzzle … --locked … --output …` and read the PDF back.

NOTE ON FIX
  Earlier this module did `return stdout` from the subprocess. The Rust CLI
  writes the PDF to a FILE and prints banners to stdout, so the caller was
  getting box-drawing characters instead of a PDF. We now read the output
  file explicitly.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ipfs_client import IPFSClient, IPFSError
from manifest import verify as verify_manifest
from shamir import reconstruct as shamir_reconstruct


log = logging.getLogger("reconstruct")


# ── Exceptions ────────────────────────────────────────────────────────────────

class ManifestVerificationError(Exception):
    """Raised when the manifest's HMAC signature is invalid."""


class ReconstructError(Exception):
    """Raised on any reconstruction failure — message is safe to surface."""


# ── IPFS helpers (try every node, in parallel where it pays) ──────────────────

async def _cat_any_node(cid: str, ipfs: IPFSClient, *, json: bool = False) -> bytes | dict:
    """Fetch *cid* from any reachable node. Tries sequentially because a single
    node typically serves the content directly via DHT; parallelising one CID
    fetch usually just multiplies bandwidth, not latency."""
    last_err: Exception | None = None
    for i in range(ipfs.node_count):
        try:
            return await (ipfs.cat_json(cid, node_index=i) if json
                          else ipfs.cat(cid, node_index=i))
        except IPFSError as exc:
            last_err = exc
            continue
    raise ReconstructError(
        f"Failed to fetch CID {cid} from any of {ipfs.node_count} nodes "
        f"(last error: {last_err})"
    )


async def _fetch_shards_parallel(
    shard_infos: Sequence[dict],
    ipfs: IPFSClient,
) -> list[dict]:
    """Fetch k shard JSONs concurrently. Returns them in the same order as
    *shard_infos*. Raises ReconstructError on any single failure."""
    tasks = [_cat_any_node(s["cid"], ipfs, json=True) for s in shard_infos]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    shards: list[dict] = []
    for info, res in zip(shard_infos, results):
        if isinstance(res, Exception):
            raise ReconstructError(
                f"Could not fetch shard CID {info['cid']}: {res}"
            )
        shards.append(res)  # type: ignore[arg-type]
    return shards


# ── Main entry point ──────────────────────────────────────────────────────────

async def reconstruct_pdf(
    manifest_cid: str,
    ipfs: IPFSClient,
    vajra_binary: str | Path,
    *,
    shard_indices: list[int] | None = None,
) -> bytes:
    """Reconstruct the original exam PDF from an IPFS manifest CID.

    Args:
        manifest_cid:   CID of the signed manifest.json on IPFS.
        ipfs:           IPFSClient instance.
        vajra_binary:   Path to the compiled `vajra` Rust binary.
        shard_indices:  Which entries of manifest["shard_cids"] to pull.
                        Defaults to the first k entries. Must contain ≥ k
                        distinct indices.

    Returns:
        Decrypted PDF bytes.

    Raises:
        ManifestVerificationError: HMAC check failed.
        ReconstructError:          Any other reconstruction failure.
    """
    # ── 1. Fetch + verify manifest ────────────────────────────────────────────
    try:
        manifest = await ipfs.cat_json(manifest_cid)
    except IPFSError as exc:
        raise ReconstructError(f"Cannot fetch manifest CID {manifest_cid}: {exc}") from exc

    if not verify_manifest(manifest):
        raise ManifestVerificationError(
            "Manifest HMAC verification failed — refusing to proceed."
        )
    log.info("Manifest verified (exam_id=%s, n=%s, k=%s)",
             manifest.get("exam_id"), manifest.get("n"), manifest.get("k"))

    # ── 2. Validate manifest shape ────────────────────────────────────────────
    required = ("puzzle_cid", "payload_cid", "nonce", "shard_cids", "k", "n")
    missing = [f for f in required if f not in manifest]
    if missing:
        raise ReconstructError(f"Manifest missing required fields: {missing}")

    n_val = int(manifest["n"])
    k_val = int(manifest["k"])
    if n_val < 2 or k_val < 2 or k_val > n_val:
        raise ReconstructError(f"Manifest has illegal (n={n_val}, k={k_val})")

    # ── 3. Pick which shards to use ───────────────────────────────────────────
    all_shards = manifest["shard_cids"]
    if shard_indices is None:
        shard_list = all_shards[:k_val]
    else:
        if len(shard_indices) < k_val:
            raise ReconstructError(
                f"Need ≥ {k_val} shards (k from manifest), got {len(shard_indices)}"
            )
        if len(set(shard_indices)) != len(shard_indices):
            raise ReconstructError("Duplicate shard indices passed")
        bad = [i for i in shard_indices if i < 0 or i >= len(all_shards)]
        if bad:
            raise ReconstructError(f"Out-of-range shard indices: {bad}")
        # Use exactly k — extras would still work but waste IPFS calls
        shard_list = [all_shards[i] for i in shard_indices[:k_val]]

    # ── 4. Fetch shard JSONs in parallel ──────────────────────────────────────
    log.info("Fetching %d shards in parallel ...", len(shard_list))
    shard_jsons = await _fetch_shards_parallel(shard_list, ipfs)

    # ── 5. Parse each shard into (x, share_bytes) for Shamir ──────────────────
    shamir_inputs: list[bytes] = []
    seen_x: set[int] = set()
    for sj, info in zip(shard_jsons, shard_list):
        cid = info["cid"]
        if "x" not in sj or "share_hex" not in sj:
            raise ReconstructError(f"Shard {cid} is malformed (missing x or share_hex)")
        x = int(sj["x"])
        if x in seen_x:
            raise ReconstructError(f"Duplicate Shamir x-coord {x} in shard {cid}")
        seen_x.add(x)
        try:
            share_bytes = bytes.fromhex(sj["share_hex"])
        except ValueError as exc:
            raise ReconstructError(f"Bad share_hex in shard {cid}: {exc}") from exc
        # shamir.reconstruct expects: bytes([x]) + f(x) for each secret byte
        shamir_inputs.append(bytes([x]) + share_bytes)

    # ── 6. Reconstruct data_key ───────────────────────────────────────────────
    try:
        data_key = shamir_reconstruct(shamir_inputs)
    except Exception as exc:
        raise ReconstructError(f"Shamir reconstruction failed: {exc}") from exc
    if len(data_key) != 32:
        raise ReconstructError(
            f"Reconstructed data_key has wrong length: {len(data_key)} (expected 32)"
        )
    log.info("data_key reconstructed (32 bytes)")

    # ── 7. Fetch payload + decrypt outer AES-GCM ──────────────────────────────
    payload_bytes = await _cat_any_node(manifest["payload_cid"], ipfs)
    try:
        nonce = bytes.fromhex(manifest["nonce"])
    except ValueError as exc:
        raise ReconstructError(f"Bad nonce hex in manifest: {exc}") from exc
    if len(nonce) != 12:
        raise ReconstructError(f"Nonce must be 12 bytes, got {len(nonce)}")

    try:
        locked_bytes = AESGCM(data_key).decrypt(nonce, payload_bytes, associated_data=None)
    except Exception as exc:
        # Most likely cause: wrong data_key (bad shards), or tampered payload.
        raise ReconstructError(
            "Outer AES-GCM decryption failed. Either the Shamir shards are "
            "wrong/insufficient or the payload has been tampered with."
        ) from exc
    log.info("Outer layer unwrapped (%d bytes → locked.json)", len(locked_bytes))

    # ── 8. Fetch puzzle.json ──────────────────────────────────────────────────
    puzzle_bytes = await _cat_any_node(manifest["puzzle_cid"], ipfs)

    # ── 9. Run `vajra solve --output <file>` and READ THE FILE ────────────────
    #     (Previously this module returned subprocess stdout, which is just the
    #     CLI's status banners — never the PDF. That was the headline bug.)
    with tempfile.TemporaryDirectory(prefix="vajra_solve_") as tmpdir:
        tmp = Path(tmpdir)
        puzzle_path = tmp / "puzzle.json"
        locked_path = tmp / "locked.json"
        out_path    = tmp / "exam.pdf"

        puzzle_path.write_bytes(puzzle_bytes)
        locked_path.write_bytes(locked_bytes)

        args = [
            str(vajra_binary), "solve",
            "--puzzle", str(puzzle_path),
            "--locked", str(locked_path),
            "--output", str(out_path),
        ]
        log.info("Running: %s", " ".join(args))

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            raise ReconstructError(
                f"`vajra solve` failed (exit {proc.returncode}):\n"
                f"stderr: {stderr.decode(errors='replace')[:800]}\n"
                f"stdout: {stdout.decode(errors='replace')[:400]}"
            )
        if not out_path.exists():
            raise ReconstructError(
                "`vajra solve` exited 0 but did not produce an output file. "
                f"stdout: {stdout.decode(errors='replace')[:400]}"
            )

        pdf_bytes = out_path.read_bytes()
        if not pdf_bytes.startswith(b"%PDF"):
            raise ReconstructError(
                "Solved output is not a PDF (missing %PDF magic). "
                "This usually means the wrong K was derived — check shards "
                "and puzzle integrity."
            )
        log.info("PDF recovered (%d bytes)", len(pdf_bytes))
        return pdf_bytes


# ── CLI entrypoint — a center operator can run this directly ──────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="VAJRA — reconstruct an exam PDF from an IPFS manifest CID.",
    )
    p.add_argument("manifest_cid", help="CID of manifest.json on IPFS")
    p.add_argument(
        "--shards",
        help=(
            "Comma-separated 0-based shard indices to use "
            "(e.g. '0,1,2,3,4,5,6,7'). Defaults to the first k from the manifest."
        ),
    )
    p.add_argument("--vajra", required=True, help="Path to the compiled vajra binary")
    p.add_argument("--out", default="exam.pdf", help="Output PDF path")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args()


async def _main() -> int:
    args = _parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(message)s",
    )

    shard_indices: list[int] | None = None
    if args.shards:
        try:
            shard_indices = [int(s.strip()) for s in args.shards.split(",") if s.strip()]
        except ValueError:
            log.error("Could not parse --shards: %r", args.shards)
            return 2

    ipfs = IPFSClient()  # reads settings.ipfs_node_list

    try:
        pdf = await reconstruct_pdf(
            args.manifest_cid, ipfs, args.vajra,
            shard_indices=shard_indices,
        )
    except (ManifestVerificationError, ReconstructError) as exc:
        log.error("Reconstruction failed: %s", exc)
        return 1

    Path(args.out).write_bytes(pdf)
    log.info("Wrote %s (%d bytes)", args.out, len(pdf))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
