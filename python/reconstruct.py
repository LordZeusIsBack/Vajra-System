"""reconstruct.py — Recover the original PDF from a VAJRA manifest CID.

USAGE (as a library, from Python):
    pdf_bytes = await reconstruct_pdf(
        manifest_cid, ipfs, "/path/to/vajra",
        center_keys={3: "...privkey_hex...", 7: "...privkey_hex...", ...},
    )

USAGE (as a CLI, for an admin / coordinator at exam time):
    python reconstruct.py <manifest_cid> \\
        --vajra ../rust/target/release/vajra \\
        --center-key keys/CENTER_003.json \\
        --center-key keys/CENTER_007.json \\
        --center-key keys/CENTER_011.json \\
        ...
        --out exam.pdf

PIPELINE
  1. Fetch + HMAC-verify manifest.
  2. **Layer A policy gate:** require drand `target_round` to have published.
     Check the local clock first (cheap), then fetch from ≥ 2 relays.
  3. Re-derive AAD from manifest fields: SHA256("vajra-v1" || target_round || chain_hash).
  4. For each provided center privkey: fetch THE specific shard for that
     center (manifest's centers[i].pubkey decides which) and decrypt with
     the privkey. Plaintext Shamir share goes into the combine bucket.
  5. Once ≥ k decrypted shares are collected, Shamir-combine → data_key.
  6. Fetch payload.bin and undo the outer AES-GCM wrap (with AAD) → locked.json.
  7. Fetch puzzle.json.
  8. Run `vajra solve --aad-hex <AAD> …` and read the PDF back.

DECENTRALIZED MODEL (matches the architecture story)
  Each `--center-key` flag represents one cooperating center submitting
  their decrypted share. In a real deployment, the k centers would each
  decrypt their shard locally on their own machine (using `vajra-center
  decrypt`) and submit ONLY the resulting plaintext share to a coordinator
  process that runs Shamir combine + the rest of this pipeline. This script
  models that flow honestly: if you only have access to your own keypair,
  you can only decrypt one shard, and you still need k-1 other shares from
  other centers to reconstruct anything. The plaintext shares from each
  center reveal nothing about data_key on their own — Shamir's information-
  theoretic security guarantees this.

HONEST CAVEAT
  Step 2 (drand publish check) is *policy*, not cryptography. An attacker
  holding the manifest, k center privkeys, and puzzle.json can bypass this
  script. The AAD binding catches manifest tampering — that's cryptographic.
  Full cryptographic time-gating requires Layer B (drand timelock encryption).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from centers import (
    CentersError,
    EncryptedShard,
    decrypt_share_with_privkey,
)
from drand_client import (
    DrandError,
    derive_aad,
    verify_round_published,
)
from ipfs_client import IPFSClient, IPFSError
from manifest import verify as verify_manifest
from shamir import reconstruct as shamir_reconstruct

log = logging.getLogger("reconstruct")


# ── Center keypair loading (CLI convenience) ──────────────────────────────────


def load_center_keypair(path: str | Path) -> tuple[str, str]:
    """Load a center keypair file written by vajra_keygen.

    Returns (id, privkey_hex). Raises ReconstructError on any problem.
    """
    p = Path(path)
    if not p.exists():
        raise ReconstructError(f"Keypair file not found: {p}")
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError as exc:
        raise ReconstructError(f"Keypair file {p} is not valid JSON: {exc}") from exc
    for k in ("id", "privkey"):
        if k not in data:
            raise ReconstructError(f"Keypair file {p} missing '{k}'")
    return str(data["id"]), str(data["privkey"])


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

# ── Manifest validation helper (shared by reconstruct + center CLI) ──────────


def validate_manifest_shape(manifest: dict) -> None:
    """Check that a manifest has all v1.3 fields with valid (n, k, drand).
    Raises ReconstructError on any problem.

    Called by reconstruct_pdf, vajra_center, vajra_coordinator — the negative
    space (which fields are required) lives here so it can't drift.
    """
    required = (
        "puzzle_cid", "payload_cid", "nonce", "shard_cids",
        "centers", "k", "n", "drand",
    )
    missing = [f for f in required if f not in manifest]
    if missing:
        raise ReconstructError(f"Manifest missing required fields: {missing}")

    n_val = int(manifest["n"])
    k_val = int(manifest["k"])
    if n_val < 2 or k_val < 2 or k_val > n_val:
        raise ReconstructError(f"Manifest has illegal (n={n_val}, k={k_val})")
    if len(manifest["centers"]) != n_val:
        raise ReconstructError(
            f"Manifest centers count {len(manifest['centers'])} ≠ n={n_val}"
        )
    if len(manifest["shard_cids"]) != n_val:
        raise ReconstructError(
            f"Manifest shard_cids count {len(manifest['shard_cids'])} ≠ n={n_val}"
        )

    drand_required = {"chain_hash", "target_round", "publish_time"}
    drand_missing = drand_required - manifest["drand"].keys()
    if drand_missing:
        raise ReconstructError(
            f"Manifest 'drand' missing required fields: {sorted(drand_missing)}"
        )


# ── Per-center helpers (used by the split-flow CLIs) ──────────────────────────


async def fetch_and_decrypt_one_shard(
    manifest: dict,
    center_index: int,
    center_privkey_hex: str,
    ipfs: IPFSClient,
) -> bytes:
    """Fetch one specific center's shard from IPFS and decrypt it.

    What `vajra_center decrypt-share` needs. A real center machine calls this
    with ONLY its own keypair — never sees other centers' anything.

    Args:
        manifest:            Already-HMAC-verified manifest dict.
        center_index:        Which center this is (0-based, matches manifest's
                             centers[i].index field).
        center_privkey_hex:  This center's X25519 privkey, hex-encoded.
        ipfs:                IPFSClient.

    Returns:
        Plaintext Shamir share bytes (1 byte x-coord + 32 bytes f_b(x)).
        These bytes alone reveal NOTHING about data_key (Shamir's info-
        theoretic security). Safe to write to a share file for shipping to
        the coordinator.

    Raises:
        ReconstructError: If the manifest is malformed, the shard CID is
                          unreachable, the shard's stated center_id doesn't
                          match the manifest, or the privkey can't decrypt it.
    """
    centers_block    = manifest["centers"]
    shard_cids_block = manifest["shard_cids"]
    n_val = int(manifest["n"])

    if center_index < 0 or center_index >= n_val:
        raise ReconstructError(
            f"center_index {center_index} out of range [0, {n_val})"
        )

    expected_center = centers_block[center_index]
    shard_info      = shard_cids_block[center_index]
    cid             = shard_info["cid"]

    # Fetch the encrypted shard from any reachable IPFS node
    try:
        shard_json = await _cat_any_node(cid, ipfs, json=True)
    except ReconstructError as exc:
        raise ReconstructError(
            f"Cannot fetch shard for center index {center_index}: {exc}"
        ) from exc
    assert isinstance(shard_json, dict)  # _cat_any_node honours json=True

    # Cross-check the shard's stated center_id against the manifest. The
    # manifest HMAC already covers this; this catches IPFS-level swaps where
    # an attacker uploads a different shard JSON and swaps the CID before
    # the manifest is signed (which then fails HMAC), or swaps just the
    # shard contents after pinning (CID changes → IPFS rejects → fetch fails).
    # Belt and braces.
    if shard_json.get("center_id") != expected_center["id"]:
        raise ReconstructError(
            f"Shard {cid} claims center_id={shard_json.get('center_id')!r} "
            f"but manifest says centers[{center_index}].id="
            f"{expected_center['id']!r}. Possible IPFS-level tampering."
        )

    try:
        enc_shard = EncryptedShard.from_dict(shard_json)
    except KeyError as exc:
        raise ReconstructError(
            f"Shard {cid} missing encryption field: {exc}"
        ) from exc

    try:
        plaintext_share = decrypt_share_with_privkey(enc_shard, center_privkey_hex)
    except CentersError as exc:
        # If you get here in production, the most likely cause is that this
        # center's keypair was rotated and the registry wasn't re-uploaded.
        raise ReconstructError(
            f"Cannot decrypt shard for center index {center_index} "
            f"(id={expected_center['id']!r}): {exc}"
        ) from exc

    if len(plaintext_share) < 2:
        raise ReconstructError(
            f"Decrypted share for center {center_index} is too short "
            f"({len(plaintext_share)} bytes — expected ≥ 2)"
        )

    return plaintext_share


async def combine_shares_to_pdf(
    manifest: dict,
    plaintext_shares: list[bytes],
    ipfs: IPFSClient,
    vajra_binary: str | Path,
    *,
    skip_drand_check: bool = False,
) -> bytes:
    """Combine ≥k plaintext Shamir shares → data_key → unwrap → solve → PDF.

    What `vajra_coordinator combine` needs. The coordinator does NOT need
    any privkeys — it only handles ALREADY-DECRYPTED shares submitted by
    cooperating centers.

    Args:
        manifest:           Already-HMAC-verified manifest dict.
        plaintext_shares:   List of plaintext Shamir shares from ≥k centers.
                            Each: bytes([x]) + 32 bytes of f_b(x). Order
                            doesn't matter; Shamir doesn't care.
        ipfs:               IPFSClient.
        vajra_binary:       Path to compiled `vajra` Rust binary.
        skip_drand_check:   If True, skip the Layer A network/clock policy
                            check. AAD is still cryptographically threaded.

    Returns:
        Decrypted PDF bytes.

    Raises:
        ReconstructError: Any failure (drand gate, Shamir, AES-GCM, vajra solve).
    """
    k_val        = int(manifest["k"])
    chain_hash   = str(manifest["drand"]["chain_hash"])
    target_round = int(manifest["drand"]["target_round"])

    if len(plaintext_shares) < k_val:
        raise ReconstructError(
            f"Need ≥ {k_val} plaintext shares to reconstruct, "
            f"got {len(plaintext_shares)}"
        )

    # ── Layer A: drand policy gate ────────────────────────────────────────
    if skip_drand_check:
        log.warning(
            "⚠  --skip-drand-check enabled — bypassing the time gate. "
            "This is for offline testing only."
        )
    else:
        try:
            round_info = await verify_round_published(
                target_round, chain_hash=chain_hash,
            )
        except DrandError as exc:
            raise ReconstructError(f"drand time-gate refused: {exc}") from exc
        log.info(
            "drand round %d verified published (randomness=%s…)",
            round_info.round, round_info.randomness[:16],
        )

    # ── Re-derive AAD ─────────────────────────────────────────────────────
    try:
        aad = derive_aad(target_round, chain_hash)
    except ValueError as exc:
        raise ReconstructError(f"Cannot derive AAD: {exc}") from exc
    log.info("AAD derived (%d bytes) — binding to drand round %d", len(aad), target_round)

    # ── Detect duplicate x-coords across submitted shares ─────────────────
    # If two centers somehow submit the same share, Shamir will silently
    # break. Catch it here with a clear error.
    seen_x: set[int] = set()
    for s in plaintext_shares:
        x = s[0]
        if x in seen_x:
            raise ReconstructError(
                f"Duplicate Shamir x-coord {x} among submitted shares — "
                f"two centers submitted the same shard, or one share was "
                f"submitted twice."
            )
        seen_x.add(x)

    # ── Shamir combine ────────────────────────────────────────────────────
    log.info("Combining %d plaintext shares via Shamir ...", len(plaintext_shares))
    try:
        data_key = shamir_reconstruct(plaintext_shares, expected_threshold=k_val)
    except Exception as exc:
        raise ReconstructError(f"Shamir reconstruction failed: {exc}") from exc
    if len(data_key) != 32:
        raise ReconstructError(
            f"Reconstructed data_key has wrong length: {len(data_key)} (expected 32)"
        )
    log.info("data_key reconstructed (32 bytes)")

    # ── Outer AES-GCM unwrap ──────────────────────────────────────────────
    payload_bytes = await _cat_any_node(manifest["payload_cid"], ipfs)
    try:
        nonce = bytes.fromhex(manifest["nonce"])
    except ValueError as exc:
        raise ReconstructError(f"Bad nonce hex in manifest: {exc}") from exc
    if len(nonce) != 12:
        raise ReconstructError(f"Nonce must be 12 bytes, got {len(nonce)}")

    try:
        locked_bytes = AESGCM(data_key).decrypt(nonce, payload_bytes, associated_data=aad)
    except Exception as exc:
        raise ReconstructError(
            "Outer AES-GCM decryption failed. Either the submitted shares "
            "are wrong/insufficient, the payload has been tampered with, "
            "or the manifest's drand fields don't match what was used at "
            "lock time."
        ) from exc
    log.info("Outer layer unwrapped (%d bytes → locked.json)", len(locked_bytes))

    # ── Fetch puzzle.json ─────────────────────────────────────────────────
    puzzle_bytes = await _cat_any_node(manifest["puzzle_cid"], ipfs)

    # ── Run vajra solve with the AAD ──────────────────────────────────────
    with tempfile.TemporaryDirectory(prefix="vajra_solve_") as tmpdir:
        tmp = Path(tmpdir)
        puzzle_path = tmp / "puzzle.json"
        locked_path = tmp / "locked.json"
        out_path    = tmp / "exam.pdf"

        puzzle_path.write_bytes(puzzle_bytes)
        locked_path.write_bytes(locked_bytes)

        args = [
            str(vajra_binary), "solve",
            "--puzzle",   str(puzzle_path),
            "--locked",   str(locked_path),
            "--output",   str(out_path),
            "--aad-hex",  aad.hex(),
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


# ── Main entry point ──────────────────────────────────────────────────────────


async def reconstruct_pdf(
    manifest_cid: str,
    ipfs: IPFSClient,
    vajra_binary: str | Path,
    *,
    center_keys: dict[int, str],
    skip_drand_check: bool = False,
) -> bytes:
    """Reconstruct the original exam PDF from an IPFS manifest CID.

    Single-machine convenience wrapper: holds all k privkeys at once. For
    the demo's decentralized story, use vajra_center + vajra_coordinator
    instead (which each operate on subsets of the data).

    Args:
        manifest_cid:     CID of the signed manifest.json on IPFS.
        ipfs:             IPFSClient instance.
        vajra_binary:     Path to the compiled `vajra` Rust binary.
        center_keys:      Map of center_index → privkey hex. ≥ k entries.
        skip_drand_check: If True, skip the Layer A network policy check.

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
    validate_manifest_shape(manifest)
    n_val = int(manifest["n"])
    k_val = int(manifest["k"])

    # ── 3. Validate that the caller has enough center privkeys ────────────────
    if len(center_keys) < k_val:
        raise ReconstructError(
            f"Need ≥ {k_val} center privkeys (k from manifest), "
            f"got {len(center_keys)}. Without enough cooperating centers, "
            f"Shamir reconstruction is information-theoretically impossible."
        )
    bad_indices = [i for i in center_keys if i < 0 or i >= n_val]
    if bad_indices:
        raise ReconstructError(
            f"Center indices out of range [0, {n_val}): {bad_indices}"
        )

    # Use exactly k privkeys
    selected_indices = sorted(center_keys.keys())[:k_val]
    log.info(
        "Using center indices: %s (out of %d registered)",
        selected_indices, n_val,
    )

    # ── 4-5. Fetch + decrypt each selected shard in parallel ──────────────────
    async def _one(idx: int) -> bytes:
        return await fetch_and_decrypt_one_shard(
            manifest, idx, center_keys[idx], ipfs,
        )

    log.info("Fetching + decrypting %d shards in parallel ...", len(selected_indices))
    decrypted = await asyncio.gather(
        *(_one(idx) for idx in selected_indices),
        return_exceptions=True,
    )
    plaintext_shares: list[bytes] = []
    for idx, res in zip(selected_indices, decrypted):
        if isinstance(res, Exception):
            raise ReconstructError(
                f"Shard fetch/decrypt failed for center {idx}: {res}"
            ) from res
        plaintext_shares.append(res)

    # ── 6+. Combine and run vajra solve ───────────────────────────────────────
    return await combine_shares_to_pdf(
        manifest, plaintext_shares, ipfs, vajra_binary,
        skip_drand_check=skip_drand_check,
    )


# ── CLI entrypoint — a center operator can run this directly ──────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="VAJRA — reconstruct an exam PDF from an IPFS manifest CID. "
                    "Models the decentralized k-of-n cooperation flow: pass one "
                    "--center-key per cooperating center.",
    )
    p.add_argument("manifest_cid", help="CID of manifest.json on IPFS")
    p.add_argument(
        "--center-key",
        action="append",
        default=[],
        metavar="KEYPAIR_JSON",
        help=(
            "Path to a center's keypair JSON (from vajra_keygen). "
            "Pass this flag once per cooperating center. The center's "
            "position in the manifest's centers list is read from the "
            "keypair file's `id` field. Must supply ≥ k to reconstruct."
        ),
    )
    p.add_argument("--vajra", required=True, help="Path to the compiled vajra binary")
    p.add_argument("--out", default="exam.pdf", help="Output PDF path")
    p.add_argument(
        "--skip-drand-check",
        action="store_true",
        help=(
            "Bypass the drand publish-time gate (Layer A policy check). "
            "The AAD is still verified cryptographically; only the "
            "wall-clock policy is skipped. Use for offline testing only."
        ),
    )
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args()


async def _resolve_center_keys(
    keypair_paths: list[str],
    manifest_cid: str,
    ipfs: IPFSClient,
) -> dict[int, str]:
    """Translate a list of keypair file paths into the center_index→privkey map
    that reconstruct_pdf wants. We need the manifest to know each ID's index."""
    if not keypair_paths:
        raise ReconstructError(
            "No --center-key flags given. Need ≥ k to reconstruct. "
            "Each cooperating center should run vajra_keygen and the "
            "coordinator collects the keypair files."
        )

    # Tiny double-fetch: reconstruct_pdf will fetch the manifest again. That's
    # fine — manifests are small, and this lets _resolve_center_keys be a
    # standalone helper. If you cared about a single fetch, you could refactor
    # the manifest into a class.
    try:
        manifest = await ipfs.cat_json(manifest_cid)
    except IPFSError as exc:
        raise ReconstructError(f"Cannot fetch manifest {manifest_cid}: {exc}") from exc

    if "centers" not in manifest:
        raise ReconstructError(
            "Manifest is missing 'centers' block (pre-Step-2 manifest?). "
            "Old manifests are not supported."
        )
    id_to_index = {c["id"]: int(c["index"]) for c in manifest["centers"]}

    out: dict[int, str] = {}
    for path in keypair_paths:
        cid_str, privkey_hex = load_center_keypair(path)
        if cid_str not in id_to_index:
            raise ReconstructError(
                f"Keypair {path} is for center {cid_str!r}, but the manifest "
                f"only knows about centers: {sorted(id_to_index)}"
            )
        idx = id_to_index[cid_str]
        if idx in out:
            raise ReconstructError(
                f"Two --center-key files claim center index {idx} "
                f"(both have id={cid_str!r})"
            )
        out[idx] = privkey_hex

    return out


async def _main() -> int:
    args = _parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(message)s",
    )

    ipfs = IPFSClient()  # reads settings.ipfs_node_list

    try:
        center_keys = await _resolve_center_keys(args.center_key, args.manifest_cid, ipfs)
        pdf = await reconstruct_pdf(
            args.manifest_cid, ipfs, args.vajra,
            center_keys=center_keys,
            skip_drand_check=args.skip_drand_check,
        )
    except (ManifestVerificationError, ReconstructError) as exc:
        log.error("Reconstruction failed: %s", exc)
        return 1

    Path(args.out).write_bytes(pdf)
    log.info("Wrote %s (%d bytes)", args.out, len(pdf))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
