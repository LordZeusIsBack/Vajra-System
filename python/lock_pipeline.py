"""lock_pipeline.py — Orchestrates the Rust CLI + Shamir + per-center + drand pipeline.

THREE LOCKS + ANCHOR
────────────────────
  Lock 1 — temporal (RSW puzzle):
    K is derived from sequential squaring of g, T_ops times mod N.
    Without p and q (destroyed in step 3), nobody can shortcut this.
    Centers must wait until T=0 and run `vajra solve` to get K.

  Lock 2 — organisational (Shamir SSS):
    A random 32-byte `data_key` is split into n shares.
    Any k-of-n exam centers must cooperate to reconstruct data_key.
    data_key wraps the RSW-locked payload (AES-GCM outer layer).

  Lock 3 — addressed (per-center X25519):
    Each Shamir share is hybrid-encrypted to its assigned center's X25519
    public key (eph-ECDH + HKDF + ChaCha20-Poly1305). IPFS becomes pure
    transport — only center i can read shard i. Without ≥k center private
    keys, the manifest + IPFS contents reveal nothing.

  Anchor — drand (Layer A):
    Both AES-GCM layers (inner Rust around PDF, outer Python around
    locked.json) share the same AAD: SHA256("vajra-v1" || target_round ||
    chain_hash). Tampering with the manifest's drand fields breaks both
    HMAC verification AND AES-GCM auth. The reconstruct flow ALSO enforces
    a wall-clock policy gate via multi-relay drand fetch.

  All conditions must hold to decrypt:
    k center privkeys + RSW key K + correct drand round in manifest.

WHAT CENTERS RECEIVE
────────────────────
  From IPFS (via manifest):
    puzzle.json      → needed by `vajra solve`
    payload.bin      → AES-GCM(data_key, locked.json, aad=AAD)
    shard_NNN.json   → encrypted to one specific center's pubkey

  From manifest:
    centers list: which pubkey owns which shard.
    drand block: target_round, chain_hash (for AAD re-derivation).

  Reconstruction:
    1. Verify manifest HMAC.
    2. Verify drand round R has published (clock + relays).
    3. Re-derive AAD from manifest's target_round + chain_hash.
    4. k centers each fetch their own shard, decrypt with their privkey.
    5. Combine k shares via Shamir → data_key.
    6. AES-GCM(data_key, payload, aad=AAD) → locked.json bytes.
    7. vajra solve --aad-hex <AAD> → decrypted exam PDF.
"""

import json
import platform
import secrets
import subprocess
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from centers import (
    CenterRegistration,
    CentersError,
    encrypt_share_for_center,
)
from config import settings
from drand_client import derive_aad, publish_time, round_at_or_after
from shamir import split as shamir_split


# ── Public exception ──────────────────────────────────────────────────────────

class PipelineError(RuntimeError):
    """Raised on any pipeline failure — message is safe to surface to the caller."""


# ── Main entry point ──────────────────────────────────────────────────────────

def run_vajra_pipeline(
    pdf_bytes: bytes,
    exam_start_seconds: int,
    n: int,
    k: int,
    centers: list[CenterRegistration],
) -> tuple[dict, bytes, list[dict], str, dict, list[dict]]:
    """Run the full admin lock pipeline synchronously.

    Call this via ``asyncio.to_thread(run_vajra_pipeline, ...)`` from
    an async FastAPI endpoint — subprocess.run() is blocking.

    Args:
        pdf_bytes:           Raw bytes of the uploaded exam PDF.
        exam_start_seconds:  Seconds from now until the exam starts.
                             Controls RSW puzzle difficulty AND the drand
                             target_round whose publish time gates reconstruction.
        n:                   Total Shamir shares to produce. MUST equal len(centers).
        k:                   Reconstruction threshold (k ≤ n shares needed).
        centers:             Pre-registered centers, in shard-index order.
                             Shard i is encrypted to centers[i].pubkey.

    Returns:
        puzzle_params      Parsed contents of puzzle.json (public, upload to IPFS).
        double_locked      AES-GCM(data_key, locked.json, aad=AAD) — outer payload.
        encrypted_shards   n EncryptedShard dicts: each has eph_pubkey_hex,
                           nonce_hex, ciphertext_hex. Plaintext shares NEVER
                           leave this function.
        nonce_hex          Hex of the 12-byte AES-GCM nonce (outer layer).
        drand_info         Dict with target_round, publish_time, chain_hash, aad_hex.
        centers_meta       List of {index, id, pubkey} dicts — what the manifest's
                           `centers` field will look like.

    Raises:
        PipelineError: On subprocess failure, binary not found, or timeout.
        CentersError:  If a center pubkey is malformed (caught at lock time,
                       not at reconstruct time).
    """
    if len(centers) != n:
        raise PipelineError(
            f"centers list has {len(centers)} entries but n={n}; "
            f"each shard must map to exactly one registered center"
        )

    vajra = settings.vajra_binary

    # ── Compute drand target round + AAD (Layer A: round-binding) ───────────
    # Target round = smallest drand round whose publish_time ≥ exam start time.
    # The AAD binds both AES-GCM layers to this round.
    lock_time_unix    = int(time.time())
    exam_start_unix   = lock_time_unix + exam_start_seconds
    chain_hash        = settings.drand_chain_hash
    target_round      = round_at_or_after(
        exam_start_unix, settings.drand_genesis, settings.drand_period,
    )
    target_pub_unix   = publish_time(
        target_round, settings.drand_genesis, settings.drand_period,
    )
    aad_bytes         = derive_aad(target_round, chain_hash)
    aad_hex           = aad_bytes.hex()
    print(
        f"[pipeline] drand: target_round={target_round} "
        f"publish_time={target_pub_unix} (lock+{target_pub_unix - lock_time_unix}s) "
        f"chain={chain_hash[:12]}…"
    )

    # All temp files live inside one directory; it's wiped on exit — including
    # any remnants of secret.json even if the secure-delete step fails.
    with tempfile.TemporaryDirectory(prefix="vajra_") as tmpdir:
        tmp         = Path(tmpdir)
        pdf_path    = tmp / "exam.pdf"
        puzzle_path = tmp / "puzzle.json"
        secret_path = tmp / "secret.json"
        locked_path = tmp / "locked.json"

        pdf_path.write_bytes(pdf_bytes)

        # ── Step 1: vajra generate ──────────────────────────────────────────
        print(f"[pipeline] vajra generate  --time {exam_start_seconds}s")
        _run(
            [vajra, "generate",
             "--time",       str(exam_start_seconds),
             "--puzzle-out", str(puzzle_path),
             "--secret-out", str(secret_path)],
            step="vajra generate",
        )
        puzzle_params: dict = json.loads(puzzle_path.read_text())
        print(f"[pipeline] puzzle ready  t_ops={puzzle_params.get('t_ops')}")

        # ── Step 2: vajra lock (with AAD) ───────────────────────────────────
        print("[pipeline] vajra lock")
        _run(
            [vajra, "lock",
             "--puzzle",   str(puzzle_path),
             "--secret",   str(secret_path),
             "--input",    str(pdf_path),
             "--output",   str(locked_path),
             "--aad-hex",  aad_hex],
            step="vajra lock",
        )
        locked_bytes = locked_path.read_bytes()
        print(f"[pipeline] locked.json  {len(locked_bytes):,} bytes")

        # ── Step 3: Destroy secret (p, q) ────────────────────────────────
        print("[pipeline] shredding secret.json ...")
        _secure_delete(secret_path)
        print("[pipeline] secret destroyed")

        # ── Step 4: Double-lock with random data_key (same AAD) ───────────
        data_key = secrets.token_bytes(32)
        nonce    = secrets.token_bytes(12)
        double_locked = AESGCM(data_key).encrypt(
            nonce, locked_bytes, associated_data=aad_bytes,
        )
        print(f"[pipeline] double-locked  {len(double_locked):,} bytes (aad={len(aad_bytes)}B)")

        # ── Step 5: Shamir-split data_key ─────────────────────────────────
        shares = shamir_split(data_key, n, k)
        print(f"[pipeline] Shamir split complete  {n} shares, k={k}")

        # ── Step 6: Encrypt each share to its center's pubkey (Step 2) ────
        # Plaintext shares exist ONLY in this local variable scope. After the
        # encrypted_shards list is built, `shares` and `data_key` are no
        # longer needed by anything downstream.
        encrypted_shards: list[dict] = []
        for i, share in enumerate(shares):
            try:
                enc = encrypt_share_for_center(share, centers[i].pubkey)
            except CentersError as exc:
                # Surface a clear, indexed error
                raise PipelineError(
                    f"Failed to encrypt shard {i} for center "
                    f"{centers[i].id!r}: {exc}"
                ) from exc
            encrypted_shards.append(enc.to_dict())
        print(
            f"[pipeline] per-center encryption complete: "
            f"{len(encrypted_shards)} shards, each addressed to one center"
        )

        # Best-effort: zero out the plaintext shares list. Python doesn't
        # actually guarantee deletion (immutable bytes), but breaking the
        # reference helps the GC and signals intent.
        shares = []
        del data_key

    # tmpdir is wiped here
    drand_info = {
        "target_round":  target_round,
        "publish_time":  target_pub_unix,
        "chain_hash":    chain_hash,
        "aad_hex":       aad_hex,
    }
    centers_meta = [
        {"index": i, "id": c.id, "pubkey": c.pubkey}
        for i, c in enumerate(centers)
    ]
    return (
        puzzle_params,
        double_locked,
        encrypted_shards,
        nonce.hex(),
        drand_info,
        centers_meta,
    )


# ── Subprocess helper ─────────────────────────────────────────────────────────

def _run(cmd: list[str], step: str) -> None:
    """Run a command, raising ``PipelineError`` on any failure.

    stderr from the subprocess is captured and included in the error message
    so the server log has the full context, but we truncate to 800 chars
    to avoid leaking huge outputs.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",       # Rust CLI prints box-drawing + ✓ ⚠ chars;
            errors="replace",       # Windows default (cp1252) crashes on them.
            timeout=settings.vajra_timeout_secs,
        )
    except FileNotFoundError:
        raise PipelineError(
            f"[{step}] Rust binary not found at {cmd[0]!r}. "
            "Run `make rs-build` first, then set VAJRA_BIN in .env."
        )
    except subprocess.TimeoutExpired:
        raise PipelineError(
            f"[{step}] Timed out after {settings.vajra_timeout_secs}s. "
            "Increase VAJRA_TIMEOUT_SECS in .env if the benchmark step is slow."
        )

    if result.returncode != 0:
        stderr_snippet = result.stderr.strip()[:800]
        raise PipelineError(
            f"[{step}] Exited with code {result.returncode}:\n{stderr_snippet}"
        )


# ── Secure delete ─────────────────────────────────────────────────────────────

def _secure_delete(path: Path) -> None:
    """Overwrite *path* with random data then unlink it.

    On Linux: delegates to ``shred -u -n 3`` (three random passes + unlink).
    Elsewhere: three manual passes (zeros, ones, random) then ``Path.unlink()``.

    SSD caveat: wear-levelling means the OS may not write to the same physical
    cells. The outer ``TemporaryDirectory`` context manager deletes the whole
    tmpdir on exit regardless, which is the real safety net. For genuine
    medium-secrecy, run on an encrypted filesystem and rotate the FS key.
    """
    size = path.stat().st_size

    if platform.system() == "Linux":
        try:
            subprocess.run(
                ["shred", "-u", "-n", "3", str(path)],
                check=True,
                timeout=30,
                capture_output=True,
            )
            return
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass  # shred not available; fall through to manual overwrite

    # Manual 3-pass overwrite
    for payload in (b"\x00" * size, b"\xFF" * size, secrets.token_bytes(size)):
        path.write_bytes(payload)
    path.unlink()