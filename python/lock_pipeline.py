"""lock_pipeline.py — Orchestrates the Rust CLI + Shamir SSS + drand pipeline.

DOUBLE-LOCK + DRAND BINDING (Layer A)
─────────────────────────────────────
  Lock 1 — temporal (RSW puzzle):
    K is derived from sequential squaring of g, T_ops times mod N.
    Without p and q (destroyed in step 3), nobody can shortcut this.
    Centers must wait until T=0 and run `vajra solve` to get K.

    ⚠ T_ops is calibrated to admin hardware; this alone gives sequentiality,
    not wall-clock anchoring. The drand binding below partially closes that.

  Lock 2 — organisational (Shamir SSS):
    A random 32-byte `data_key` is split into n shares.
    Any k-of-n exam centers must cooperate to reconstruct data_key.
    data_key wraps the RSW-locked payload (AES-GCM outer layer).

  Drand binding (Layer A):
    Both AES-GCM layers (inner Rust around PDF, outer Python around
    locked.json) are computed with the SAME AAD:
        aad = SHA256("vajra-v1" || target_round_be_u64 || chain_hash_bytes)
    where target_round is the drand round whose publish_time equals the exam
    start time. The AAD is reconstructed by reconstruct.py from manifest
    fields; tampering with target_round in the manifest causes AAD mismatch
    → AES-GCM auth failure. This is cryptographic round-binding.

  All conditions must hold to decrypt:
    k Shamir shares + RSW key K + correct drand round in manifest.

WHAT CENTERS RECEIVE
────────────────────
  From IPFS (via manifest):
    puzzle.json      → needed by `vajra solve`
    payload.bin      → AES-GCM(data_key, locked.json bytes, aad=AAD)
    shard_NNN.json   → each center's Shamir share of data_key

  From manifest:
    target_round, chain_hash → re-derive AAD identically.

  Reconstruction:
    1. Collect k shard files  → reconstruct data_key
    2. Verify drand round R has published (clock + relays)  ← Layer A gate
    3. Re-derive AAD from manifest's target_round + chain_hash
    4. Fetch payload.bin → AES-GCM-decrypt with data_key+AAD → locked.json
    5. vajra solve --aad-hex <AAD>  → decrypted exam PDF
"""

import json
import platform
import secrets
import subprocess
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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
) -> tuple[dict, bytes, list[bytes], str, dict]:
    """Run the full admin lock pipeline synchronously.

    Call this via ``asyncio.to_thread(run_vajra_pipeline, ...)`` from
    an async FastAPI endpoint — subprocess.run() is blocking.

    Args:
        pdf_bytes:           Raw bytes of the uploaded exam PDF.
        exam_start_seconds:  Seconds from now until the exam starts.
                             Controls RSW puzzle difficulty (T_ops = secs × squarings/sec)
                             AND determines the drand target_round whose publish time
                             must be reached before reconstruction is permitted.
        n:                   Total Shamir shares to produce.
        k:                   Reconstruction threshold (k ≤ n shares needed).

    Returns:
        puzzle_params   Parsed contents of puzzle.json (public, upload to IPFS).
        double_locked   AES-GCM(data_key, locked.json bytes, aad=AAD) — outer payload.
        shares          n Shamir share bytestrings (one per exam center / IPFS node).
        nonce_hex       Hex of the 12-byte AES-GCM nonce used in the outer layer.
        drand_info      Dict with target_round, publish_time, chain_hash, aad_hex.
                        Caller passes these into the manifest so reconstruct.py
                        can re-derive the AAD and enforce the policy gate.

    Raises:
        PipelineError: On subprocess failure, binary not found, or timeout.
    """
    vajra = settings.vajra_binary

    # ── Compute drand target round + AAD (Layer A: round-binding) ───────────
    # Target round = smallest drand round whose publish_time ≥ exam start time.
    # The AAD binds both AES-GCM layers to this round; tampering with
    # target_round in the manifest causes outer (and inner) decrypt to fail.
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
        # Produces puzzle.json (public) and secret.json (contains p, q — TOP SECRET).
        # The 2-second benchmark inside `generate` is the bottleneck here.
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
        # Uses the φ(N) shortcut to compute K instantly, then encrypts:
        #   locked.json = { nonce, ciphertext: AES-GCM(SHA256(K), pdf, aad=AAD) }
        # The AAD ties the inner layer to the drand target round.
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
        # After this point, K is unrecoverable until T=0.
        # The tempdir context manager is a safety net; _secure_delete is the
        # real defence — it overwrites before unlinking.
        # NOTE: on SSDs, wear-levelling means overwrites may not hit original
        # physical cells. For prototype this is acceptable; for production
        # consider full-disk encryption + key destruction instead.
        print("[pipeline] shredding secret.json ...")
        _secure_delete(secret_path)
        print("[pipeline] secret destroyed")

        # ── Step 4: Double-lock with random data_key (same AAD) ───────────
        # data_key is the Shamir secret: k centers reconstruct it to get here.
        # The outer layer uses the SAME AAD as the inner — tampering with
        # target_round breaks both layers, not just one. The HMAC on the
        # manifest is the first line of defence; AAD is the cryptographic
        # belt-and-suspenders if HMAC verification is somehow skipped.
        data_key = secrets.token_bytes(32)
        nonce    = secrets.token_bytes(12)
        double_locked = AESGCM(data_key).encrypt(
            nonce, locked_bytes, associated_data=aad_bytes,
        )
        print(f"[pipeline] double-locked  {len(double_locked):,} bytes (aad={len(aad_bytes)}B)")

        # ── Step 5: Shamir-split data_key ─────────────────────────────────
        # Each share is 33 bytes: [x_coord (1 byte)] + [f_b(x) for each of the
        # 32 data_key bytes]. Any k shares reconstruct data_key exactly.
        shares = shamir_split(data_key, n, k)
        print(f"[pipeline] Shamir split complete  {n} shares, k={k}")

    # tmpdir is wiped here (including any un-shredded residue on some OSes)
    drand_info = {
        "target_round":  target_round,
        "publish_time":  target_pub_unix,
        "chain_hash":    chain_hash,
        "aad_hex":       aad_hex,
    }
    return puzzle_params, double_locked, shares, nonce.hex(), drand_info


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
