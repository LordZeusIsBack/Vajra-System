"""main.py — VAJRA Source Vault (FastAPI)

ENDPOINTS
  POST /api/v1/lock              Admin uploads PDF → fully automated pipeline
  GET  /api/v1/manifest/{cid}   Fetch + verify a manifest from IPFS
  GET  /api/v1/nodes            Show health of all configured IPFS nodes
  GET  /                        Health check

AUTOMATED PIPELINE (POST /api/v1/lock)
  0.  Compute drand target_round + AAD  (Layer A: time-anchor)  [Python, offline]
  1.  vajra generate   → puzzle.json + secret.json       [Rust subprocess]
  2.  vajra lock --aad-hex … → locked.json (RSW + AAD)   [Rust subprocess]
  3.  shred            → secret.json destroyed             [secure delete]
  4.  double-lock      → AES-GCM(data_key, locked.json, aad=AAD)   [Python]
  5.  Shamir split     → n shares of data_key              [Python]
  6.  Per-center encrypt → each share → X25519+ChaCha20 to one center pubkey  [Python]
  7.  IPFS upload      → puzzle.json, payload, n encrypted shards  [Python → IPFS]
  8.  Sign manifest    → HMAC over CIDs + drand + centers   [Python]

Start with:
  make py-server
  # or:
  cd python && uv run fastapi dev main.py
"""

import asyncio
import logging
import json
from contextlib import asynccontextmanager
from typing import Annotated

import httpx
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel

from centers import CentersError, load_registry
from config import settings
from ipfs_client import IPFSClient, IPFSError
from lock_pipeline import PipelineError, run_vajra_pipeline
from manifest import build_and_sign, verify as verify_manifest

log = logging.getLogger("vajra")


# ── App lifecycle ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Probe all IPFS nodes at startup; warn but don't abort if any are down.
    Also load the centers registry — fail fast if it's missing or malformed,
    because the lock pipeline can't run without it."""
    log.info("Checking IPFS nodes ...")
    statuses = await _ipfs.health_check_all()
    for url, ver in statuses.items():
        if ver:
            log.info("  ✓  %s  kubo %s", url, ver)
        else:
            log.warning("  ⚠  %s  unreachable", url)

    log.info("Rust binary: %s", settings.vajra_binary)

    # Centers registry: load once at startup. We hold this in module-level
    # state to avoid re-reading the JSON on every lock request, but reload
    # is a fresh process restart away if you re-register centers.
    try:
        global _registry
        _registry = load_registry(settings.centers_registry_path)
        log.info(
            "Centers registry loaded: %d centers from %s",
            len(_registry), settings.centers_registry_path,
        )
    except CentersError as exc:
        log.error("Centers registry failed to load: %s", exc)
        log.error(
            "The /api/v1/lock endpoint will reject requests until this is fixed."
        )
        _registry = []

    yield


app = FastAPI(
    title="VAJRA Source Vault",
    version="0.2.0",
    description=(
        "Upload an exam PDF → get back an IPFS-pinned manifest. "
        "All cryptography (RSW time-lock + Shamir SSS) runs automatically."
    ),
    lifespan=lifespan,
)

_ipfs = IPFSClient()   # reads settings.ipfs_node_list
_registry: list = []   # populated at startup from settings.centers_registry_path


# ── Response models ───────────────────────────────────────────────────────────

class LockResponse(BaseModel):
    manifest_cid: str
    manifest: dict


class ManifestResponse(BaseModel):
    cid: str
    hmac_valid: bool
    manifest: dict


class NodeStatus(BaseModel):
    url: str
    version: str | None
    reachable: bool


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_shamir_params(req_n: int | None, req_k: int | None) -> tuple[int, int]:
    """Merge per-request overrides with env defaults and validate.

    Also enforces that n does not exceed the number of registered centers —
    we can't encrypt more shards than we have pubkeys for.
    """
    n = req_n if req_n is not None else settings.default_n
    k = req_k if req_k is not None else settings.default_k

    errors: list[str] = []
    if not (2 <= n <= settings.max_shards):
        errors.append(f"n must satisfy 2 ≤ n ≤ {settings.max_shards} (MAX_SHARDS), got {n}")
    if k < settings.min_threshold:
        errors.append(f"k must be ≥ {settings.min_threshold} (MIN_THRESHOLD), got {k}")
    if k > n:
        errors.append(f"Threshold k ({k}) cannot exceed total shards n ({n})")
    if not _registry:
        errors.append(
            "Centers registry is empty or failed to load. "
            f"Generate one: python vajra_keygen.py bulk --n {n} --out-dir ./keys"
        )
    elif n > len(_registry):
        errors.append(
            f"n ({n}) exceeds registered centers ({len(_registry)}). "
            f"Register more centers, or request smaller n."
        )
    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"errors": errors},
        )
    return n, k


def _is_pdf(data: bytes) -> bool:
    return data[:4] == b"%PDF"


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def health():
    return {"service": "VAJRA Source Vault", "version": "0.2.0", "status": "ok"}


@app.get("/api/v1/nodes", response_model=list[NodeStatus], summary="IPFS node health")
async def node_health() -> list[NodeStatus]:
    """Show the reachability and kubo version of every configured IPFS node."""
    statuses = await _ipfs.health_check_all()
    return [
        NodeStatus(url=url, version=ver, reachable=ver is not None)
        for url, ver in statuses.items()
    ]


@app.post(
    "/api/v1/lock",
    response_model=LockResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Lock an exam PDF (fully automated, per-center + drand-anchored)",
    description="""
Upload an exam PDF. The server runs the full automated pipeline and returns
an IPFS manifest CID. No further human action is needed.

**Pipeline (zero human intervention after upload)**

0. Compute drand `target_round` whose publish time = lock_time + exam_start_seconds.
   Derive `aad = SHA256("vajra-v1" || target_round || chain_hash)`.
1. `vajra generate` — creates RSW puzzle (N, g, T_ops) + admin secret (p, q)
2. `vajra lock --aad-hex …` — computes K via φ(N) shortcut, encrypts PDF:
   `AES-GCM(SHA256(K), pdf, aad=AAD)`
3. `shred secret.json` — p and q destroyed; K is now unrecoverable until T=0
4. Double-lock — `AES-GCM(data_key, locked.json, aad=AAD)` with random 32-byte `data_key`
5. Shamir split — `data_key` split into n shares (any k reconstruct)
6. **Per-center encryption** — each share is X25519+ChaCha20-Poly1305 encrypted
   to one center's public key from the centers registry. Plaintext shares
   never leave the server.
7. IPFS upload — puzzle.json + payload + n encrypted shard files
8. Sign manifest — HMAC-SHA256 over all CIDs + centers + drand fields

**Center reconstruction (at T=0)**

1. Each of k centers fetches their assigned `shard_cid` and decrypts with
   their X25519 private key → plaintext Shamir share
2. k shares combined via Shamir → `data_key`
3. Verify manifest HMAC; re-derive AAD from `drand.target_round` + `drand.chain_hash`
4. Check drand round R has published (local clock + ≥2 relay agreement)
5. `AES-GCM-decrypt(data_key, payload, aad=AAD)` → `locked.json`
6. `vajra solve --aad-hex <AAD>` → decrypted exam PDF
""",
)
async def lock_exam(
    file: Annotated[
        UploadFile,
        File(description="Exam PDF to lock"),
    ],
    exam_start_seconds: Annotated[
        int,
        Form(
            ge=60,
            description=(
                "Seconds from now until the exam starts. "
                "Controls RSW puzzle difficulty: T_ops = exam_start_seconds × squarings/sec. "
                "Minimum 60s (shorter durations don't leave time for the benchmark step)."
            ),
        ),
    ],
    n: Annotated[
        int | None,
        Form(description="Total shards to generate (overrides DEFAULT_N)"),
    ] = None,
    k: Annotated[
        int | None,
        Form(description="Reconstruction threshold (overrides DEFAULT_K)"),
    ] = None,
    exam_id: Annotated[
        str | None,
        Form(description="Optional exam UUID for tracking; auto-generated if omitted"),
    ] = None,
) -> LockResponse:

    # ── Validate params ───────────────────────────────────────────────────────
    n_val, k_val = _resolve_shamir_params(n, k)

    # ── Read + validate PDF ───────────────────────────────────────────────────
    pdf_bytes = await file.read()

    if not pdf_bytes:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Uploaded file is empty")
    if len(pdf_bytes) > settings.max_upload_bytes:
        limit_mb = settings.max_upload_bytes // (1024 * 1024)
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"File exceeds the {limit_mb} MB upload limit",
        )
    if not _is_pdf(pdf_bytes):
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            "File does not appear to be a PDF (missing %PDF magic bytes)",
        )

    # ── Pick the first n centers from the registry (deterministic) ────────────
    # For the demo we always use the first n. A real deployment would let the
    # admin pick specific centers per exam (e.g. only Mumbai region for a
    # regional test); that's a small API change away.
    selected_centers = _registry[:n_val]

    # ── Run Rust pipeline in thread pool (subprocess calls are blocking) ──────
    # asyncio.to_thread keeps the event loop free while vajra runs.
    log.info(
        "Starting pipeline: exam_start=%ds  n=%d  k=%d  centers=%d  pdf=%d bytes",
        exam_start_seconds, n_val, k_val, len(selected_centers), len(pdf_bytes),
    )
    try:
        (
            puzzle_params,
            double_locked,
            encrypted_shards,     # ← Step 2: list[dict] of EncryptedShard
            nonce_hex,
            drand_info,           # ← Layer A: target_round, publish_time, chain_hash, aad_hex
            centers_meta,         # ← Step 2: list[{index, id, pubkey}] for manifest
        ) = await asyncio.to_thread(
            run_vajra_pipeline,
            pdf_bytes,
            exam_start_seconds,
            n_val,
            k_val,
            selected_centers,
        )
    except PipelineError as exc:
        log.error("Pipeline failed: %s", exc)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"Rust pipeline error: {exc}",
        )
    except CentersError as exc:
        log.error("Centers encryption failed: %s", exc)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"Per-center encryption error: {exc}",
        )

    log.info(
        "drand anchor: round=%d  publish_time=%d  chain=%s…",
        drand_info["target_round"],
        drand_info["publish_time"],
        drand_info["chain_hash"][:12],
    )

    # ── Upload to IPFS ────────────────────────────────────────────────────────
    try:
        # puzzle.json → always on node 0 (primary, most reliable)
        puzzle_cid = await _ipfs.add_bytes(
            json.dumps(puzzle_params, separators=(",", ":")).encode(),
            filename="puzzle.json",
            node_index=0,
        )
        log.info("puzzle.json → %s (node 0)", puzzle_cid)

        # double-locked payload → node 0 as well (it's big, keep on primary)
        payload_cid = await _ipfs.add_bytes(
            double_locked,
            filename="payload.bin",
            node_index=0,
        )
        log.info("payload.bin → %s (node 0)  %d bytes", payload_cid, len(double_locked))

        # Encrypted shards → round-robin across all configured nodes.
        # Each shard's on-IPFS content is now the EncryptedShard dict from
        # the pipeline; the plaintext Shamir share never left run_vajra_pipeline.
        shard_cid_entries: list[dict] = []
        for idx, enc_shard in enumerate(encrypted_shards):
            node_idx = idx % _ipfs.node_count
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
            cid = await _ipfs.add_json(
                shard_obj,
                filename=f"shard_{idx:03d}.json",
                node_index=node_idx,
            )
            shard_cid_entries.append({"cid": cid, "node_index": node_idx})
            log.info(
                "shard_%03d.json → %s  (node %d, center %s)",
                idx, cid, node_idx, centers_meta[idx]["id"],
            )

    except (IPFSError, httpx.HTTPError) as exc:
        log.error("IPFS upload failed: %s", exc)
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"IPFS upload failed: {exc}",
        )

    # ── Build + sign manifest ─────────────────────────────────────────────────
    manifest = build_and_sign(
        n=n_val,
        k=k_val,
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
        manifest_cid = await _ipfs.add_json(manifest, filename="manifest.json", node_index=0)
        log.info("manifest.json → %s", manifest_cid)
    except (IPFSError, httpx.HTTPError) as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Manifest upload failed: {exc}")

    return LockResponse(manifest_cid=manifest_cid, manifest=manifest)


@app.get(
    "/api/v1/manifest/{cid}",
    response_model=ManifestResponse,
    summary="Fetch and verify a manifest from IPFS",
)
async def get_manifest(cid: str) -> ManifestResponse:
    """Retrieve a previously uploaded manifest by CID and verify its HMAC.

    Returns ``hmac_valid: false`` (not HTTP 4xx) when the signature is bad,
    so callers can decide how to handle a potentially tampered manifest.
    """
    try:
        data = await _ipfs.cat_json(cid)
    except IPFSError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))

    return ManifestResponse(
        cid=cid,
        hmac_valid=verify_manifest(data),
        manifest=data,
    )