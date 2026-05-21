"""main.py — VAJRA Source Vault (FastAPI)

ENDPOINTS
  POST /api/v1/lock              Admin uploads PDF → fully automated pipeline
  GET  /api/v1/manifest/{cid}   Fetch + verify a manifest from IPFS
  GET  /api/v1/nodes            Show health of all configured IPFS nodes
  GET  /                        Health check

AUTOMATED PIPELINE (POST /api/v1/lock)
  1.  vajra generate   → puzzle.json + secret.json       [Rust subprocess]
  2.  vajra lock       → locked.json (RSW-encrypted PDF)  [Rust subprocess]
  3.  shred            → secret.json destroyed             [secure delete]
  4.  double-lock      → AES-GCM(data_key, locked.json)   [Python]
  5.  Shamir split     → n shares of data_key              [Python]
  6.  IPFS upload      → puzzle.json, payload, n shards    [Python → IPFS]
  7.  Sign manifest    → HMAC-SHA256 over all CIDs         [Python]

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

from config import settings
from ipfs_client import IPFSClient, IPFSError
from lock_pipeline import PipelineError, run_vajra_pipeline
from manifest import build_and_sign, verify as verify_manifest

log = logging.getLogger("vajra")


# ── App lifecycle ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Probe all IPFS nodes at startup; warn but don't abort if any are down."""
    log.info("Checking IPFS nodes ...")
    statuses = await _ipfs.health_check_all()
    for url, ver in statuses.items():
        if ver:
            log.info("  ✓  %s  kubo %s", url, ver)
        else:
            log.warning("  ⚠  %s  unreachable", url)

    log.info("Rust binary: %s", settings.vajra_binary)
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
    """Merge per-request overrides with env defaults and validate."""
    n = req_n if req_n is not None else settings.default_n
    k = req_k if req_k is not None else settings.default_k

    errors: list[str] = []
    if not (2 <= n <= settings.max_shards):
        errors.append(f"n must satisfy 2 ≤ n ≤ {settings.max_shards} (MAX_SHARDS), got {n}")
    if k < settings.min_threshold:
        errors.append(f"k must be ≥ {settings.min_threshold} (MIN_THRESHOLD), got {k}")
    if k > n:
        errors.append(f"Threshold k ({k}) cannot exceed total shards n ({n})")
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
    summary="Lock an exam PDF (fully automated)",
    description="""
Upload an exam PDF. The server runs the full automated pipeline and returns
an IPFS manifest CID. No further human action is needed.

**Pipeline (zero human intervention after upload)**

1. `vajra generate` — creates RSW puzzle (N, g, T_ops) + admin secret (p, q)
2. `vajra lock` — computes K via φ(N) shortcut, encrypts PDF: `AES-GCM(SHA256(K), pdf)`
3. `shred secret.json` — p and q destroyed; K is now unrecoverable until T=0
4. Double-lock — `AES-GCM(data_key, locked.json)` with random 32-byte `data_key`
5. Shamir split — `data_key` split into n shares (any k reconstruct)
6. IPFS upload — puzzle.json + payload + n shard files (round-robin across nodes)
7. Sign manifest — HMAC-SHA256 over all CIDs

**Center reconstruction (at T=0)**

1. Collect k shard files → reconstruct `data_key`
2. Fetch `payload_cid` → decrypt with `data_key` → `locked.json`
3. `vajra solve --puzzle puzzle.json --locked locked.json` → decrypted exam PDF
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

    # ── Run Rust pipeline in thread pool (subprocess calls are blocking) ──────
    # asyncio.to_thread keeps the event loop free while vajra runs.
    log.info(
        "Starting pipeline: exam_start=%ds  n=%d  k=%d  pdf=%d bytes",
        exam_start_seconds, n_val, k_val, len(pdf_bytes),
    )
    try:
        puzzle_params, double_locked, shares, nonce_hex = await asyncio.to_thread(
            run_vajra_pipeline,
            pdf_bytes,
            exam_start_seconds,
            n_val,
            k_val,
        )
    except PipelineError as exc:
        log.error("Pipeline failed: %s", exc)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"Rust pipeline error: {exc}",
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

        # Shamir shares → round-robin across all configured nodes
        shard_cid_entries: list[dict] = []
        for idx, share in enumerate(shares):
            node_idx = idx % _ipfs.node_count
            shard_obj = {
                "shard_index": idx,          # 0-based position in shard_cids list
                "x":           share[0],     # Shamir x-coordinate (1 … n)
                "share_hex":   share[1:].hex(),  # GF(2^8) evaluations of data_key bytes
                "payload_cid": payload_cid,  # pointer to the outer-locked payload
                "nonce_hex":   nonce_hex,    # nonce for outer AES-GCM layer
                "puzzle_cid":  puzzle_cid,   # pointer to puzzle.json
            }
            cid = await _ipfs.add_json(
                shard_obj,
                filename=f"shard_{idx:03d}.json",
                node_index=node_idx,
            )
            shard_cid_entries.append({"cid": cid, "node_index": node_idx})
            log.info("shard_%03d.json → %s (node %d)", idx, cid, node_idx)

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
