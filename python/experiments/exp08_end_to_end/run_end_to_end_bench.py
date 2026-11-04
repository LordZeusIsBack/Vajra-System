import argparse
import asyncio
import csv
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCRIPT_DIR = Path(__file__).resolve().parent
PYTHON_DIR = SCRIPT_DIR.parents[1]
REPO_ROOT = PYTHON_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR.parent))

import common

from centers import EncryptedShard, bulk_generate, decrypt_share_with_privkey, encrypt_share_for_center
from drand_client import DrandError, derive_aad, verify_round_published
from manifest import build_and_sign
from manifest import verify as verify_manifest
from shamir import reconstruct as shamir_reconstruct
from shamir import split as shamir_split

PDF_SIZES_MB = [1, 5, 10, 25, 50, 100]
N, K = 10, 8
PUZZLE_TIME_SECONDS = 2
REPETITIONS = 5
FORCE_FAKE_IPFS = False

CHAIN_HASH = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
TARGET_ROUND = 99999
AAD = derive_aad(TARGET_ROUND, CHAIN_HASH)

RESULTS_FILE = SCRIPT_DIR / "raw_results.csv"

TIMING_LINE_RE = re.compile(r"^VAJRA_TIMING (\w+) (.+)$")


def find_vajra_binary() -> Path:
    exe_name = "vajra.exe" if platform.system() == "Windows" else "vajra"
    candidate = REPO_ROOT / "rust" / "target" / "release" / exe_name
    if not candidate.exists():
        raise SystemExit(
            f"Compiled vajra binary not found at {candidate}\n"
            f"Build it first:  make rs-build   (or: cd rust && cargo build --release)"
        )
    return candidate


def run_vajra(binary: Path, args: list[str]) -> dict[str, float]:
    env = {**os.environ, "VAJRA_TIMING": "1"}
    result = subprocess.run(
        [str(binary), *args],
        capture_output=True, text=True,
        encoding="utf-8", errors="replace",
        timeout=300, env=env,
    )
    if result.returncode != 0: raise RuntimeError(f"`vajra {args[0]}` failed: {result.stderr.strip()[:400]}")

    breakdown: dict[str, float] = {}
    for line in result.stderr.splitlines():
        m = TIMING_LINE_RE.match(line.strip())
        if m:
            cmd = m.group(1)
            for pair in m.group(2).split():
                key, _, val = pair.partition("=")
                breakdown[f"{cmd}_{key}_sec"] = float(val)
    return breakdown


def make_pdf_bytes(size_mb: float) -> bytes:
    size_bytes = int(size_mb * 1024 * 1024)
    header = b"%PDF-1.4\n"
    return header + (b"\x00" * (size_bytes - len(header)))


async def get_ipfs_backend(args):
    if FORCE_FAKE_IPFS or args.ipfs == "sim":
        return common.SimulatedIPFS(node_count=args.nodes or 3)
    urls = common.resolve_ipfs_urls(args) if args.ipfs_urls or args.ipfs == "real" else []
    if not urls:
        from config import settings
        urls = settings.ipfs_node_list
    count = args.nodes or len(urls)
    backend = common.RealIPFS(urls, node_count=count)
    try:
        await asyncio.wait_for(backend.probe(), timeout=5.0)
    except Exception as exc:
        if args.ipfs == "real":
            raise SystemExit(f"Kubo nodes not reachable: {exc}")
        print(f"[ipfs] no live Kubo cluster reachable ({exc.__class__.__name__}) -> simulated")
        return common.SimulatedIPFS(node_count=args.nodes or 3)
    print(f"[ipfs] live Kubo nodes: {backend.versions}")
    return backend


async def drand_gate(mode: str) -> tuple[float | str, str]:
    if mode != "live":
        return "", "off"
    round_num = common.latest_round() - 2
    t0 = time.perf_counter()
    try:
        await verify_round_published(round_num)
        result = "ok"
    except DrandError as exc:
        result = "refused: " + " | ".join(str(exc).split("\n"))[:200]
    return time.perf_counter() - t0, result


async def run_one(binary: Path, ipfs, pdf_bytes: bytes, drand_mode: str = "off") -> tuple[dict, bool]:
    timings: dict[str, float] = {}
    tmpdir = tempfile.mkdtemp(prefix="vajra_e2e_")
    try:
        tmp = Path(tmpdir)
        pdf_path = tmp / "exam.pdf"
        puzzle_path = tmp / "puzzle.json"
        secret_path = tmp / "secret.json"
        locked_path = tmp / "locked.json"

        t0 = time.perf_counter()
        registry, keypairs = bulk_generate(N, id_prefix="E2E_CENTER")
        timings["centre_keygen_sec"] = time.perf_counter() - t0

        t0 = time.perf_counter()
        run_vajra(binary, [
            "generate", "--time", str(PUZZLE_TIME_SECONDS),
            "--puzzle-out", str(puzzle_path), "--secret-out", str(secret_path),
        ])
        timings["puzzle_generation_sec"] = time.perf_counter() - t0

        t0 = time.perf_counter()
        pdf_path.write_bytes(pdf_bytes)
        lock_breakdown = run_vajra(binary, [
            "lock", "--puzzle", str(puzzle_path), "--secret", str(secret_path),
            "--input", str(pdf_path), "--output", str(locked_path),
            "--aad-hex", AAD.hex(),
        ])
        locked_bytes = locked_path.read_bytes()
        timings["lock_wall_sec"] = time.perf_counter() - t0
        timings.update(lock_breakdown)
        secret_path.unlink(missing_ok=True)

        data_key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        t0 = time.perf_counter()
        payload_bytes = AESGCM(data_key).encrypt(nonce, locked_bytes, associated_data=AAD)
        timings["outer_lock_sec"] = time.perf_counter() - t0

        t0 = time.perf_counter()
        shares = shamir_split(data_key, N, K)
        timings["shamir_split_sec"] = time.perf_counter() - t0

        t0 = time.perf_counter()
        encrypted_shards = [
            encrypt_share_for_center(share, registry[i].pubkey).to_dict()
            for i, share in enumerate(shares)
        ]
        timings["centre_encryption_sec"] = time.perf_counter() - t0

        puzzle_bytes = puzzle_path.read_bytes()

        t0 = time.perf_counter()
        puzzle_cid = await ipfs.add_bytes(puzzle_bytes, "puzzle.json", node_index=0)
        payload_cid = await ipfs.add_bytes(payload_bytes, "payload.bin", node_index=0)
        shard_entries = []
        for i, s in enumerate(encrypted_shards):
            node = i % ipfs.node_count
            cid = await ipfs.add_json({"center_id": registry[i].id, **s}, f"shard_{i:03d}.json", node_index=node)
            shard_entries.append({"cid": cid, "node_index": node})
        manifest = build_and_sign(
            n=N, k=K, puzzle_cid=puzzle_cid, payload_cid=payload_cid, nonce_hex=nonce.hex(),
            shard_cids=shard_entries,
            centers=[{"index": i, "id": r.id, "pubkey": r.pubkey} for i, r in enumerate(registry)],
            drand={"chain_hash": CHAIN_HASH, "target_round": TARGET_ROUND,
                   "publish_time": 1595431050 + 30 * TARGET_ROUND},
        )
        manifest_cid = await ipfs.add_json(manifest, "manifest.json", node_index=0)
        timings["ipfs_upload_sec"] = time.perf_counter() - t0
        total_ipfs_bytes = (
            len(puzzle_bytes) + len(payload_bytes)
            + sum(len(json.dumps(s).encode()) for s in encrypted_shards)
        )

        t0 = time.perf_counter()
        fetched_manifest = await ipfs.cat_json(manifest_cid, node_index=0)
        if not verify_manifest(fetched_manifest):
            raise RuntimeError("fetched manifest failed HMAC verification")
        fetched_puzzle_bytes = await ipfs.cat(fetched_manifest["puzzle_cid"], node_index=0)
        fetched_payload_bytes = await ipfs.cat(fetched_manifest["payload_cid"], node_index=0)
        fetched_shards = [
            await ipfs.cat_json(e["cid"], node_index=e["node_index"])
            for e in fetched_manifest["shard_cids"][:K]
        ]
        timings["ipfs_fetch_sec"] = time.perf_counter() - t0

        gate_sec, gate_result = await drand_gate(drand_mode)
        if gate_sec != "":
            timings["drand_gate_sec"] = gate_sec
        timings["drand_gate_result"] = gate_result

        t0 = time.perf_counter()
        plaintext_shares = [
            decrypt_share_with_privkey(EncryptedShard.from_dict(fetched_shards[i]), keypairs[i][1])
            for i in range(K)
        ]
        timings["centre_reconstruction_sec"] = time.perf_counter() - t0

        t0 = time.perf_counter()
        recovered_data_key = shamir_reconstruct(plaintext_shares, expected_threshold=K)
        timings["shamir_combine_sec"] = time.perf_counter() - t0

        t0 = time.perf_counter()
        recovered_locked_bytes = AESGCM(recovered_data_key).decrypt(
            nonce, fetched_payload_bytes, associated_data=AAD,
        )
        timings["outer_decrypt_sec"] = time.perf_counter() - t0

        fetched_puzzle_path = tmp / "fetched_puzzle.json"
        fetched_locked_path = tmp / "fetched_locked.json"
        solved_path = tmp / "solved.pdf"
        t0 = time.perf_counter()
        fetched_puzzle_path.write_bytes(fetched_puzzle_bytes)
        fetched_locked_path.write_bytes(recovered_locked_bytes)
        solve_breakdown = run_vajra(binary, [
            "solve", "--puzzle", str(fetched_puzzle_path),
            "--locked", str(fetched_locked_path),
            "--output", str(solved_path), "--aad-hex", AAD.hex(),
        ])
        recovered_pdf = solved_path.read_bytes()
        timings["solve_wall_sec"] = time.perf_counter() - t0
        timings.update(solve_breakdown)

        correct = recovered_pdf == pdf_bytes
    finally:
        t0 = time.perf_counter()
        shutil.rmtree(tmpdir, ignore_errors=True)
        timings["cleanup_sec"] = time.perf_counter() - t0

    return {**timings, "total_ipfs_bytes": total_ipfs_bytes, "objects_uploaded": N + 3}, correct


FIELDNAMES = [
    "pdf_size_mb", "run_id", "n", "k", "puzzle_time_target_sec", "ipfs_backend",
    "ipfs_nodes", "objects_uploaded", "drand_backend", "drand_gate_sec", "drand_gate_result",
    "centre_keygen_sec", "puzzle_generation_sec",
    "lock_wall_sec", "lock_parse_sec", "lock_keyderiv_sec", "lock_encrypt_sec", "lock_write_sec",
    "outer_lock_sec", "shamir_split_sec", "centre_encryption_sec",
    "ipfs_upload_sec", "ipfs_fetch_sec",
    "centre_reconstruction_sec", "shamir_combine_sec", "outer_decrypt_sec",
    "solve_wall_sec", "solve_parse_sec", "solve_squaring_sec", "solve_decrypt_sec", "solve_write_sec",
    "cleanup_sec", "total_ipfs_bytes", "wall_clock_total_sec", "reconstruction_correct",
]


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    common.add_ipfs_arguments(ap, default="auto", allow_auto=True)
    ap.add_argument("--nodes", type=int, default=None,
                    help="number of shard nodes (default: all given URLs; 3 for sim)")
    ap.add_argument("--drand", choices=["off", "live"], default="off")
    ap.add_argument("--sizes", default=",".join(str(x) for x in PDF_SIZES_MB))
    ap.add_argument("--reps", type=int, default=REPETITIONS)
    ap.add_argument("--out", type=Path, default=RESULTS_FILE)
    args = ap.parse_args()
    sizes = [float(x) if "." in x else int(x) for x in args.sizes.split(",")]

    binary = find_vajra_binary()
    ipfs = await get_ipfs_backend(args)
    backend = "real" if ipfs.is_real else "simulated"

    print(
        f"Starting Experiment 08: End-to-End Performance "
        f"(sizes={sizes} MB, n={N}, k={K}, "
        f"puzzle_time={PUZZLE_TIME_SECONDS}s, {args.reps} reps each, "
        f"ipfs={backend} x{ipfs.node_count}, drand={args.drand})"
    )

    rows = []
    for size_mb in sizes:
        pdf_bytes = make_pdf_bytes(size_mb)
        print(f"\n-- PDF size {size_mb} MB --")
        for run_id in range(1, args.reps + 1):
            t_wall0 = time.perf_counter()
            timings, correct = await run_one(binary, ipfs, pdf_bytes, args.drand)
            wall = time.perf_counter() - t_wall0

            row = {
                "pdf_size_mb": size_mb,
                "run_id": run_id,
                "n": N,
                "k": K,
                "puzzle_time_target_sec": PUZZLE_TIME_SECONDS,
                "ipfs_backend": backend,
                "ipfs_nodes": ipfs.node_count,
                "drand_backend": args.drand,
                **{key: (round(val, 6) if isinstance(val, float) else val)
                   for key, val in timings.items()},
                "wall_clock_total_sec": round(wall, 6),
                "reconstruction_correct": correct,
            }
            rows.append(row)

            status = "OK" if correct else "MISMATCH"
            squaring = timings.get("solve_squaring_sec")
            squaring_str = f"{squaring:.3f}s" if squaring is not None else "n/a (unpatched binary)"
            gate = f", drand gate {timings['drand_gate_result']}" if args.drand == "live" else ""
            print(
                f"  run {run_id}/{args.reps}: total={wall:.3f}s "
                f"(solve_wall={timings['solve_wall_sec']:.3f}s [whole CLI call, grows with size -- expected], "
                f"solve_squaring={squaring_str} [pure RSW -- should stay flat], "
                f"lock_wall={timings['lock_wall_sec']:.3f}s{gate}) [{status}]"
            )

    with open(args.out, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=FIELDNAMES, restval="")
        writer.writeheader()
        writer.writerows(rows)

    mismatches = sum(1 for r in rows if not r["reconstruction_correct"])
    print(f"\nExperiment complete: {len(rows)} runs, {mismatches} mismatches. Raw data -> {args.out}")


if __name__ == "__main__":
    asyncio.run(main())