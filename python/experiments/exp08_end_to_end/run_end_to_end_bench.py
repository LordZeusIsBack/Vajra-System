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

os.environ.setdefault("MANIFEST_HMAC_SECRET", secrets.token_hex(32))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCRIPT_DIR = Path(__file__).resolve().parent
PYTHON_DIR = SCRIPT_DIR.parents[1]
REPO_ROOT = PYTHON_DIR.parent
sys.path.insert(0, str(PYTHON_DIR))

from centers import EncryptedShard, bulk_generate, decrypt_share_with_privkey, encrypt_share_for_center
from drand_client import derive_aad
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


class SimulatedIPFS:
    is_real = False

    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}
        self._n = 0

    async def add_bytes(self, data: bytes) -> str:
        self._n += 1
        cid = f"sim-{self._n}"
        self._store[cid] = data
        return cid

    async def add_json(self, obj: dict) -> str:
        return await self.add_bytes(json.dumps(obj, separators=(",", ":")).encode())

    async def cat(self, cid: str) -> bytes:
        return self._store[cid]

    async def cat_json(self, cid: str) -> dict:
        return json.loads(await self.cat(cid))


class RealIPFS:
    is_real = True

    def __init__(self, client) -> None:
        self._client = client

    async def add_bytes(self, data: bytes) -> str:
        return await self._client.add_bytes(data, node_index=0)

    async def add_json(self, obj: dict) -> str:
        return await self._client.add_json(obj, node_index=0)

    async def cat(self, cid: str) -> bytes:
        return await self._client.cat(cid, node_index=0)

    async def cat_json(self, cid: str) -> dict:
        return await self._client.cat_json(cid, node_index=0)


async def get_ipfs_backend():
    if FORCE_FAKE_IPFS:
        print("[ipfs] FORCE_FAKE_IPFS=True -> using simulated in-memory IPFS")
        return SimulatedIPFS()
    try:
        from ipfs_client import IPFSClient
        client = IPFSClient()
        version = await asyncio.wait_for(client.version(node_index=0), timeout=2.0)
        print(f"[ipfs] live Kubo daemon detected (v{version}) at {client.node_for(0)} -> using it")
        return RealIPFS(client)
    except Exception as exc:
        print(f"[ipfs] no live Kubo daemon reachable ({exc.__class__.__name__}) -> using simulated in-memory IPFS")
        return SimulatedIPFS()


async def run_one(binary: Path, ipfs, pdf_bytes: bytes) -> tuple[dict, bool]:
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
        puzzle_cid = await ipfs.add_bytes(puzzle_bytes)
        payload_cid = await ipfs.add_bytes(payload_bytes)
        shard_cids = [await ipfs.add_json(s) for s in encrypted_shards]
        timings["ipfs_upload_sec"] = time.perf_counter() - t0
        total_ipfs_bytes = (
            len(puzzle_bytes) + len(payload_bytes)
            + sum(len(json.dumps(s).encode()) for s in encrypted_shards)
        )

        t0 = time.perf_counter()
        fetched_puzzle_bytes = await ipfs.cat(puzzle_cid)
        fetched_payload_bytes = await ipfs.cat(payload_cid)
        fetched_shards = [await ipfs.cat_json(cid) for cid in shard_cids[:K]]
        timings["ipfs_fetch_sec"] = time.perf_counter() - t0

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

    return {**timings, "total_ipfs_bytes": total_ipfs_bytes}, correct


FIELDNAMES = [
    "pdf_size_mb", "run_id", "n", "k", "puzzle_time_target_sec", "ipfs_backend",
    "centre_keygen_sec", "puzzle_generation_sec",
    "lock_wall_sec", "lock_parse_sec", "lock_keyderiv_sec", "lock_encrypt_sec", "lock_write_sec",
    "outer_lock_sec", "shamir_split_sec", "centre_encryption_sec",
    "ipfs_upload_sec", "ipfs_fetch_sec",
    "centre_reconstruction_sec", "shamir_combine_sec", "outer_decrypt_sec",
    "solve_wall_sec", "solve_parse_sec", "solve_squaring_sec", "solve_decrypt_sec", "solve_write_sec",
    "cleanup_sec", "total_ipfs_bytes", "wall_clock_total_sec", "reconstruction_correct",
]


async def main() -> None:
    binary = find_vajra_binary()
    ipfs = await get_ipfs_backend()

    print(
        f"Starting Experiment 08: End-to-End Performance "
        f"(sizes={PDF_SIZES_MB} MB, n={N}, k={K}, "
        f"puzzle_time={PUZZLE_TIME_SECONDS}s, {REPETITIONS} reps each, "
        f"ipfs={'real' if ipfs.is_real else 'simulated'})"
    )

    rows = []
    for size_mb in PDF_SIZES_MB:
        pdf_bytes = make_pdf_bytes(size_mb)
        print(f"\n-- PDF size {size_mb} MB --")
        for run_id in range(1, REPETITIONS + 1):
            t_wall0 = time.perf_counter()
            timings, correct = await run_one(binary, ipfs, pdf_bytes)
            wall = time.perf_counter() - t_wall0

            row = {
                "pdf_size_mb": size_mb,
                "run_id": run_id,
                "n": N,
                "k": K,
                "puzzle_time_target_sec": PUZZLE_TIME_SECONDS,
                "ipfs_backend": "real" if ipfs.is_real else "simulated",
                **{key: round(val, 6) for key, val in timings.items() if key != "total_ipfs_bytes"},
                "total_ipfs_bytes": timings["total_ipfs_bytes"],
                "wall_clock_total_sec": round(wall, 6),
                "reconstruction_correct": correct,
            }
            rows.append(row)

            status = "OK" if correct else "MISMATCH"
            squaring = timings.get("solve_squaring_sec")
            squaring_str = f"{squaring:.3f}s" if squaring is not None else "n/a (unpatched binary)"
            print(
                f"  run {run_id}/{REPETITIONS}: total={wall:.3f}s "
                f"(solve_wall={timings['solve_wall_sec']:.3f}s [whole CLI call, grows with size -- expected], "
                f"solve_squaring={squaring_str} [pure RSW -- should stay flat], "
                f"lock_wall={timings['lock_wall_sec']:.3f}s) [{status}]"
            )

    with open(RESULTS_FILE, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=FIELDNAMES, restval="")
        writer.writeheader()
        writer.writerows(rows)

    mismatches = sum(1 for r in rows if not r["reconstruction_correct"])
    print(f"\nExperiment complete: {len(rows)} runs, {mismatches} mismatches. Raw data -> {RESULTS_FILE}")


if __name__ == "__main__":
    asyncio.run(main())