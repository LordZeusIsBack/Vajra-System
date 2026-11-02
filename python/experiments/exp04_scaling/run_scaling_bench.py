import argparse
import asyncio
import csv
import json
import sys
import time
import tracemalloc
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent))

import common
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config
from centers import EncryptedShard, bulk_generate, decrypt_share_with_privkey
from lock_pipeline import run_vajra_pipeline
from lock_publish import publish_locked_exam
from manifest import verify as verify_manifest
from shamir import reconstruct as shamir_reconstruct

CONFIGURATIONS = [(5, 3), (10, 5), (10, 8), (20, 15), (50, 30), (100, 60)]
MIB = 1024 * 1024


async def one_run(n: int, k: int, registry, keypairs, ipfs, pdf_payload: bytes) -> dict:
    stages: dict = {}
    tracemalloc.start()

    t0 = time.perf_counter()
    (puzzle_params, double_locked, encrypted_shards, nonce_hex,
     drand_info, centers_meta) = run_vajra_pipeline(
        pdf_bytes=pdf_payload, exam_start_seconds=1, n=n, k=k,
        centers=registry, timings=stages,
    )
    lock_total = time.perf_counter() - t0

    pub: dict = {}
    t0 = time.perf_counter()
    manifest_cid, _ = await publish_locked_exam(
        ipfs, n=n, k=k, puzzle_params=puzzle_params, double_locked=double_locked,
        encrypted_shards=encrypted_shards, nonce_hex=nonce_hex, drand_info=drand_info,
        centers_meta=centers_meta, stats=pub,
    )
    publish_sec = time.perf_counter() - t0

    # Fetch what k centers and the coordinator need.
    t0 = time.perf_counter()
    manifest_bytes = await ipfs.cat(manifest_cid, node_index=0)
    manifest = json.loads(manifest_bytes)
    if not verify_manifest(manifest):
        raise RuntimeError("fetched manifest failed HMAC verification")
    payload = await ipfs.cat(manifest["payload_cid"], node_index=0)
    shard_blobs = []
    for i in range(k):
        entry = manifest["shard_cids"][i]
        shard_blobs.append(await ipfs.cat(entry["cid"], node_index=entry["node_index"]))
    fetch_sec = time.perf_counter() - t0
    bytes_fetched = len(manifest_bytes) + len(payload) + sum(len(b) for b in shard_blobs)

    t0 = time.perf_counter()
    plaintext_shares = [
        decrypt_share_with_privkey(EncryptedShard.from_dict(json.loads(blob)), keypairs[i][1])
        for i, blob in enumerate(shard_blobs)
    ]
    t1 = time.perf_counter()
    data_key = shamir_reconstruct(plaintext_shares, expected_threshold=k)
    t2 = time.perf_counter()
    AESGCM(data_key).decrypt(bytes.fromhex(manifest["nonce"]), payload,
                             associated_data=bytes.fromhex(drand_info["aad_hex"]))
    t3 = time.perf_counter()

    _, python_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    calibration = stages.get("generate_calibration_sec", 0.0)
    return {
        "lock_pipeline_sec": lock_total,
        "lock_pipeline_excl_calibration_sec": lock_total - calibration,
        **{k_: v for k_, v in stages.items() if k_.endswith("_sec")},
        "publish_sec": publish_sec,
        "objects_created": pub["objects_created"],
        "objects_per_node": json.dumps(pub["objects_per_node"]),
        "bytes_uploaded_mb": pub["bytes_uploaded"] / MIB,
        "fetch_sec": fetch_sec,
        "bytes_fetched_mb": bytes_fetched / MIB,
        "center_decrypt_sec": t1 - t0,
        "shamir_combine_sec": t2 - t1,
        "outer_decrypt_sec": t3 - t2,
        "reconstruction_sec": t3 - t0,
        "python_peak_mb": python_peak / MIB,
        "generate_peak_rss_mb": stages.get("generate_peak_rss_bytes", 0) / MIB,
        "lock_peak_rss_mb": stages.get("lock_peak_rss_bytes", 0) / MIB,
        "child_memory_method": stages.get("child_memory_method", ""),
    }


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    common.add_ipfs_arguments(ap)
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--nodes", type=int, default=3, help="shard nodes (default 3, as in the service)")
    ap.add_argument("--configs", default=",".join(f"{n}:{k}" for n, k in CONFIGURATIONS),
                    help="comma-separated n:k pairs")
    ap.add_argument("--out", type=Path, default=SCRIPT_DIR / "raw_results_stages.csv")
    args = ap.parse_args()

    config.settings.vajra_binary = str(common.find_vajra_binary())
    configs = [tuple(int(x) for x in pair.split(":")) for pair in args.configs.split(",")]
    ipfs = await common.make_backend(args, node_count=args.nodes)
    host = common.host_info()
    print(f"Backend: {ipfs.describe()}  host: {host['CPU_model'] or host['CPU']}")

    max_n = max(n for n, _ in configs)
    registry_all, keypairs_all = bulk_generate(max_n)
    pdf_payload = b"%PDF-1.4\n" + (b"\x00" * (MIB - 9))

    rows = []
    for n, k in configs:
        print(f"Testing n={n}, k={k}")
        for run in range(1, args.reps + 1):
            metrics = await one_run(n, k, registry_all[:n], keypairs_all[:n], ipfs, pdf_payload)
            rows.append({"n": n, "k": k, "run": run, **ipfs.describe(),
                         **{key: (round(v, 6) if isinstance(v, float) else v)
                            for key, v in metrics.items()},
                         "cpu_model": host["CPU_model"]})
            print(f"  run {run}: lock {metrics['lock_pipeline_sec']:.3f}s "
                  f"(calibration {metrics.get('generate_calibration_sec', 0):.3f}s), "
                  f"objects {metrics['objects_created']}, recon {metrics['reconstruction_sec']*1000:.1f} ms")

    fields: list[str] = []
    for row in rows:
        fields += [key for key in row if key not in fields]
    with open(args.out, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fields, restval="")
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nExperiment complete. Raw data saved to {args.out}")


if __name__ == "__main__":
    asyncio.run(main())
