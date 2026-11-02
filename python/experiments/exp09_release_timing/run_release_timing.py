from __future__ import annotations

import argparse
import asyncio
import csv
import json
import secrets
import sys
import tempfile
import time
from pathlib import Path

import httpx

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent))

import common

import config
from centers import bulk_generate
from config import settings
from lock_pipeline import run_vajra_pipeline
from lock_publish import publish_locked_exam
from reconstruct import ReconstructError
from vajra_center import decrypt_my_share
from vajra_coordinator import coordinate

N, K = 10, 8


def mock_relays_for(round_num: int) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"round": round_num, "randomness": "ee" * 32,
                                         "signature": "aa" * 48})
    return httpx.MockTransport(handler)


async def lock_in_process(pdf: bytes, lock_seconds: int, registry, ipfs) -> dict:
    stages: dict = {}
    t_start = time.time()
    out = run_vajra_pipeline(pdf, lock_seconds, N, K, registry, timings=stages)
    puzzle_params, double_locked, shards, nonce_hex, drand_info, centers_meta = out
    manifest_cid, manifest = await publish_locked_exam(
        ipfs, n=N, k=K, puzzle_params=puzzle_params, double_locked=double_locked,
        encrypted_shards=shards, nonce_hex=nonce_hex, drand_info=drand_info,
        centers_meta=centers_meta,
    )
    return {"manifest_cid": manifest_cid, "manifest": manifest, "lock_started": t_start,
            "scheduled_start": float(stages["exam_start_unix"]),
            "scheduled_start_source": "pipeline exam_start_unix",
            "t_ops": puzzle_params["t_ops"],
            "ref_squarings_per_sec": puzzle_params["ref_squarings_per_sec"]}


async def lock_via_service(pdf: bytes, lock_seconds: int, url: str, ipfs) -> dict:
    t_start = time.time()
    async with httpx.AsyncClient(timeout=600) as client:
        resp = await client.post(
            f"{url.rstrip('/')}/api/v1/lock",
            files={"file": ("exam.pdf", pdf, "application/pdf")},
            data={"exam_start_seconds": str(lock_seconds), "n": str(N), "k": str(K)},
        )
    resp.raise_for_status()
    body = resp.json()
    puzzle = await ipfs.cat_json(body["manifest"]["puzzle_cid"], node_index=0)
    return {"manifest_cid": body["manifest_cid"], "manifest": body["manifest"],
            "lock_started": t_start, "scheduled_start": float(int(t_start) + lock_seconds),
            "scheduled_start_source": "request time + L (service computes it ≤1 s later)",
            "t_ops": puzzle["t_ops"], "ref_squarings_per_sec": puzzle["ref_squarings_per_sec"]}


def keyfiles_from_dir(directory: Path) -> dict[str, Path]:
    out = {}
    for f in directory.glob("*.json"):
        try:
            data = json.loads(f.read_text())
        except json.JSONDecodeError:
            continue
        if "id" in data and "privkey" in data:
            out[data["id"]] = f
    return out


async def run_once(mode: str, args, ipfs, vajra: Path, rep: int) -> dict:
    with tempfile.TemporaryDirectory(prefix=f"vajra_exp09_{mode}_") as tmp:
        work = Path(tmp)
        pdf = b"%PDF-1.4\n%vajra exp09\n" + secrets.token_bytes(args.pdf_kib * 1024)

        if args.service_url:
            lock = await lock_via_service(pdf, args.lock_seconds, args.service_url, ipfs)
            keyfiles = keyfiles_from_dir(args.keys_dir)
        else:
            registry, privkeys = bulk_generate(N, id_prefix="CENTER")
            lock = await lock_in_process(pdf, args.lock_seconds, registry, ipfs)
            keyfiles = {}
            for cid_, priv in privkeys:
                f = work / f"{cid_}.json"
                f.write_text(json.dumps({"id": cid_, "privkey": priv}))
                keyfiles[cid_] = f
        locked_at = time.time()
        manifest, manifest_cid = lock["manifest"], lock["manifest_cid"]
        target_round = int(manifest["drand"]["target_round"])
        beacon_publish = settings.drand_genesis + (target_round - 1) * settings.drand_period
        gate_time = settings.drand_genesis + target_round * settings.drand_period
        print(f"  [{mode} #{rep}] locked: t_ops={lock['t_ops']:,}, round {target_round}, "
              f"start in {lock['scheduled_start'] - locked_at:.1f}s")

        await asyncio.sleep(max(0.0, gate_time - time.time() + 0.05))
        share_files = []
        centers_started = time.time()
        for c in manifest["centers"][:K]:
            out = work / f"share_{c['index']}.json"
            await decrypt_my_share(manifest_cid, keyfiles[c["id"]], out, ipfs)
            share_files.append(str(out))
        centers_done = time.time()

        marks: dict = {}
        attempts = 0
        while True:
            attempts += 1
            transport = (common.relay_transport() if args.drand == "live"
                         else mock_relays_for(target_round))
            try:
                with common.patched_httpx_transport(transport):
                    recovered = await coordinate(manifest_cid, share_files, vajra, ipfs,
                                                 stage_times=marks)
                break
            except ReconstructError as exc:
                if "drand" not in str(exc) or attempts >= args.gate_retries:
                    raise
                await asyncio.sleep(2.0)

        s = lock["scheduled_start"]
        return {
            "mode": mode, "rep": rep, "lock_seconds": args.lock_seconds,
            **ipfs.describe(), "drand_backend": args.drand,
            "via_service": bool(args.service_url),
            "t_ops": lock["t_ops"], "ref_squarings_per_sec": lock["ref_squarings_per_sec"],
            "target_round": target_round,
            "lock_started": round(lock["lock_started"], 3),
            "locked_at": round(locked_at, 3),
            "scheduled_start": s,
            "scheduled_start_source": lock["scheduled_start_source"],
            "beacon_publish": beacon_publish,
            "gate_time": gate_time,
            "centers_done": round(centers_done, 3),
            "gate_passed": round(marks.get("gate_passed", 0), 3),
            "solve_started": round(marks["solve_started"], 3),
            "pdf_ready": round(marks["pdf_ready"], 3),
            "gate_attempts": attempts,
            "centers_sec": round(centers_done - centers_started, 3),
            "solve_sec": round(marks["pdf_ready"] - marks["solve_started"], 3),
            "gate_minus_start": round(gate_time - s, 3),
            "pdf_ready_minus_start": round(marks["pdf_ready"] - s, 3),
            "pdf_ready_minus_beacon": round(marks["pdf_ready"] - beacon_publish, 3),
            "pdf_ready_over_lock": round((marks["pdf_ready"] - s) / args.lock_seconds, 4),
            "pdf_identical": recovered == pdf,
        }


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    common.add_ipfs_arguments(ap)
    ap.add_argument("--lock-seconds", type=int, default=300)
    ap.add_argument("--reps", type=int, default=1)
    ap.add_argument("--drand", choices=["clock", "live"], default="clock")
    ap.add_argument("--gate-retries", type=int, default=30,
                    help="relay attempts (2 s apart) before giving up (live mode)")
    ap.add_argument("--pdf-kib", type=int, default=1024)
    ap.add_argument("--service-url", default="", help="lock through a running Source Vault")
    ap.add_argument("--keys-dir", type=Path, default=None,
                    help="with --service-url: directory of the service's center keypair files")
    ap.add_argument("--out", type=Path, default=SCRIPT_DIR / "raw_results.csv")
    args = ap.parse_args()
    if args.service_url and (args.ipfs != "real" or args.keys_dir is None):
        raise SystemExit("--service-url needs --ipfs real (the service's nodes) and --keys-dir")
    if args.service_url and args.lock_seconds < 60:
        raise SystemExit("the service requires exam_start_seconds >= 60")

    vajra = common.find_vajra_binary()
    config.settings.vajra_binary = str(vajra)
    ipfs = await common.make_backend(args, node_count=3)
    modes = ["legacy"]
    host = common.host_info()
    print(f"Experiment 09: L={args.lock_seconds}s, modes={modes}, reps={args.reps}, "
          f"ipfs={ipfs.describe()}, drand={args.drand}, host={host['CPU_model'] or host['CPU']}")

    rows = []
    for rep in range(1, args.reps + 1):
        results = [await run_once(m, args, ipfs, vajra, rep) for m in modes]
        for r in results:
            r["cpu_model"] = host["CPU_model"]
            rows.append(r)
            print(f"  [{r['mode']} #{rep}] PDF ready {r['pdf_ready_minus_start']:+.1f}s vs scheduled start "
                  f"({r['pdf_ready_over_lock']:.2f} L), {r['pdf_ready_minus_beacon']:+.1f}s vs beacon; "
                  f"identical={r['pdf_identical']}")

    with open(args.out, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    asyncio.run(main())
