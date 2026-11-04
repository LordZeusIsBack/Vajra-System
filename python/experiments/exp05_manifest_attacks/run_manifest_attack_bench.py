import argparse
import asyncio
import csv
import json
import secrets
import sys
import tempfile
from copy import deepcopy
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent))

import common

import config
from centers import bulk_generate, generate_keypair
from config import settings
from drand_client import publish_time, round_at_or_after
from lock_pipeline import run_vajra_pipeline
from lock_publish import publish_locked_exam
from manifest import _canonical, _sign, build_and_sign
from manifest import verify as verify_manifest
from reconstruct import ManifestVerificationError, ReconstructError
from vajra_center import decrypt_my_share
from vajra_coordinator import coordinate

N = 10
K = 8


def build_reference_manifest():
    registry, _ = bulk_generate(N, id_prefix="CENTER")
    target_round = round_at_or_after(2000000000, settings.drand_genesis, settings.drand_period)
    pub_time = publish_time(target_round, settings.drand_genesis, settings.drand_period)
    return build_and_sign(
        n=N, k=K,
        puzzle_cid=f"bafy_puzzle_{secrets.token_hex(4)}",
        payload_cid=f"bafy_payload_{secrets.token_hex(4)}",
        nonce_hex=secrets.token_bytes(12).hex(),
        shard_cids=[{"cid": f"bafy_shard_{i:03d}_{secrets.token_hex(4)}", "node_index": i % 3}
                    for i in range(N)],
        centers=[{"index": i, "id": r.id, "pubkey": r.pubkey} for i, r in enumerate(registry)],
        drand={"chain_hash": settings.drand_chain_hash, "target_round": target_round,
               "publish_time": pub_time},
    )


def _with(fn):
    def apply(m):
        t = deepcopy(m)
        fn(t)
        return t
    return apply


VERIFY_ONLY_ATTACKS = [
    ("none (control)", "n/a", _with(lambda m: None), "Accept"),
    ("target_round tamper", "drand.target_round",
     _with(lambda m: m["drand"].__setitem__("target_round", m["drand"]["target_round"] + 1)), "Reject"),
    ("payload_cid tamper", "payload_cid",
     _with(lambda m: m.__setitem__("payload_cid", "bafy_ATTACKER_SWAPPED_PAYLOAD")), "Reject"),
    ("center_pubkey tamper", "centers[0].pubkey",
     _with(lambda m: m["centers"][0].__setitem__("pubkey", generate_keypair()[1])), "Reject"),
    ("shard_cid tamper", "shard_cids[0].cid",
     _with(lambda m: m["shard_cids"][0].__setitem__("cid", "bafy_ATTACKER_SWAPPED_SHARD")), "Reject"),
]


def run_verify_only(reps: int, out: Path) -> None:
    results = []
    for rep in range(1, reps + 1):
        reference = build_reference_manifest()
        for name, field, fn, expected in VERIFY_ONLY_ATTACKS:
            actual = "Accept" if verify_manifest(fn(reference)) else "Reject"
            results.append({"repetition": rep, "attack": name, "modified_field": field,
                            "expected_result": expected, "actual_result": actual,
                            "passed": actual == expected})
    _write(results, out)


def resign(m: dict) -> dict:
    """What any holder of the HMAC key can do: sign an arbitrary manifest."""
    body = {k: v for k, v in m.items() if k != "hmac"}
    body["hmac"] = _sign(_canonical(body))
    return body


def keep_hmac(field: str, mutate):
    return (f"{field} changed, original HMAC kept", field, False, _with(mutate),
            "Rejected: HMAC", K)


def resigned(field: str, mutate, expected: str, shares: int = K):
    return (f"{field} changed and re-signed", field, True,
            lambda m: resign(_with(mutate)(m)), expected, shares)


def _new_round(m):
    m["drand"]["target_round"] += 1


def _set(path: list, value):
    def mutate(m):
        obj = m
        for key in path[:-1]:
            obj = obj[key]
        obj[path[-1]] = value(obj[path[-1]]) if callable(value) else value
    return mutate


FULL_CASES = [
    ("control (unmodified)", "n/a", False, lambda m: deepcopy(m), "Accepted (original paper)", K),
    keep_hmac("drand.target_round", _new_round),
    keep_hmac("drand.publish_time", _set(["drand", "publish_time"], lambda v: v - 86400)),
    keep_hmac("drand.chain_hash", _set(["drand", "chain_hash"], "00" * 32)),
    keep_hmac("payload_cid", _set(["payload_cid"], "sim-attacker-payload")),
    keep_hmac("puzzle_cid", _set(["puzzle_cid"], "sim-attacker-puzzle")),
    keep_hmac("nonce", _set(["nonce"], lambda v: secrets.token_bytes(12).hex())),
    keep_hmac("n", _set(["n"], lambda v: v + 1)),
    keep_hmac("k", _set(["k"], lambda v: v - 1)),
    keep_hmac("exam_id", _set(["exam_id"], "00000000-0000-0000-0000-000000000000")),
    keep_hmac("version", _set(["version"], "9.9")),
    keep_hmac("locked_at", _set(["locked_at"], "2000-01-01T00:00:00+00:00")),
    keep_hmac("centers[0].id", _set(["centers", 0, "id"], "ATTACKER")),
    keep_hmac("centers[0].pubkey", _set(["centers", 0, "pubkey"], lambda v: generate_keypair()[1])),
    keep_hmac("shard_cids[0].cid", _set(["shard_cids", 0, "cid"], "sim-attacker-shard")),
    keep_hmac("shard_cids[0].node_index", _set(["shard_cids", 0, "node_index"], lambda v: (v + 1) % 3)),
    ("hmac removed", "hmac", False,
     lambda m: {k: v for k, v in m.items() if k != "hmac"}, "Rejected: HMAC", K),
    resigned("drand.target_round", _new_round, "Rejected: outer AES-GCM tag"),
    resigned("drand.chain_hash", _set(["drand", "chain_hash"], "00" * 32), "Rejected: outer AES-GCM tag"),
    resigned("nonce", _set(["nonce"], lambda v: secrets.token_bytes(12).hex()), "Rejected: outer AES-GCM tag"),
    resigned("drand.publish_time", _set(["drand", "publish_time"], lambda v: v - 86400),
             "Accepted (original paper)"),
    resigned("k", _set(["k"], lambda v: v - 1), "Rejected: outer AES-GCM tag", shares=K - 1),
    resigned("n", _set(["n"], lambda v: v + 1), "Rejected: manifest shape"),
]


def classify(exc: Exception) -> str:
    if isinstance(exc, ManifestVerificationError):
        return "Rejected: HMAC"
    msg = str(exc)
    for needle, label in (
        ("missing required fields", "Rejected: manifest shape"),
        ("illegal (n=", "Rejected: manifest shape"),
        ("count", "Rejected: manifest shape"),
        ("Outer AES-GCM", "Rejected: outer AES-GCM tag"),
        ("vajra solve", "Rejected: inner AES-GCM tag"),
        ("Cannot fetch", "Rejected: object unavailable"),
        ("Failed to fetch", "Rejected: object unavailable"),
        ("not in the manifest", "Rejected: center ID"),
        ("claims center_id", "Rejected: center ID"),
        ("Cannot decrypt shard", "Rejected: shard AEAD tag"),
        ("Need ≥", "Rejected: threshold"),
    ):
        if needle in msg:
            return label
    return f"Rejected: other ({msg[:80]})"


async def run_case(manifest: dict, ipfs, keyfiles: list[Path], shares_used: int,
                   original_pdf: bytes, vajra: Path, workdir: Path) -> tuple[str, str, bool]:
    """Return (outcome, stopped_at, verify_result)."""
    verified = verify_manifest(manifest)
    cid = await ipfs.add_json(manifest, "manifest.json", node_index=0)
    share_files = []
    for i in range(shares_used):
        out = workdir / f"share_{i}.json"
        try:
            await decrypt_my_share(cid, keyfiles[i], out, ipfs)
        except (ManifestVerificationError, ReconstructError) as exc:
            return classify(exc), f"center {i}", verified
        share_files.append(str(out))
    try:
        pdf = await coordinate(cid, share_files, vajra, ipfs, skip_drand_check=True)
    except (ManifestVerificationError, ReconstructError) as exc:
        return classify(exc), "coordinator", verified
    if pdf == original_pdf:
        return "Accepted (original paper)", "completed", verified
    return "Forged paper produced", "completed", verified


async def lock_paper(pdf: bytes, registry, ipfs) -> tuple[str, dict]:
    out = run_vajra_pipeline(pdf, 1, N, K, registry)
    puzzle_params, double_locked, shards, nonce_hex, drand_info, centers_meta = out
    return await publish_locked_exam(
        ipfs, n=N, k=K, puzzle_params=puzzle_params, double_locked=double_locked,
        encrypted_shards=shards, nonce_hex=nonce_hex, drand_info=drand_info,
        centers_meta=centers_meta,
    )


async def run_full(reps: int, out: Path) -> None:
    vajra = common.find_vajra_binary()
    config.settings.vajra_binary = str(vajra)
    results = []
    for rep in range(1, reps + 1):
        ipfs = common.SimulatedIPFS(node_count=3)
        registry, privkeys = bulk_generate(N, id_prefix="CENTER")
        with tempfile.TemporaryDirectory(prefix="vajra_exp05_") as tmp:
            work = Path(tmp)
            keyfiles = []
            for cid_, priv in privkeys:
                f = work / f"{cid_}.json"
                f.write_text(json.dumps({"id": cid_, "privkey": priv}))
                keyfiles.append(f)

            original_pdf = b"%PDF-1.4\n%original exam\n" + secrets.token_bytes(512)
            _, reference = await lock_paper(original_pdf, registry, ipfs)

            attacker_payload = await ipfs.add_bytes(secrets.token_bytes(2048), node_index=0)
            forged_pdf = b"%PDF-1.4\n%FORGED exam\n" + secrets.token_bytes(512)
            _, forged = await lock_paper(forged_pdf, registry, ipfs)

            cases = list(FULL_CASES) + [
                resigned("payload_cid", _set(["payload_cid"], attacker_payload),
                         "Rejected: outer AES-GCM tag"),
                ("full substitution, re-signed", "all object references", True,
                 lambda m: deepcopy(forged), "Forged paper produced", K),
            ]
            for name, field, is_resigned, make, expected, shares in cases:
                case_dir = work / f"case_{abs(hash(name))}"
                case_dir.mkdir()
                outcome, stopped_at, verified = await run_case(
                    make(reference), ipfs, keyfiles, shares, original_pdf, vajra, case_dir,
                )
                results.append({
                    "repetition": rep, "case": name, "modified_field": field,
                    "resigned_with_hmac_key": is_resigned, "shares_submitted": shares,
                    "hmac_verify_accepts": verified, "expected_result": expected,
                    "actual_result": outcome, "stopped_at": stopped_at,
                    "passed": outcome == expected,
                })
        print(f"Repetition {rep}/{reps} done")
    _write(results, out)


def _write(results: list[dict], out: Path) -> None:
    with open(out, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)
    passed = sum(1 for r in results if r["passed"])
    print(f"Experiment complete: {passed}/{len(results)} outcomes matched expectation → {out}")
    for r in results:
        if not r["passed"]:
            print(f"  MISMATCH: {r}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["full", "verify-only"], default="full")
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.mode == "verify-only":
        run_verify_only(args.reps, args.out or SCRIPT_DIR / "raw_results.csv")
    else:
        asyncio.run(run_full(args.reps, args.out or SCRIPT_DIR / "raw_results_extended.csv"))


if __name__ == "__main__":
    main()
