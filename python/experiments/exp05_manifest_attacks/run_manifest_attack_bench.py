import csv
from copy import deepcopy
import os
import sys
from pathlib import Path
import secrets

os.environ.setdefault('MANIFEST_HMAC_SECRET', secrets.token_hex(32))

SCRIPT_DIR = Path(__file__).resolve().parent
PYTHON_DIR = SCRIPT_DIR.parents[1]
sys.path.insert(0, str(PYTHON_DIR))

from centers import bulk_generate, generate_keypair
from config import settings
from drand_client import publish_time, round_at_or_after
from manifest import build_and_sign
from manifest import verify as verify_manifest

N = 10
K = 8
REPETITIONS = 10

RESULTS_FILE = SCRIPT_DIR / 'raw_results.csv'

def build_reference_manifest():
    registry, privkeys = bulk_generate(N, id_prefix='CENTER')

    chain_hash = settings.drand_chain_hash
    target_round = round_at_or_after(
        2000000000,
        settings.drand_genesis,
        settings.drand_period
    )
    pub_time = publish_time(target_round, settings.drand_genesis, settings.drand_period)

    shard_cids = [
        {"cid": f"bafy_shard_{i:03d}_{secrets.token_hex(4)}", "node_index": i % 3} for i in range(N)
    ]
    centers_meta = [
        {"index": i, "id": r.id, "pubkey": r.pubkey} for i, r in enumerate(registry)
    ]

    return build_and_sign(
        n=N,
        k=K,
        puzzle_cid=f"bafy_puzzle_{secrets.token_hex(4)}",
        payload_cid=f"bafy_payload_{secrets.token_hex(4)}",
        nonce_hex=secrets.token_bytes(12).hex(),
        shard_cids=shard_cids,
        centers=centers_meta,
        drand={
            "chain_hash": chain_hash,
            "target_round": target_round,
            "publish_time": pub_time,
        },
    )

def attack_none(manifest):
    return deepcopy(manifest)

def attack_target_round(manifest):
    tampered = deepcopy(manifest)
    tampered['drand']['target_round'] += 1
    return tampered

def attack_payload_cid(manifest):
    tampered = deepcopy(manifest)
    tampered["payload_cid"] = "bafy_ATTACKER_SWAPPED_PAYLOAD"
    return tampered

def attack_center_pubkey(manifest):
    tampered = deepcopy(manifest)
    attacker_privkey, attacker_pubkey = generate_keypair()
    tampered["centers"][0]["pubkey"] = attacker_pubkey
    return tampered

def attack_shard_cid(manifest):
    tampered = deepcopy(manifest)
    tampered["shard_cids"][0]["cid"] = "bafy_ATTACKER_SWAPPED_SHARD"
    return tampered

ATTACKS = [
    ("none (control)",          "n/a",                 attack_none,          "Accept"),
    ("target_round tamper",     "drand.target_round",  attack_target_round,  "Reject"),
    ("payload_cid tamper",      "payload_cid",         attack_payload_cid,   "Reject"),
    ("center_pubkey tamper",    "centers[0].pubkey",   attack_center_pubkey, "Reject"),
    ("shard_cid tamper",        "shard_cids[0].cid",   attack_shard_cid,     "Reject"),
]

def run_experiment():
    print(
        f"Starting Experiment 05: Manifest Integrity Attacks "
        f"({len(ATTACKS)} attacks x {REPETITIONS} repetitions)"
    )

    results = []
    for rep in range(1, REPETITIONS + 1):
        reference = build_reference_manifest()

        for attack_name, modified_field, attack_fn, expected in ATTACKS:
            tampered = attack_fn(reference)
            accepted = verify_manifest(tampered)
            actual = 'Accept' if accepted else 'Reject'

            results.append(
                {
                    "repetition": rep,
                    "attack": attack_name,
                    "modified_field": modified_field,
                    "expected_result": expected,
                    "actual_result": actual,
                    "passed": actual == expected,
                }
            )

        print(f"Repetition {rep}/{REPETITIONS} done")

    with open(RESULTS_FILE, 'w', newline='', encoding='utf-8') as fp:
        writer = csv.DictWriter(fp, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    total = len(results)
    passed = sum(1 for r in results if r['passed'])
    print(f"Experiment complete: {passed}/{total} checks matched expectation.")


if __name__ == '__main__':
    run_experiment()
