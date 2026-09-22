import csv
import secrets
import sys
from time import perf_counter
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCRIPT_DIR = Path(__file__).resolve().parent
PYTHON_DIR = SCRIPT_DIR.parents[1]
sys.path.insert(0, str(PYTHON_DIR))

from centers import CentersError, bulk_generate, decrypt_share_with_privkey, encrypt_share_for_center
from shamir import reconstruct as shamir_reconstruct
from shamir import split as shamir_split


N = 10
K_VALUES = [3, 5, 8, 10]
REPETITIONS = 10

AAD = b"vajra-exp06-centre-compromise"
PAYLOAD = b"stand-in for the double-locked exam payload (locked.json bytes)"

RESULTS_FILE = SCRIPT_DIR / 'raw_results.csv'


def build_locked_exam(k: int) -> dict:
    """Create a fresh encrypted k-of-N fixture for compromise attempts."""
    registry, keypairs = bulk_generate(N, id_prefix='CENTER')

    data_key = secrets.token_bytes(32)
    shares = shamir_split(data_key, N, k)
    encrypted_shards = [
        encrypt_share_for_center(share, registry[i].pubkey) for i, share in enumerate(shares)
    ]

    nonce = secrets.token_bytes(12)
    double_locked = AESGCM(data_key).encrypt(nonce, PAYLOAD, associated_data=AAD)

    return {
        "keypairs": keypairs,
        "encrypted_shards": encrypted_shards,
        "nonce": nonce,
        "double_locked": double_locked
    }


def attempt_decrypt(instance: dict, compromised_indices: list[int]) -> tuple[bool, float]:
    """Try to decrypt a fixture with selected centers' private keys.

    Returns the decryption outcome and elapsed seconds. Center decryption,
    reconstruction, and authentication failures are reported as unsuccessful.
    """
    start= perf_counter()

    recovered_shares = []
    for i in compromised_indices:
        _, privkey_hex = instance["keypairs"][i]
        try:
            recovered_shares.append(
                decrypt_share_with_privkey(instance["encrypted_shards"][i], privkey_hex)
            )
        except CentersError: pass

    decrypted_ok = False
    if recovered_shares:
        try:
            candidate_key = shamir_reconstruct(recovered_shares)
            AESGCM(candidate_key).decrypt(
                instance["nonce"], instance['double_locked'], associated_data=AAD
            )
            decrypted_ok = True
        except Exception: decrypted_ok = False

    elapsed = perf_counter() - start
    return decrypted_ok, elapsed


def run_experiment():
    """Measure decryption outcomes across thresholds and compromise levels."""
    print(
        f"Starting Experiment 06: Centre Compromise "
        f"(n={N}, thresholds={K_VALUES}, {REPETITIONS} reps each)"
    )

    rng = secrets.SystemRandom()
    results = []

    for k in K_VALUES:
        for rep in range(1, REPETITIONS + 1):
            instance = build_locked_exam(k)

            for num_compromised in range(0, N + 1):
                compromised = rng.sample(range(N), num_compromised)
                decrypted_ok, elapsed = attempt_decrypt(instance, compromised)

                expected = "Decrypt" if num_compromised >= k else "Fail"
                actual = "Decrypt" if decrypted_ok else "Fail"

                results.append(
                    {
                        "n": N,
                        "k": k,
                        "repetition": rep,
                        "centers_compromised": num_compromised,
                        "expected_result": expected,
                        "actual_result": actual,
                        "matches_expected": expected == actual,
                        "time_seconds": elapsed,
                    }
                )

        print(f"k={k} done ({REPETITIONS} repetitions x {N + 1} compromise levels)")

    with open(RESULTS_FILE, 'w', newline='', encoding='utf-8') as fp:
        writer = csv.DictWriter(fp, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    total = len(results)
    matched = sum(1 for r in results if r["matches_expected"])
    print(f"Experiment complete: {matched}/{total} outcomes matched the k-of-n threshold prediction.")


if __name__ == '__main__':
    run_experiment()
