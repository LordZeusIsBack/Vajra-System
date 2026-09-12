import csv
import json
import os
import secrets
import time
import tracemalloc
from pathlib import Path
import subprocess
import sys
import tempfile

script_dir = Path(__file__).resolve().parent
python_dir = script_dir.parent.parent
repo_root = python_dir.parent

os.environ['MANIFEST_HMAC_SECRET'] = secrets.token_hex(32)

vajra_exe = repo_root / "rust" / "target" / "release" / "vajra.exe"
os.environ["VAJRA_BIN"] = str(vajra_exe)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from lock_pipeline import run_vajra_pipeline
from centers import CenterRegistration, EncryptedShard, decrypt_share_with_privkey
from shamir import reconstruct as shamir_reconstruct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_mock_centers(n: int) -> list[dict]:
    keys = []

    # Resolve the absolute path to the main python/ directory
    python_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    keygen_script = os.path.join(python_dir, 'vajra_keygen.py')

    # Force UTF-8 encoding INSIDE the subprocess
    custom_env = os.environ.copy()
    custom_env["PYTHONIOENCODING"] = "utf-8"

    with tempfile.TemporaryDirectory() as tmpdir:
        print(f'Generating {n} center keypairs for scaling test')

        try:
            subprocess.run(
                [
                    sys.executable, keygen_script, 'bulk',
                    '--n', str(n),
                    '--out-dir', tmpdir,
                    '--force'
                ],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=python_dir,
                env=custom_env  # Pass the modified environment here
            )
        except subprocess.CalledProcessError as e:
            print(f"Error running vajra_keygen.py (Exit {e.returncode})")
            print(f"STDOUT:\n{e.stdout}")
            print(f"STDERR:\n{e.stderr}")
            sys.exit(1)

        for key_file in Path(tmpdir).glob('*.json'):
            if key_file.name == 'centers.json':
                continue

            with open(key_file, encoding="utf-8") as fp:
                keys.append(json.load(fp))

    keys.sort(key=lambda k: k.get('id'))
    return keys

def run_scaling_experiment():
    configurations = [
        {"n": 5, "k": 3},
        {"n": 10, "k": 5},
        {"n": 10, "k": 8},
        {"n": 20, "k": 15},
        {"n": 50, "k": 30},
        {"n": 100, "k": 60}
    ]

    repetitions = 10
    results = []

    max_n = max(cfg["n"] for cfg in configurations)
    all_keys = generate_mock_centers(max_n)

    pdf_payload = b"%PDF-1.4\n" + (b"\x00" * (1024 * 1024 - 9))

    for config in configurations:
        n = config.get('n')
        k = config.get('k')
        print(f'Testing configuration with n={n} and k={k}')

        active_keys = all_keys[:n]
        centers = [
            CenterRegistration(id=k_dict['id'], pubkey=k_dict['pubkey'])
            for k_dict in active_keys
        ]

        for run in range(repetitions):
            tracemalloc.start()

            start_gen = time.perf_counter()

            puzzle_params, double_locked, encrypted_shards, nonce_hex, drand_info, centers_meta = run_vajra_pipeline(
                pdf_bytes=pdf_payload,
                exam_start_seconds=1,
                n=n,
                k=k,
                centers=centers
            )

            gen_time = time.perf_counter() - start_gen

            start_recon = time.perf_counter()

            plaintext_shares = []
            for i in range(k):
                enc_shard = EncryptedShard.from_dict(encrypted_shards[i])
                privkey_hex = active_keys[i]['privkey']
                share = decrypt_share_with_privkey(enc_shard, privkey_hex)
                plaintext_shares.append(share)

            data_key = shamir_reconstruct(plaintext_shares, expected_threshold=k)

            aad_bytes = bytes.fromhex(drand_info["aad_hex"])
            nonce = bytes.fromhex(nonce_hex)
            locked_bytes = AESGCM(data_key).decrypt(nonce, double_locked, associated_data=aad_bytes)

            recon_time = time.perf_counter() - start_recon

            current_mem, peak_mem = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            shards_bytes = sum(len(json.dumps(s).encode('utf-8')) for s in encrypted_shards)
            data_transferred = len(double_locked) + shards_bytes + len(json.dumps(puzzle_params).encode('utf-8'))

            results.append({
                "n": n,
                "k": k,
                "run": run + 1,
                "share_gen_encryption_time_sec": round(gen_time, 4),
                "reconstruction_time_sec": round(recon_time, 4),
                "peak_memory_mb": round(peak_mem / (1024 * 1024), 2),
                "data_transferred_mb": round(data_transferred / (1024 * 1024), 2),
                "ipfs_objects": n + 2  # n shards + 1 payload + 1 puzzle[cite: 3]
            })

    csv_file = Path(__file__).parent / "raw_results.csv"
    with open(csv_file, mode='w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print(f"\nExperiment complete. Raw data saved to {csv_file}")

if __name__ == "__main__":
    run_scaling_experiment()
