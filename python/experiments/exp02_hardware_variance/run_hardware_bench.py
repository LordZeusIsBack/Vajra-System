import csv
import json
import os.path
from pathlib import Path
import platform
import time
import subprocess

import psutil

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[2]

BINARY_NAME = 'vajra.exe' if platform.system() == 'Windows' else 'vajra'
RUST_BINARY = str(REPO_ROOT / 'rust' / 'target' / 'release' / BINARY_NAME)

PUZZLE_FILE = SCRIPT_DIR / 'puzzle.json'
CSV_FILE = SCRIPT_DIR / 'raw_results.csv'


def solve_puzzle(t_ops):
    subprocess.run(
        [RUST_BINARY, '--solve', str(t_ops)],
        capture_output=True
    )


def get_system_info():
    try:
        rustc_version = subprocess.check_output(['rustc', '--version']).decode().strip()
    except Exception:
        rustc_version = 'Unknown'

    return {
        'Machine': platform.node(),
        'OS': platform.system() + ' ' + platform.release(),
        'CPU': platform.processor(),
        'RAM_GB': round(psutil.virtual_memory().total / (1024 ** 3), 2),
        'Rust Version': rustc_version
    }


def run_hardware_bench(repetition=5):
    if not PUZZLE_FILE.exists():
        print(f'Error: {PUZZLE_FILE} not found. Please copy the reference puzzle to this directory.')
        return []

    if not os.path.exists(RUST_BINARY):
        print(f'Error: Compiled binary not found at {RUST_BINARY}')
        print("Build it with: cargo build --release (inside the rust/ directory)")
        return []

    sys_info = get_system_info()
    results = []

    with open(PUZZLE_FILE) as fp:
        puzzle_data = json.load(fp)
        t_ops = puzzle_data['t_ops']

    for i in range(repetition):
        start_time = time.perf_counter()

        subprocess.run([RUST_BINARY, 'solve'], check=True)

        elapsed_time = time.perf_counter() - start_time

        results.append({
            **sys_info,
            'T_ops': t_ops,
            'Run': i + 1,
            'solve_time_sec': round(elapsed_time, 4),
            'squarings_sec': round(t_ops / elapsed_time, 2) if elapsed_time > 0 else 0
        })

    return results

if __name__ == '__main__':
    print(f"Running hardware benchmark on {platform.node()} ({platform.system()})...")

    experiment_data = run_hardware_bench(10)

    if experiment_data:
        file_exists = CSV_FILE.exists()

        with open(CSV_FILE, 'a', newline='') as fp:
            writer = csv.DictWriter(fp, fieldnames=experiment_data[0].keys())
            if not file_exists:
                writer.writeheader()
            writer.writerows(experiment_data)

        print(f"Recorded {len(experiment_data)} runs to {CSV_FILE}")
