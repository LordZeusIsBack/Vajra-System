import csv
import json
import os.path
import platform
import time
import subprocess

import psutil

RUST_BINARY = r'..\..\..\rust\target\release\vajra.exe'
PUZZLE_FILE = 'puzzle.json'


def solve_puzzle(t_ops):
    subprocess.run(
        ['../../../rust/target/release/vajra.exe', '--solve', str(t_ops)],
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
    if not os.path.exists(PUZZLE_FILE):
        print(f'Error: {PUZZLE_FILE} not found. Please copy the reference puzzle to this directory.')
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
    print(f"Running hardware benchmark on {platform.node()}...")

    experiment_data = run_hardware_bench(10)

    if experiment_data:
        csv_file = 'raw_results.csv'
        file_exists = os.path.exists(csv_file)

        with open(csv_file, 'a', newline='') as fp:
            writer = csv.DictWriter(fp, fieldnames=experiment_data[0].keys())
            if not file_exists:
                writer.writeheader()
            writer.writerows(experiment_data)

        print(f"Recorded {len(experiment_data)} runs to {csv_file}")
