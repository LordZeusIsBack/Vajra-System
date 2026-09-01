import csv
from datetime import datetime, timezone
import platform
import subprocess
import time
from pathlib import Path

TIME_TARGETS = [1, 2, 4, 8, 16]
REPETITIONS = 10

RUST_BINARY_PATH = Path('../../../rust/target/release/vajra.exe')
RESULTS_FILE = Path('results.csv')
DUMMY_EXAM = Path('dummy_exam.txt')


def get_system_metadata() -> dict:
    try:
        commit = subprocess.check_output(
            ['git', 'rev-parse', '--short', 'HEAD'],
            text=True,
            encoding='utf-8',
            errors='replace'
        ).strip()
    except Exception:
        commit = 'unknown'

    return {
        'os': platform.system(),
        'cpu': platform.processor(),
        'commit_hash': commit
    }


def run_experiment():
    if not RUST_BINARY_PATH.exists():
        print(f'Error: Rust binary not found at {RUST_BINARY_PATH}')
        return

    DUMMY_EXAM.write_text("Benchmarking payload.", encoding="utf-8")
    metadata = get_system_metadata()

    with open(RESULTS_FILE, 'a', encoding='utf-8', newline='') as fp:
        fieldnames = [
            "timestamp_utc", "commit_hash", "os", "cpu",
            "target_time_seconds", "run_id", "actual_solve_time_seconds"
        ]
        writer = csv.DictWriter(fp, fieldnames=fieldnames)

        if not RESULTS_FILE.exists():
            writer.writeheader()

        print(f"Starting Experiment 01: RSW Scaling ({len(TIME_TARGETS)} settings x {REPETITIONS} runs)")

        for target_time in TIME_TARGETS:
            print(f"Testing target_time = {target_time}s...")

            for run_id in range(1, REPETITIONS + 1):
                gen_result = subprocess.run(
                    [str(RUST_BINARY_PATH), 'generate', '--time', str(target_time)],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace'
                )
                if gen_result.returncode != 0:
                    print(f"[Run {run_id}] Setup failed at 'generate': {gen_result.stderr.strip()}")
                    break

                lock_result = subprocess.run(
                    [str(RUST_BINARY_PATH), 'lock', '--input', str(DUMMY_EXAM)],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace'
                )
                if lock_result.returncode != 0:
                    print(f"[Run {run_id}] Setup failed at 'lock': {lock_result.stderr.strip()}")
                    break

                start_time = time.perf_counter()
                result = subprocess.run(
                    [str(RUST_BINARY_PATH), 'solve'],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace'
                )
                elapsed_time = time.perf_counter() - start_time

                if result.returncode != 0:
                    print(f"[Run {run_id}] Failed during 'solve'! Error: {result.stderr.strip()}")
                    continue

                writer.writerow({
                    'timestamp_utc': datetime.now(timezone.utc).isoformat(),
                    'commit_hash': metadata['commit_hash'],
                    'os': metadata['os'],
                    'cpu': metadata['cpu'],
                    'target_time_seconds': target_time,
                    'run_id': run_id,
                    'actual_solve_time_seconds': round(elapsed_time, 6)
                })
                fp.flush()

            print(f"Completed {REPETITIONS} runs for {target_time}s.")

    print(f"Experiment complete. Results appended to {RESULTS_FILE}")

    if DUMMY_EXAM.exists():
        DUMMY_EXAM.unlink()

if __name__ == '__main__':
    run_experiment()
