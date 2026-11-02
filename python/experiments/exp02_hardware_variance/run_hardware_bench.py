"""Experiment 2 — solve the same RSW puzzle on this machine and record the host.

Every participating machine must use the SAME puzzle.json and locked.json
(copy both into this directory). The puzzle file records the calibration
speed (ref_squarings_per_sec); the requested lock duration is
t_ops / ref_squarings_per_sec (see analyze_against_puzzle.py).

Each run records:
  • solve_time_sec      wall time of the whole `vajra solve` process
                        (the quantity reported in the paper, Table III)
  • squaring_sec        the sequential squaring alone (VAJRA_TIMING)
  • the CPU model name, core counts, power plan or frequency governor,
    AC/battery state, EC2 instance type (common.host_info), and the CPU
    frequency, load and temperature sampled just before and after the run
    (common.runtime_state).

Usage:
  python run_hardware_bench.py                    # 10 runs → raw_results_v2.csv
  python run_hardware_bench.py --runs 10 --note "High performance plan, AC power"

The published raw_results.csv (first run of this experiment) is left untouched;
new runs go to --out (default raw_results_v2.csv) because the columns differ.
"""

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent))

from common import find_vajra_binary, host_info, runtime_state  # noqa: E402

PUZZLE_FILE = SCRIPT_DIR / "puzzle.json"
LOCKED_FILE = SCRIPT_DIR / "locked.json"


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def solve_once(binary: Path, puzzle: Path, locked: Path, aad_hex: str) -> tuple[float, float | None]:
    """Run `vajra solve` once; return (process wall seconds, squaring seconds)."""
    with tempfile.TemporaryDirectory(prefix="vajra_exp02_") as tmp:
        out = Path(tmp) / "exam.pdf"
        env = {**os.environ, "VAJRA_TIMING": "1"}
        t0 = time.perf_counter()
        proc = subprocess.run(
            [str(binary), "solve", "--puzzle", str(puzzle), "--locked", str(locked),
             "--output", str(out), "--aad-hex", aad_hex],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
        )
        elapsed = time.perf_counter() - t0
    if proc.returncode != 0:
        raise RuntimeError(f"vajra solve failed: {proc.stderr.strip()[-400:]}")
    squaring = None
    for line in proc.stderr.splitlines():
        if line.startswith("VAJRA_TIMING solve"):
            for pair in line.split()[2:]:
                key, _, val = pair.partition("=")
                if key == "squaring":
                    squaring = float(val)
    return elapsed, squaring


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--puzzle", type=Path, default=PUZZLE_FILE)
    ap.add_argument("--locked", type=Path, default=LOCKED_FILE)
    ap.add_argument("--aad-hex", default="", help="AAD used when locked.json was created (default none)")
    ap.add_argument("--note", default="", help="free text, e.g. power plan chosen for this repeat")
    ap.add_argument("--out", type=Path, default=SCRIPT_DIR / "raw_results_v2.csv")
    args = ap.parse_args()

    for f in (args.puzzle, args.locked):
        if not f.exists():
            raise SystemExit(f"{f} not found. Copy the shared puzzle.json and locked.json here.")
    binary = find_vajra_binary()
    puzzle = json.loads(args.puzzle.read_text())
    t_ops = int(puzzle["t_ops"])

    static = host_info()
    print(f"Host: {static['Machine']} — {static['CPU_model'] or static['CPU']}")
    print(f"Puzzle: t_ops={t_ops}, ref_squarings_per_sec={puzzle.get('ref_squarings_per_sec')}, "
          f"lock_seconds={puzzle.get('lock_seconds', 'not recorded')}")

    rows = []
    for i in range(1, args.runs + 1):
        state = runtime_state()
        wall, squaring = solve_once(binary, args.puzzle, args.locked, args.aad_hex)
        state_after = runtime_state()
        rows.append({
            **static,
            "T_ops": t_ops,
            "ref_squarings_per_sec": puzzle.get("ref_squarings_per_sec", ""),
            "lock_seconds": puzzle.get("lock_seconds", ""),
            "puzzle_sha256": file_sha256(args.puzzle),
            "Run": i,
            "solve_time_sec": round(wall, 4),
            "squaring_sec": round(squaring, 4) if squaring is not None else "",
            "squarings_sec": round(t_ops / wall, 2) if wall > 0 else 0,
            **{f"before_{k}": v for k, v in state.items()},
            **{f"after_{k}": v for k, v in state_after.items()},
            "note": args.note,
        })
        sq = f"{squaring:.2f} s" if squaring is not None else "n/a"
        print(f"  run {i}/{args.runs}: {wall:.2f} s (squaring {sq}, "
              f"{state['cpu_mhz_now']} MHz before)")

    exists = args.out.exists()
    with open(args.out, "a", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=list(rows[0].keys()))
        if not exists:
            writer.writeheader()
        writer.writerows(rows)
    print(f"Recorded {len(rows)} runs to {args.out}")


if __name__ == "__main__":
    main()
