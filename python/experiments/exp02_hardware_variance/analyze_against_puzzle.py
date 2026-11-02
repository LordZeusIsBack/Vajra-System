import argparse
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


def load_hwinfo(directory: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if directory.is_dir():
        for f in directory.glob("*.json"):
            try:
                info = json.loads(f.read_text())
            except json.JSONDecodeError:
                continue
            out[info.get("Machine", f.stem)] = info
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--puzzle", type=Path, default=SCRIPT_DIR / "puzzle.json")
    ap.add_argument("--results", type=Path, default=SCRIPT_DIR / "raw_results.csv")
    ap.add_argument("--hwinfo-dir", type=Path, default=SCRIPT_DIR / "hwinfo")
    ap.add_argument("--calibrated-on", default="", help="host name of the machine that ran `vajra generate`")
    ap.add_argument("--tolerance", type=float, default=0.05,
                    help="relative throughput tolerance for calibration candidates (default 0.05)")
    ap.add_argument("--out", type=Path, default=SCRIPT_DIR / "deviation_from_configured.csv")
    args = ap.parse_args()

    if not args.puzzle.exists():
        raise SystemExit(f"{args.puzzle} not found — add the shared Experiment 2 puzzle.json.")
    puzzle = json.loads(args.puzzle.read_text())
    t_ops = int(puzzle["t_ops"])
    ref = int(puzzle.get("ref_squarings_per_sec") or 0)

    if puzzle.get("lock_seconds") is not None:
        t_cfg = float(puzzle["lock_seconds"])
        source = "lock_seconds field"
    elif ref:
        t_cfg = t_ops / ref
        exact = t_ops % ref == 0
        source = f"t_ops / ref_squarings_per_sec ({'exact' if exact else 'NOT an integer — check the file'})"
    else:
        raise SystemExit("puzzle.json has neither lock_seconds nor ref_squarings_per_sec")

    by_machine: dict[str, list[dict]] = defaultdict(list)
    with open(args.results, newline="", encoding="utf-8") as fp:
        for row in csv.DictReader(fp):
            by_machine[row["Machine"]].append(row)

    mismatched = sorted({r["T_ops"] for rows in by_machine.values() for r in rows} - {str(t_ops)})
    if mismatched:
        raise SystemExit(f"raw results use T_ops {mismatched}, puzzle.json has {t_ops} — wrong file?")

    hw = load_hwinfo(args.hwinfo_dir)
    summary = []
    for machine, rows in by_machine.items():
        times = [float(r["solve_time_sec"]) for r in rows]
        mean = statistics.fmean(times)
        sd = statistics.stdev(times) if len(times) > 1 else 0.0
        throughput = statistics.fmean(float(r["squarings_sec"]) for r in rows)
        info = hw.get(machine, {})
        summary.append({
            "Machine": machine,
            "OS": rows[0]["OS"],
            "CPU_identifier": rows[0]["CPU"],
            "CPU_model": info.get("CPU_model", ""),
            "ec2_instance_type": info.get("ec2_instance_type", ""),
            "power": info.get("power_plan") or info.get("cpufreq_governor") or info.get("power_settings", ""),
            "runs": len(times),
            "mean_solve_sec": round(mean, 3),
            "sd_sec": round(sd, 3),
            "cv_pct": round(100 * sd / mean, 2),
            "min_sec": round(min(times), 3),
            "max_sec": round(max(times), 3),
            "throughput_per_sec": round(throughput),
            "configured_sec": round(t_cfg, 3),
            "deviation_sec": round(mean - t_cfg, 3),
            "deviation_pct": round(100 * (mean - t_cfg) / t_cfg, 2),
            "ratio_to_configured": round(mean / t_cfg, 3),
            "calibration_candidate": bool(ref) and abs(throughput - ref) / ref <= args.tolerance,
            "is_calibration_machine": machine == args.calibrated_on if args.calibrated_on else "",
        })

    summary.sort(key=lambda r: r["mean_solve_sec"])
    for i, row in enumerate(summary, 1):
        row["label"] = f"M{i}"

    fields = ["label"] + [k for k in summary[0] if k != "label"]
    with open(args.out, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fields)
        writer.writeheader()
        writer.writerows(summary)

    print(f"T_ops = {t_ops:,}   ref_squarings_per_sec = {ref:,}")
    print(f"Configured lock duration T_cfg = {t_cfg:g} s  (from {source})\n")
    print(f"{'Label':<6}{'Machine':<46}{'mean s':>9}{'Δ s':>9}{'Δ %':>9}{'ratio':>8}  cal?")
    for r in summary:
        print(f"{r['label']:<6}{r['Machine'][:45]:<46}{r['mean_solve_sec']:>9.2f}"
              f"{r['deviation_sec']:>9.2f}{r['deviation_pct']:>9.1f}{r['ratio_to_configured']:>8.2f}"
              f"  {'yes' if r['calibration_candidate'] else ''}")
    early = [r["label"] for r in summary if r["deviation_sec"] < 0]
    print(f"\nFinished before T_cfg: {', '.join(early) or 'none'}")
    within = [r["label"] for r in summary if abs(r["deviation_pct"]) <= 10]
    print(f"Within ±10 % of T_cfg: {', '.join(within) or 'none'}")
    if args.calibrated_on and args.calibrated_on not in by_machine:
        print(f"Note: --calibrated-on {args.calibrated_on!r} is not among the measured machines.")
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
