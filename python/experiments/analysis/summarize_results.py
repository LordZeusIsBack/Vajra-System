import csv
import re
import statistics as st
from collections import Counter, OrderedDict
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"

EXP01_FIELDS = ["timestamp_utc", "commit_hash", "os", "cpu", "target_time_seconds", "run_id", "actual_solve_time_seconds"]


def rows(name, fieldnames=None):
    with open(DATA / name, newline="", encoding="utf-8") as fp: return list(csv.DictReader(fp, fieldnames=fieldnames))


def num(value):
    cleaned = re.sub(r"[^0-9eE+.\-]", "", value)
    if cleaned != value: print(f"note: value {value!r} parsed as {cleaned!r}")
    return float(cleaned)


def msd(values):
    return st.mean(values), (st.stdev(values) if len(values) > 1 else 0.0)


def group(items, key):
    out = OrderedDict()
    for item in items: out.setdefault(key(item), []).append(item)
    return out


def exp01():
    print("== Experiment 1: RSW lock-duration scaling (results.csv has no header row)")
    data = rows("exp01_results.csv", EXP01_FIELDS)
    print(f"  rows={len(data)} commits={sorted(set(r['commit_hash'] for r in data))} os={sorted(set(r['os'] for r in data))}")
    for target, grp in group(data, lambda r: int(r["target_time_seconds"])).items():
        t = [num(r["actual_solve_time_seconds"]) for r in grp]
        m, s = msd(t)
        print(f"  target={target:>2}s n={len(t)} mean={m:.3f} sd={s:.3f} min={min(t):.3f} max={max(t):.3f} mean/target={m / target:.3f} cv={s / m:.3f}")


def exp02():
    print("== Experiment 2: cross-hardware RSW evaluation")
    data = rows("exp02_raw_results.csv")
    print(f"  rows={len(data)} T_ops={sorted(set(r['T_ops'] for r in data))}")
    summary = []
    for key, grp in group(data, lambda r: r["Machine"]).items():
        t = [num(r["solve_time_sec"]) for r in grp]
        s = [num(r["squarings_sec"]) for r in grp]
        summary.append((st.mean(t), key, grp[0], t, s))
    summary.sort()
    for i, (_, _, first, t, s) in enumerate(summary, start=1):
        tm, ts = msd(t)
        sm, ss = msd(s)
        print(f"  M{i:<2} os={first['OS']!r} cpu={first['CPU']!r} ram={first['RAM_GB']} rustc={first['Rust Version'].split(' (')[0]} n={len(t)} "
              f"time={tm:.2f}+-{ts:.2f} [{min(t):.2f},{max(t):.2f}] cv={ts / tm:.3f} rate={sm / 1e6:.3f}+-{ss / 1e6:.3f} M/s")
    fastest, slowest = summary[0][0], summary[-1][0]
    rates = [st.mean(x[4]) for x in summary]
    print(f"  fastest mean={fastest:.3f}s slowest mean={slowest:.3f}s time ratio={slowest / fastest:.3f} rate ratio={max(rates) / min(rates):.3f}")


def exp03():
    print("== Experiment 3: threshold reconstruction (one attempt per (k, j))")
    data = rows("exp03_raw_results.csv")
    print(f"  rows={len(data)} success values={Counter(r['success'] for r in data)}")
    for k, grp in group(data, lambda r: int(r["k"])).items():
        match = [int(r["shares_used"]) for r in grp if r["matches_original"] == "True"]
        print(f"  k={k:>2}: shares_used tested={[int(r['shares_used']) for r in grp]} matches_original for j={match}")
    t = [num(r["time_seconds"]) for r in data]
    print(f"reconstruction call time: min={min(t) * 1e3:.2f} ms max={max(t) * 1e3:.2f} ms")


def exp04():
    print("== Experiment 4: scaling across (n, k)")
    data = rows("exp04_raw_results.csv")
    fields = ["share_gen_encryption_time_sec", "reconstruction_time_sec", "peak_memory_mb", "data_transferred_mb", "ipfs_objects"]
    for (n, k), grp in group(data, lambda r: (int(r["n"]), int(r["k"]))).items():
        parts = []
        for f in fields:
            m, s = msd([num(r[f]) for r in grp])
            parts.append(f"{f}={m:.4f}+-{s:.4f}")
        print(f"  n={n:>3} k={k:>2} reps={len(grp)} " + " ".join(parts))


def exp05():
    print("== Experiment 5: manifest tampering")
    data = rows("exp05_raw_results.csv")
    print(f"rows={len(data)} repetitions={len(set(r['repetition'] for r in data))}")
    for (attack, actual), c in Counter((r["attack"], r["actual_result"]) for r in data).items():
        print(f"{attack:<24} -> {actual}: {c}")
    print(f"passed={sum(r['passed'] == 'True' for r in data)}/{len(data)}")


def exp06():
    print("== Experiment 6: center compromise")
    data = rows("exp06_raw_results.csv")
    print(f"rows={len(data)} matches_expected={Counter(r['matches_expected'] for r in data)}")
    for k, grp in group(data, lambda r: int(r["k"])).items():
        dec = [sum(1 for r in grp if int(r["centers_compromised"]) == j and r["actual_result"] == "Decrypt") for j in range(11)]
        print(f"k={k:>2}: successful decryptions per j=0..10 (of 10 reps): {dec}")
    t = [num(r["time_seconds"]) for r in data]
    print(f"attempt time: mean={st.mean(t) * 1e3:.2f} ms max={max(t) * 1e3:.2f} ms")


def exp07():
    print("== Experiment 7: failure and fault injection")
    data = rows("exp07_raw_results.csv")
    print(f"rows={len(data)} passed={sum(r['passed'] == 'True' for r in data)}")
    for (scen, case), grp in group(data, lambda r: (r["scenario"], r["case"])).items():
        res = Counter((r["expected_result"], r["actual_result"]) for r in grp)
        print(f"{scen:<28} {case:<28} reps={len(grp)} (expected,actual)={dict(res)}")
    downs = [r["notes"].split("down=")[1].split(")")[0] for r in data if r["scenario"] == "shard_granularity_10nodes" and "down=" in r["notes"]]
    print(f"10-node outage sets: {downs}")


def exp08():
    print("== Experiment 8: end-to-end payload size")
    data = rows("exp08_raw_results.csv")
    print(f"rows={len(data)} backends={set(r['ipfs_backend'] for r in data)} correct={Counter(r['reconstruction_correct'] for r in data)}")
    stage_cols = [
        "centre_keygen_sec", "puzzle_generation_sec", "lock_wall_sec", "outer_lock_sec",
        "shamir_split_sec", "centre_encryption_sec", "ipfs_upload_sec", "ipfs_fetch_sec",
        "centre_reconstruction_sec", "shamir_combine_sec", "outer_decrypt_sec",
        "solve_wall_sec", "cleanup_sec",
    ]
    show = ["puzzle_generation_sec", "lock_wall_sec", "lock_keyderiv_sec", "lock_encrypt_sec",
            "outer_lock_sec", "outer_decrypt_sec", "solve_wall_sec", "solve_parse_sec",
            "solve_squaring_sec", "solve_decrypt_sec", "solve_write_sec", "wall_clock_total_sec"]
    for size, grp in group(data, lambda r: int(r["pdf_size_mb"])).items():
        means = {c: st.mean(num(r[c]) for r in grp) for c in stage_cols + show}
        sds = {c: st.stdev(num(r[c]) for r in grp) for c in show}
        other = sum(means[c] for c in stage_cols if c not in ("puzzle_generation_sec", "lock_wall_sec", "solve_wall_sec"))
        stage_sum = sum(means[c] for c in stage_cols)
        print(f"{size:>3} MiB reps={len(grp)} " + " ".join(f"{c.replace('_sec', '')}={means[c]:.4f}+-{sds[c]:.4f}" for c in show) +
              f"other_stages={other:.4f} sum_of_stage_means={stage_sum:.4f} ipfs_bytes={st.mean(num(r['total_ipfs_bytes']) for r in grp):.0f}")
    sq = [num(r["solve_squaring_sec"]) for r in data]
    m, s = msd(sq)
    print(f"squaring over all 30 runs: mean={m:.4f} sd={s:.4f} min={min(sq):.4f} max={max(sq):.4f} range={max(sq) - min(sq):.4f}")


if __name__ == "__main__":
    for fn in (exp01, exp02, exp03, exp04, exp05, exp06, exp07, exp08):
        fn()
        print()
