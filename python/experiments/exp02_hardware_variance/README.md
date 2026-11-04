# Experiment 2 — Hardware Variance

## Research Question
How much does RSW solving time vary across hardware?

## Hypothesis
Solving time and squarings/sec will vary significantly based on CPU single-thread performance, demonstrating that a faster centre may finish the sequential puzzle earlier than a slower one.

## Independent Variable
Machine hardware (CPU, RAM)

## Dependent Variable
Solve time, Squarings/sec

## Controlled Variables
N (constant puzzle)
T_ops (constant)


## Evidence revision (Outstanding Evidence items 2 and 3)

The first run recorded only `platform.processor()` strings and the
repository did not contain the shared `puzzle.json`, so the configured lock
duration and the calibration machine were unknown.

**Configured duration (item 2).** Commit the shared puzzle as
`exp02_hardware_variance/puzzle.json` (it is public data: N, g, t_ops,
ref_squarings_per_sec), then run:

```bash
python analyze_against_puzzle.py --calibrated-on <host name that ran vajra generate>
```

This derives T_cfg = t_ops / ref_squarings_per_sec (exact for puzzles from
`vajra generate`), checks that the
CSV's T_ops matches the file, labels the machines M1–M12 by mean solve time
as in Table III, and writes `deviation_from_configured.csv` with each
machine's deviation from T_cfg (seconds, percent, ratio) and whether its
throughput is within ±5 % of `ref_squarings_per_sec`.

**Hardware descriptions (item 3).** On every machine that took part, run

```bash
python collect_hwinfo.py --label M<n>
```

and commit `hwinfo/<host>.json`. It records the CPU marketing name
(`/proc/cpuinfo` or `lscpu`, `Get-CimInstance Win32_Processor` / `wmic`,
`sysctl machdep.cpu.brand_string`), core counts, the Windows power plan or
Linux frequency governor/driver/turbo setting or macOS `pmset`, AC/battery
state, and the EC2 instance type (IMDSv2). `analyze_against_puzzle.py`
merges these files by host name.

**Repeat on the high-variance machines (M6, M7, M8, M10, M11).**
`run_hardware_bench.py` now passes explicit `--puzzle/--locked` paths to
`vajra solve`, records the pure squaring time (`VAJRA_TIMING`) next to the
whole-process time, and samples CPU frequency, CPU load, load average and
temperature before and after every run. Fix the power plan (e.g. Windows
"High performance", AC power, no other load), then:

```bash
python run_hardware_bench.py --runs 10 --note "High performance plan, AC power, idle"
```

New runs go to `raw_results_v2.csv`; the original `raw_results.csv` is kept
unchanged.
