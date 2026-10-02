# Experiment 08 — End-to-End Performance

## Research Question

As the exam PDF grows (1 MB -> 100 MB), which pipeline stage actually
dominates total lock-to-reconstruct time — and, specifically, does RSW
puzzle-solving time (the thing the temporal security guarantee depends on)
stay independent of PDF size, or not?

## Hypothesis

Pure RSW squaring time is set only by `T_ops` (the calibrated difficulty),
never by PDF size, because `puzzle::solve()` never touches plaintext or
ciphertext bytes. Shamir split/combine and per-centre encryption depend
only on n/k. Everything that actually processes the PDF (AES-GCM
encrypt/decrypt, hex encode/decode, JSON read/write) grows with PDF size
and can end up dominating wall-clock time at large sizes — the _whole_
`vajra lock`/`vajra solve` CLI calls are not size-independent (on this
hardware the `solve` call ends up ~1.9x slower at 100 MB than at 1 MB),
only the squaring inside them is.

_(First pass at this experiment measured `vajra lock`/`vajra solve` only
as single opaque wall-clock numbers and found both growing substantially
with PDF size. That looked like it contradicted the "solving is
size-independent" claim. It didn't — see the instrumentation note below.)_

> **Read this before looking at the CSV.** `lock_wall_sec` and
> `solve_wall_sec` are wall-clock time for the _whole_ CLI call and **will
> grow with PDF size** — that's expected, not a bug. The column that
> isolates pure RSW squaring time — the one that should stay flat, and the
> one to cite for "solving time is independent of exam size" — is
> **`solve_squaring_sec`**. (These two columns used to be named
> `inner_lock_sec`/`rsw_solve_sec`; "rsw_solve" read like it meant pure RSW
> time, which caused real confusion when it grew with size, so they were
> renamed.)

## Independent Variable

PDF size: 1, 5, 10, 25, 50, 100 MB (synthetic payloads, same as exp04)

## Dependent Variable

Wall-clock time of each pipeline stage, plus an internal breakdown of the
two RSW-binary calls:
`centre_keygen -> puzzle_generation -> lock_wall (parse/keyderiv/encrypt/write)
-> outer_lock -> shamir_split -> centre_encryption -> ipfs_upload
-> ipfs_fetch -> centre_reconstruction -> shamir_combine -> outer_decrypt
-> solve_wall (parse/squaring/decrypt/write) -> cleanup`

## Controlled Variables

- n = 10, k = 8
- Puzzle target time = 2s (same RSW difficulty at every PDF size)
- 5 repetitions per size

## VAJRA_TIMING instrumentation

`lock_wall_sec` and `solve_wall_sec` are wall-clock time for the _whole_
CLI call — realistic, but a black box: `vajra solve` internally does
(a) read+parse `locked.json` (hex-encoded, ~2x PDF size as text), (b) the
actual sequential squaring, (c) derive K and AES-GCM-decrypt the full
plaintext, (d) write the recovered PDF. Only (b) is "RSW solving"; (a)/(c)/(d)
scale with PDF size and were originally invisible inside one timer.

`main.rs`'s `cmd_lock`/`cmd_solve` wrap each of those four sub-steps in
`Instant::now()` and, if `VAJRA_TIMING=1` is set in the environment, print
one extra line to stderr. A real line from this run (100 MB, run 1):

```
VAJRA_TIMING solve parse=0.230555 squaring=1.934076 decrypt=1.048715 write=0.134042
```

This is **opt-in and stderr-only** — unset, the binary's stdout, output
files and exit code are unchanged (verified: running `solve` twice on
identical inputs, with and without the env var, produced byte-identical
stdout and a byte-identical output PDF). `puzzle.rs` and `crypto.rs` (the
actual cryptographic code) are untouched; only the CLI orchestration in
`main.rs` gained timers. `run_end_to_end_bench.py` sets `VAJRA_TIMING=1` on
every call and parses these lines into `lock_parse_sec` /
`lock_keyderiv_sec` / `lock_encrypt_sec` / `lock_write_sec` and
`solve_parse_sec` / `solve_squaring_sec` / `solve_decrypt_sec` /
`solve_write_sec`. Against an unpatched binary these columns just come
back empty — everything else in the script still works.

**`solve_wall_sec` is a little larger than `solve_parse + solve_squaring +
solve_decrypt + solve_write` added together** — e.g. at 100 MB the four
sub-stages sum to 1.387s but `solve_wall_sec` averages 3.709s (minus the
1.946s of that which is squaring, a residual of ~0.38s). That residual is
real, but it isn't RSW, decrypt, or parse — it's Python-harness overhead
(writing `fetched_puzzle.json`/`fetched_locked.json` before invoking the
binary, reading `solved.pdf` back after, plus process-spawn cost), and it
grows with size because those files do. `lock_wall_sec` has the same kind
of residual versus its own four sub-stages, for the same reason. Report
the four named sub-stages individually if you need the precise breakdown;
treat `*_wall_sec` as "whole CLI round-trip as experienced by the rest of
the pipeline," not as a sum of exactly four numbers.

## IPFS layer

Auto-detects a live Kubo daemon on the configured `IPFS_API_URLS`; if
found, uses the real, unmodified `IPFSClient` for genuine network timing.
Otherwise (the common case — no server needed) falls back to a small
in-memory content store, same idea as `FakeIPFSClient` in
`tests/test_split_flow.py`. `ipfs_backend` in the CSV records which one
ran; `ipfs_upload_sec`/`ipfs_fetch_sec` are only real network numbers when
it says `real`. Every run so far (including this one) used `simulated`.

## Environment

No IPFS node or server required by default. Needs a `vajra` binary built
from the patched `main.rs` at `rust/target/release/vajra(.exe)` —
`make rs-build`. (Runs fine against an unpatched binary too; you just lose
the `solve_squaring_sec` breakdown.)

## How to run

```bash
cd python/experiments/exp08_end_to_end
python run_end_to_end_bench.py
```

Edit the constants at the top of `run_end_to_end_bench.py` to change the
sweep. Results are written to `raw_results.csv`.

## Result

Full sweep, 5 reps per size, n=10/k=8, puzzle target 2s, simulated IPFS,
on target hardware (Windows). All 30 runs reconstructed correctly
(`reconstruction_correct == True` throughout).

**`solve` call breakdown (the number that matters for the security claim):**

|   size | solve_parse | **solve_squaring** | solve_decrypt | solve_write | solve_wall (total) |
| -----: | ----------: | -----------------: | ------------: | ----------: | -----------------: |
|   1 MB |      0.003s |         **1.925s** |        0.011s |      0.002s |             1.991s |
|   5 MB |      0.012s |         **1.956s** |        0.053s |      0.005s |             2.086s |
|  10 MB |      0.020s |         **1.938s** |        0.103s |      0.007s |             2.138s |
|  25 MB |      0.048s |         **1.933s** |        0.255s |      0.036s |             2.391s |
|  50 MB |      0.095s |         **1.938s** |        0.512s |      0.061s |             2.804s |
| 100 MB |      0.216s |         **1.946s** |        1.031s |      0.139s |             3.709s |

Across all 30 runs at every size, `solve_squaring_sec` has mean 1.940s,
stdev 0.026s, full range 1.874s–2.013s — a 0.14s spread (7.2% relative)
across a 100x range in PDF size, with no trend across sizes (1 MB and
100 MB are both ~1.93-1.95s; the variation is run-to-run noise, not a
function of size). **Confirms the hypothesis: RSW solving time really is
independent of PDF size.** Essentially all of the growth in
`solve_wall_sec` (1.991s -> 3.709s, +1.86x) is `solve_decrypt` (AES-GCM
decrypt + hex-decode of the full payload, 0.011s -> 1.031s, a 97x
increase) with a smaller contribution from `solve_parse` (JSON
deserialize of the hex-encoded blob, 0.003s -> 0.216s).

**`lock` call breakdown (same mechanism, mirrored):**

|   size | lock_parse | lock_keyderiv | lock_encrypt | lock_write | lock_wall (total) |
| -----: | ---------: | ------------: | -----------: | ---------: | ----------------: |
|   1 MB |     0.001s |        0.001s |       0.007s |     0.018s |            0.067s |
|   5 MB |     0.003s |        0.001s |       0.030s |     0.030s |            0.117s |
|  10 MB |     0.005s |        0.001s |       0.057s |     0.042s |            0.160s |
|  25 MB |     0.011s |        0.001s |       0.141s |     0.118s |            0.366s |
|  50 MB |     0.023s |        0.001s |       0.284s |     0.227s |            0.693s |
| 100 MB |     0.043s |        0.001s |       0.563s |     0.453s |            1.355s |

`lock_keyderiv_sec` (the admin's φ(N) shortcut) stays flat like squaring
does, as expected — it never touches the plaintext either.
`lock_encrypt_sec` (AES-GCM-encrypt + hex-encode the full exam) is the
dominant grower, 85x from 1 MB to 100 MB, mirroring `solve_decrypt_sec`'s
97x growth on the reconstruction side — same hex-encode/decode +
AES-GCM-over-everything mechanism, both directions.

**Overall pipeline:** `puzzle_generation_sec` stays flat (~2.10s at every
size, confirming it's pure admin-side setup independent of the exam). Mean
`wall_clock_total_sec` grows 1.78x, from 4.19s (1 MB) to 7.45s (100 MB),
entirely driven by `lock_wall` (+1.29s) and `solve_wall` (+1.72s) — not by
`puzzle_generation` or by any of the Shamir/centre/IPFS stages, which stay
in the tens-of-milliseconds range regardless of size.

**On the variance seen in the previous run:** an earlier run of this
sweep had one 100 MB repetition spike to `solve_wall_sec` = 8.26s against
a ~3.7-4.7s baseline for its siblings, suspected to be transient host
noise (e.g. antivirus real-time scanning the ~100-200 MB temp files this
script writes every repetition). **This clean rerun shows no such
outlier** — 100 MB `solve_wall_sec` is tightly clustered at 3.67s-3.76s
(stdev 0.037s) across all 5 reps — consistent with that earlier spike
being transient host noise rather than a property of the pipeline itself.
