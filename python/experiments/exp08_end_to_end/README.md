# Experiment 08 — End-to-End Performance

## Research Question
As the exam PDF grows (1 MB -> 100 MB), which pipeline stage actually
dominates total lock-to-reconstruct time?

## Hypothesis
RSW puzzle solving time stays ~constant (it's set by the target lock
duration, not PDF size). The AES-GCM stages grow with PDF size but stay
small in absolute terms. Shamir split/combine and per-centre encryption
depend only on n/k, not PDF size. So beyond a few MB, PDF size should
barely move the total.

## Independent Variable
PDF size: 1, 5, 10, 25, 50, 100 MB (synthetic payloads, same as exp04)

## Dependent Variable
Wall-clock time of each stage, separately:
`puzzle_generation -> inner_lock -> outer_lock -> shamir_split ->
centre_encryption -> ipfs_upload -> ipfs_fetch -> centre_reconstruction ->
shamir_combine -> outer_decrypt -> rsw_solve`

## Controlled Variables
- n = 10, k = 8
- Puzzle target time = 2s (same RSW difficulty at every PDF size)
- 5 repetitions per size

## Procedure
Every crypto/Shamir/centre call is the real, unmodified production function
(`centers.py`, `shamir.py`, `drand_client.py`); the two RSW steps shell out
to the real compiled `vajra` binary — nothing about production code is
touched or reimplemented, only wrapped with timers (per the "harness
around it" convention from exp01/exp04).

**IPFS layer:** the script auto-detects a live Kubo daemon on the
configured `IPFS_API_URLS`. If found, it uses the real, unmodified
`IPFSClient` for genuine network upload/fetch timing. If not found (the
common case — no server needed), it falls back to a small in-memory
content store, the same idea as `FakeIPFSClient` in
`tests/test_split_flow.py`. `ipfs_backend` in the CSV records which one
ran, and `total_ipfs_bytes` records how much data would have moved either
way, so `ipfs_upload_sec`/`ipfs_fetch_sec` are only meaningful as real
network numbers when `ipfs_backend == real`. To get those, start a local
Kubo daemon (`ipfs daemon`) before running this script — nothing else
changes.

Each repetition also re-derives the recovered PDF and checks it against
the original byte-for-byte (`reconstruction_correct`).

## Environment
No IPFS node or server is required to run this. Needs a compiled `vajra`
binary at `rust/target/release/vajra(.exe)` — build with `make rs-build`.

## Result
Not yet run on target hardware — fill in after running. Local smoke test
(1 MB / 5 MB, 2 reps, simulated IPFS) reconstructed correctly on every run
and already showed the expected shape: `puzzle_generation` flat at ~2s
regardless of size, `rsw_solve` flat at ~puzzle target time, while
`inner_lock`/`outer_lock`/`outer_decrypt` grow with PDF size but stay
small (tens of ms) next to the RSW stages.