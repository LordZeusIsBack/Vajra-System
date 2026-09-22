# Experiment 07 — Failure Testing

## Research Question
When pieces of VAJRA's own infrastructure fail or get tampered with (an IPFS
node down, drand relays down, a wrong/duplicate/mislabeled share, a
corrupted ciphertext), does reconstruction fail *safely* at the point it
should — a clean, attributable rejection, never a wrong PDF?

## Hypothesis
Reconstruction succeeds whenever ≥k honest centres can reach the manifest
and their own shard, and is cleanly rejected for every tampering case below.

## Independent Variables
- Which IPFS node(s) are down (0–3, at two shard-distribution granularities: 3 nodes and 10 nodes)
- Number of down drand relays (0–4 of 4)
- Injected fault: wrong share value, duplicate share, mislabeled centre ID
  (IPFS layer and coordinator layer), corrupted shard ciphertext, corrupted
  outer payload ciphertext

## Dependent Variables
- Reconstruction result (Success / Fail)
- Which real function raised the error, and its message

## Controlled Variables
- n = 10, k = 8
- Fresh centre keypairs, data_key, and manifest per repetition
- Fixed drand target_round/chain_hash (round 1, already published)

## Procedure
Every check calls the real production functions unmodified (`centers.py`,
`shamir.py`, `manifest.py`, `reconstruct.py`, `vajra_coordinator.py`,
`drand_client.py`). Only the two network boundaries are swapped for
in-memory stand-ins — an in-memory `FakeIPFS` (same idea as
`tests/test_split_flow.py`'s fake) and `httpx.MockTransport` for the drand
relays (same pattern as `tests/test_drand.py`) — so the script needs no
live IPFS node, no live drand relay, and no server. Build one synthetic
locked exam per repetition, inject the fault, run the real reconstruction
path, compare actual vs. expected. 3–5 repetitions per case. If a compiled
`vajra` binary is found it's used for the success-path cases (real `vajra
solve`); otherwise those stop one step short, same fallback the test suite
uses.

## Environment
No IPFS node, drand relay, or server needed. Compiled `vajra` binary is
optional — used automatically if present at `rust/target/release/`.

## Result
65/65 outcomes matched expectation (both with and without the compiled
binary present) — see `raw_results.csv`. Two things worth flagging: node 0
(where the manifest/payload/puzzle are pinned, per `main.py`) is a hard
single point of failure with no fallback; and at the default 3-node IPFS
deployment, losing any single non-primary node already drops shard
availability below k even though Shamir's k-of-n nominally tolerates 2
losses — the nominal tolerance only holds with finer-grained (10-node)
distribution.