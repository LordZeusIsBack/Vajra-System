# Experiment 05 — Manifest Integrity Attacks

## Research Question
Does the manifest's HMAC signature correctly reject a manifest that has been tampered with after signing?

## Hypothesis
Any post-signing change to a security-relevant manifest field (the drand `target_round`, the `payload_cid`, a center's `pubkey`, or a `shard_cid`) will cause HMAC verification to fail, while an untampered manifest still verifies successfully.

## Independent Variable
Which manifest field is tampered with:
- none (control)
- `drand.target_round`
- `payload_cid`
- `centers[0].pubkey`
- `shard_cids[0].cid`

## Dependent Variable
Verification result of `manifest.verify()` — ACCEPT or REJECT.

## Controlled Variables
- n = 10, k = 8
- Same manifest (and HMAC secret) used to derive all attack copies within a repetition
- Exactly one field changed per attack

## Procedure
1. Build and sign one valid manifest (real X25519 center keys via `centers.py`; IPFS CIDs are opaque placeholder strings since no IPFS node is used).
2. Make a deep copy for each attack and tamper exactly one field.
3. Call `manifest.verify()` on each copy — this is the same check `reconstruct.py` runs as the first step of reconstruction, so a REJECT here means reconstruction would have stopped immediately.
4. Record attack, modified field, expected result, and actual result to `raw_results.csv`.
5. Repeat for 20 freshly generated reference manifests.

## Environment
No IPFS node, drand relay, server, or compiled Rust binary needed — manifest signing/verification is pure Python HMAC-SHA256 and never touches the RSW puzzle.

## Result
100/100 checks matched expectation (5 attacks × 20 repetitions) — see `raw_results.csv`.