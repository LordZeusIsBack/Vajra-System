# Experiment 06 — Centre Compromise

## Research Question
If an attacker steals the private keys of j out of n exam centres, can they decrypt the exam?

## Hypothesis
The attacker fails to decrypt for any j < k, and succeeds for any j >= k.

## Independent Variable
Number of centres compromised (private key stolen), 0 through n.

## Dependent Variables
- Decryption result (Decrypt / Fail)
- Time to attempt the attack

## Controlled Variables
- n = 10
- Tested thresholds (k) = 3, 5, 8, 10
- A fresh data_key, centre keypair set, and double-locked payload per repetition

## Procedure
1. Build one instance of the real centre-encryption layer: generate n X25519 centre keypairs (`centers.py`), Shamir-split a random 32-byte data_key into n shares (`shamir.py`), hybrid-encrypt each share to its centre's pubkey, and AES-GCM-wrap a stand-in payload with data_key — the same steps `lock_pipeline.py` runs.
2. For each compromise level j (0 to n), give the "attacker" a random sample of j centre private keys.
3. The attacker decrypts whichever shards those keys allow, feeds whatever shares it recovers into `shamir.reconstruct()` (no threshold hint — it doesn't know if it has enough), and tries to open the AES-GCM payload with the result.
4. A wrong data_key does not raise a Shamir error by itself — it only shows up when the AES-GCM tag fails to authenticate. Success is defined purely by that authentication check, matching how `centers.py` says this boundary is actually enforced in production.
5. Record expected vs. actual result and elapsed time. Repeat 10 times per threshold with fresh keys/data each time.

## Environment
No IPFS node, drand relay, server, or compiled Rust binary needed — this only exercises the Shamir + per-centre X25519/ChaCha20-Poly1305 + AES-GCM layer, in pure Python.

## Result
440/440 outcomes matched the k-of-n threshold prediction (4 thresholds x 10 repetitions x 11 compromise levels) — see `raw_results.csv`.