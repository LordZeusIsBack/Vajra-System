# VAJRA Architecture

_Detailed technical specification — current as of manifest v1.3._

This document is the canonical technical reference. It describes the system
as currently implemented in this repository. For the original design
document (manifest v1.0, pre-drand, pre-per-centre), see
[Vajra_Architecture_Detailed v1.md](Vajra_Architecture_Detailed_v1); that
document is preserved for historical context but does not match the
current implementation.

---

## 1. Threat model

VAJRA is designed against four classes of adversary, with the cryptographic
protection appropriate to each:

| Adversary                 | Capability                                              | VAJRA defence                                                                                                                                     |
| ------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Curious administrator** | Holds all admin secrets, has full pre-T=0 access        | Time-lock puzzle: K destroyed at lock-time, recoverable only by sequential work that completes at T=0.                                            |
| **Insider at one centre** | Holds one centre's private key, can read its shard      | Shamir threshold: one share reveals zero information about `data_key`. Information-theoretic, not computational.                                  |
| **Network adversary**     | Passively observes IPFS, MitM on coordinator submission | Per-centre hybrid encryption: shards in transit and at rest on IPFS are ciphertext against one specific recipient. AAD binds payload to manifest. |
| **Wall-clock attacker**   | Manipulates local NTP, fakes "exam time has arrived"    | drand beacon: cryptographically signed time anchor, multi-relay agreement, refuses early decryption.                                              |

VAJRA does _not_ defend against:

- An adversary who compromises ≥ _k_ centre private keys simultaneously
  (this is the threshold security boundary by design).
- An adversary who controls the printer or screen at a centre after T=0
  (this is outside the cryptographic system; addressed by forensic
  watermarking, which is not yet implemented).
- An adversary who can forge the manifest's HMAC (i.e. who possesses
  `MANIFEST_HMAC_SECRET`). In production this should be replaced with
  Ed25519 signatures so no symmetric secret is needed for verification.
- Quantum adversaries against RSW or X25519 (a post-quantum redesign is
  out of scope).

## 2. The three locks

### Lock 1 — Time-lock puzzle (RSW)

Based on **Rivest, Shamir, and Wagner (1996), "Time-lock puzzles and
timed-release Crypto."** The construction:

1. The administrator generates two large random primes _p_, _q_ (currently
   512 bits each; production requires ≥ 1024 bits each). Let _N_ = _p_ · _q_.
2. The administrator picks a base _g_ as a quadratic residue mod _N_:
   _g_ = *h*² mod _N_ for random _h_ ∈ [2, *N* − 2].
3. The administrator decides _T_ops_ — how many sequential squarings the
   solver must perform. This is calibrated to the administrator's hardware
   via a 2-second benchmark (see § 5.1 below for the timing limitation).
4. Using the trapdoor _φ_(_N_) = (_p_ − 1)(_q_ − 1), the administrator
   computes:
   - _e_ = 2^_T_ops_ mod _φ_(_N_) (fast, _O_(log _T_ops_) operations)
   - _K_ = _g_^_e_ mod _N_ (fast, _O_(log _e_) operations)
5. _K_ is hashed through SHA-256 to derive a 32-byte AES key, used to
   encrypt the exam PDF under AES-256-GCM.
6. The administrator **destroys** _p_, _q_, and _φ_(_N_).

Without _φ_(_N_), the only known way to recover _K_ is to start with _g_
and compute _T_ops_ sequential squarings. This is provably sequential:
each squaring depends on the previous result, so no amount of parallelism
helps. The construction's security rests on the conjecture that no faster
algorithm exists for general repeated squaring without knowing the
factorisation of _N_.

**Implementation:** [`rust/src/puzzle.rs`](../rust/src/puzzle.rs).
Pure Rust with `num-bigint`; no GMP or external C dependencies. The
Miller–Rabin primality test runs 25 rounds (false-positive probability
< 4⁻²⁵ ≈ 10⁻¹⁵). Squaring uses Rust's built-in big-integer arithmetic;
the inner loop is `x = (&x * &x) % &n` and is approximately 1 million
operations per second on a modern CPU for a 1024-bit modulus.

### Lock 2 — k-of-n threshold (Shamir's Secret Sharing)

Based on **Adi Shamir (1979), "How to share a secret."** Over GF(2⁸)
(byte-level field, AES reducing polynomial *x*⁸ + *x*⁴ + *x*³ + _x_ + 1).

For each byte _b_ of the 32-byte `data_key`, the administrator constructs
a random polynomial of degree _k_ − 1 in GF(2⁸):

$$f_b(x) = b + r_1 x + r_2 x^2 + \dots + r_{k-1} x^{k-1}$$

where _r₁_ … _r\_{k-1}_ are uniformly random bytes. The administrator
evaluates _f_b_ at _x_ = 1, 2, …, _n_; the _i_-th share is the vector

$$\text{share}_i = (i, f_0(i), f_1(i), \dots, f_{31}(i))$$

— 1 byte of x-coordinate plus 32 bytes of polynomial evaluations.

**Reconstruction property.** Lagrange interpolation at _x_ = 0 recovers
_f_b_(0) = _b_ from any _k_ shares. _k_ − 1 shares yield no information
about the byte — this is information-theoretic, not computational.

**Implementation:** [`python/shamir.py`](../python/shamir.py). The
`reconstruct` function accepts an `expected_threshold` parameter that
explicitly guards against the "too few shares" case (where standard
Shamir would silently return a wrong secret). Tests verify the
information-theoretic property by attempting reconstruction with _k_ − 1
shares and confirming the result differs from the original.

### Lock 3 — per-centre addressing (X25519 + ChaCha20-Poly1305)

A standard hybrid encryption construction (essentially HPKE base mode,
RFC 9180, without the full ceremony). For each Shamir share, the
administrator:

1. Generates a fresh ephemeral X25519 keypair (_eph_sk_, _eph_pk_).
2. Computes the X25519 shared secret with the recipient centre's pubkey:
   _shared_secret_ = X25519(_eph_sk_, _centre_pk_).
3. Derives a symmetric key via HKDF-SHA256:
   _key_ = HKDF(_shared_secret_, _info_ = "vajra-shard-v1", _length_ = 32).
4. Generates a fresh random 96-bit nonce.
5. Encrypts the share: _ciphertext_ = ChaCha20-Poly1305(_key_).encrypt
   (_nonce_, _share_bytes_, AAD = ∅).

The output stored on IPFS is _(eph_pk, nonce, ciphertext)_. The
ephemeral private key is discarded. Forward secrecy on the sender side
is provided by the freshness of _eph_sk_; if the administrator's machine
were compromised after lock-time, the historical shards would not be
recoverable.

The recipient decrypts by computing
_shared_secret_ = X25519(_centre_sk_, _eph_pk_) and proceeding symmetrically.

**Implementation:** [`python/centers.py`](../python/centers.py). Uses
the `cryptography` library's primitives directly (no NaCl, no PyNaCl
dependency). HKDF info string is hardcoded for domain separation.

## 3. The time anchor — drand

Independent of the three locks, VAJRA cryptographically binds each exam
to a specific drand round. **drand** is a publicly-auditable distributed
randomness beacon operated by the **League of Entropy** (Cloudflare,
Protocol Labs, EPFL, kudelski security, and other members). A fresh
threshold-BLS-signed random value is published every 30 seconds on a
known chain whose configuration (chain hash, genesis time, period) is
public and immutable.

### 3.1. AAD binding (cryptographic)

The administrator computes a 32-byte additional-authenticated-data value:

$$\text{AAD} = \text{SHA-256}(\texttt{"vajra-v1"} \,\|\, R_{\text{u64,BE}} \,\|\, \text{chain\_hash}_{\text{bytes}})$$

where _R_ is the smallest drand round whose publish time ≥ the configured
exam start. Both AES-GCM layers — the inner one wrapping `exam.pdf`
inside Rust, and the outer one wrapping `locked.json` in Python —
include this AAD in their authentication tags. The AAD value itself is
not stored; the verifier derives it identically from manifest fields
(`drand.target_round` and `drand.chain_hash`) at reconstruction time.

**Consequence.** An attacker who modifies the manifest's `target_round`
breaks the HMAC signature first; but even if HMAC verification were
somehow bypassed, the AAD derived from the tampered value would not
match what was used at lock-time, and the AES-GCM authentication tags
on both encryption layers would fail. The drand round is
cryptographically welded to the encryption.

### 3.2. Policy gate (operational)

At reconstruction time, the coordinator additionally:

1. Refuses to proceed if the local clock indicates the target round's
   publish time has not yet been reached.
2. Fetches round _R_ from all configured drand relays (default: 4
   public relays) in parallel.
3. Requires at least _min_agreement_ relays (default: 2) to return
   identical signature and randomness values.
4. Refuses to proceed if fewer relays agree.

This is policy, not cryptography. A determined attacker who has
the manifest, ≥ _k_ centre privkeys, and the IPFS payload can run
`vajra solve` directly and bypass this gate. The AAD binding ensures
they cannot alter _which_ round was used; the policy gate ensures the
coordinator script will not knowingly decrypt early. A fully
cryptographic time gate requires timelock encryption against drand
itself — see [DEPLOYMENT.md § 3.1](DEPLOYMENT.md#31-timelock-encryption).

**Implementation:** [`python/drand_client.py`](../python/drand_client.py).
Default chain is the League of Entropy mainnet (chain hash
`8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce`,
30-second period). Configurable via `.env`.

## 4. The pipeline, step by step

### 4.1. Lock pipeline (Source Vault, T = −days)

Invoked via `POST /api/v1/lock` to the FastAPI server, or directly via
`run_vajra_pipeline()`:

1. **Compute drand parameters.** From the configured exam start time,
   derive _target_round_, _publish_time_, and the AAD.
2. **`vajra generate`** (Rust subprocess). Produces `puzzle.json`
   (public: _N_, _g_, _T_ops_, reference squarings/sec) and `secret.json`
   (private: _p_, _q_). The benchmark step inside `generate` is the
   bottleneck — ~2 seconds.
3. **`vajra lock --aad-hex <AAD>`** (Rust subprocess). Computes _K_ via
   the _φ_(_N_) shortcut, encrypts the PDF under AES-256-GCM with the
   AAD bound in. Output: `locked.json`.
4. **Shred secret.** `secret.json` is overwritten with three passes
   (zeros, ones, random) and unlinked. On Linux, this delegates to
   `shred -u -n 3`. SSDs with wear-levelling may retain physical
   remnants; production should run on encrypted filesystems with key
   destruction. After this point, _K_ is unrecoverable until the
   sequential squaring completes at T=0.
5. **Outer AES-GCM wrap.** A random 32-byte `data_key` is generated.
   `locked.json` bytes are encrypted under AES-GCM(`data_key`, AAD).
6. **Shamir split.** `data_key` is split into _n_ shares using the
   GF(2⁸) construction above. Each share is 33 bytes.
7. **Per-centre encryption.** Each share is hybrid-encrypted to the
   corresponding centre's pubkey from `centers.json`. Output:
   `n` `EncryptedShard` objects.
8. **IPFS upload.** `puzzle.json`, the outer payload, and each
   encrypted shard are uploaded to IPFS. Shards are round-robined
   across configured Kubo nodes for redundancy. CIDs are recorded.
9. **Manifest construction.** A v1.3 manifest is built containing all
   CIDs, the drand block, and the centre pubkeys. HMAC-SHA256 signed
   with `MANIFEST_HMAC_SECRET`. The signed manifest is itself uploaded
   to IPFS.
10. The administrator's response is the manifest CID. They may publish
    it however they wish — Twitter, official notification, press
    release, embedded in QR codes on candidate admit cards. The CID
    is integrity-protected by IPFS content addressing.

### 4.2. Reconstruction pipeline (T = 0)

This is decentralised. _k_ centres each run on their own machine:

```
python vajra_center.py decrypt-share <manifest_cid> \
    --my-key path/to/MY_KEYPAIR.json \
    --out path/to/share_for_coordinator.json
```

The script:

1. Fetches the manifest from IPFS.
2. Verifies the HMAC. Aborts if invalid.
3. Looks up this centre's index in the manifest's `centers` array
   (by centre ID).
4. Fetches that centre's specific shard CID from IPFS.
5. Cross-checks the shard's `center_id` field against the manifest
   (defence against IPFS-level swap attacks).
6. Decrypts the shard using the centre's private key.
7. Writes a small JSON share file: `{manifest_cid, center_id,
center_index, share_hex}`.

The share file is safe to transmit over any channel — by Shamir's
information-theoretic security, the holder of one share alone learns
nothing about `data_key`. _k_ − 1 shares together are equally useless.

A coordinator (which may be one of the centres, or a neutral party,
or an automated process) collects ≥ _k_ share files and runs:

```
python vajra_coordinator.py combine <manifest_cid> \
    --share share_001.json --share share_002.json [... ≥ k total ...] \
    --vajra path/to/vajra \
    --out exam.pdf
```

The coordinator:

1. Fetches and HMAC-verifies the manifest.
2. Validates each submitted share file (manifest CID matches,
   center_id at the claimed index matches the manifest, no duplicate
   indices).
3. **Drand gate.** Verifies the target round has published — local
   clock check first, then multi-relay agreement.
4. Re-derives the AAD from manifest fields.
5. Combines the _k_ plaintext shares via Shamir Lagrange
   interpolation → `data_key`.
6. Fetches the outer payload from IPFS, decrypts with `data_key`
   and AAD → `locked.json` bytes.
7. Fetches `puzzle.json` from IPFS.
8. Invokes `vajra solve --aad-hex <AAD>` — this is where the time-lock
   does its work. The squaring runs for approximately _T_ seconds.
9. The decrypted PDF is written to the output path. The coordinator
   verifies it begins with `%PDF` magic bytes.

## 5. Known cryptographic limitations

These are limitations of the current prototype, not flaws in the
underlying constructions. Each has a clear path to resolution in a
production design.

### 5.1. Hardware-calibrated time-lock

`T_ops` is calibrated to the _administrator's_ hardware via a 2-second
benchmark inside `vajra generate`. A centre with a meaningfully faster
CPU will finish squaring _before_ T=0; a slower centre will finish
_after_. The drand time-anchor partially closes this:

- The policy gate refuses reconstruction before publish_time, so a
  fast centre that finishes early still cannot decrypt early.
- The AAD binding ensures the manifest's target_round cannot be
  silently altered.

But the _upper bound_ — making decryption impossible before T=0 in
the cryptographic sense — requires **timelock encryption (TLE)
against drand itself**. This is a known construction (Boneh–Franklin
identity-based encryption with the drand chain pubkey as the master
public key, the target round number as the identity); it is
implemented in the `drand-tlock` reference. Integrating it into VAJRA
is the largest single piece of remaining work and is the highest
priority production upgrade. See [DEPLOYMENT.md § 3.1](DEPLOYMENT.md#31-timelock-encryption).

### 5.2. Coordinator share visibility

At the moment of Shamir combine, the coordinator's process holds all
_k_ plaintext shares simultaneously. An attacker who compromises the
coordinator at that instant recovers `data_key`. This is inherent to
the basic Shamir scheme; a production-grade design would use
**secure multi-party computation** (MPC) so the Lagrange
interpolation happens without any single party holding the full set
of shares. This is well-studied (BGW, SPDZ, etc.) but adds
substantial operational complexity.

For this prototype, the coordinator should be treated as a sensitive
machine — air-gapped, attested, ephemeral. In a real deployment with
_n_ = 50 centres and _k_ = 35, the threshold is forgiving enough
that one compromised coordinator does not enable systematic leaks
across exam cycles, but it remains the highest-value single target.

### 5.3. Cryptographic parameter sizes

Current defaults:

| Parameter          | Current                                     | Production target | Reason                                                                                                            |
| ------------------ | ------------------------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------- |
| RSW prime size     | 512 bits                                    | ≥ 1024 bits       | 1024-bit _N_ (current) is within reach of nation-state factoring; 2048-bit _N_ is conjectured secure for decades. |
| Drand chain        | League of Entropy mainnet, 30-second period | Same              | Already production-grade.                                                                                         |
| Manifest signature | HMAC-SHA256                                 | Ed25519           | Removes the symmetric secret.                                                                                     |
| Shamir n / k       | configurable (default 10/8)                 | per-exam policy   | No cryptographic change; just operational.                                                                        |

### 5.4. Key custody at centres

Centre private keys live as plain JSON files. Production demands
HSM or TEE custody, attested boot, and key rotation between exams.
See [DEPLOYMENT.md § 4](DEPLOYMENT.md#4-key-custody).

### 5.5. Forensic watermarking

Once decrypted, the exam paper is plaintext at each centre. A
malicious proctor or candidate could photograph the screen or
printout. The original architecture document specified
LSB/frequency-domain watermarking that embeds centre ID, room
number, and timestamp into the rendered PDF; this would make any
leaked photograph instantly traceable to its source.

This is not yet implemented. The stub at
[`python/steg.py`](../python/steg.py) marks the intended location.

## 6. Manifest format (v1.3)

Stored as a JSON object on IPFS. All fields are required.

```json
{
  "version": "1.3",
  "exam_id": "<uuid4>",
  "locked_at": "<ISO-8601 UTC>",
  "n": 10,
  "k": 8,
  "puzzle_cid": "bafy…",
  "payload_cid": "bafy…",
  "nonce": "<24 hex chars — 12 bytes>",
  "shard_cids": [
    {"cid": "bafy…", "node_index": 0},
    ...
  ],
  "centers": [
    {"index": 0, "id": "CENTER_000", "pubkey": "<64 hex chars — 32 bytes>"},
    ...
  ],
  "drand": {
    "chain_hash": "<64 hex chars — 32 bytes>",
    "target_round": 12345678,
    "publish_time": 1932000000
  },
  "hmac": "<64 hex chars — SHA-256 HMAC>"
}
```

The HMAC is computed over canonical (sort*keys, no whitespace) JSON
of the manifest \_without* the `hmac` field. Every other field is
covered by the HMAC.

## 7. Code map

| Module                        | Responsibility                                                                                                                                           |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `python/main.py`              | FastAPI server; orchestrates `POST /api/v1/lock`.                                                                                                        |
| `python/lock_pipeline.py`     | The full lock pipeline, called from `main.py`.                                                                                                           |
| `python/reconstruct.py`       | Library functions for single-machine reconstruction; also defines `fetch_and_decrypt_one_shard` and `combine_shares_to_pdf` used by the split-flow CLIs. |
| `python/vajra_center.py`      | CLI for the centre-side `decrypt-share` operation.                                                                                                       |
| `python/vajra_coordinator.py` | CLI for the coordinator-side `combine` operation.                                                                                                        |
| `python/vajra_keygen.py`      | CLI for X25519 keypair generation and registry assembly.                                                                                                 |
| `python/centers.py`           | Hybrid encryption (X25519 + ChaCha20-Poly1305) for shards.                                                                                               |
| `python/shamir.py`            | GF(2⁸) Shamir secret sharing.                                                                                                                            |
| `python/drand_client.py`      | Multi-relay drand HTTP client + AAD derivation.                                                                                                          |
| `python/manifest.py`          | HMAC-signed manifest build + verify.                                                                                                                     |
| `python/ipfs_client.py`       | Kubo HTTP RPC wrapper.                                                                                                                                   |
| `python/config.py`            | pydantic-settings; loads `.env` with strict validation.                                                                                                  |
| `rust/src/main.rs`            | CLI dispatch: `generate`, `lock`, `solve`, `bench`.                                                                                                      |
| `rust/src/puzzle.rs`          | RSW puzzle: Miller–Rabin, generation, admin shortcut, solver.                                                                                            |
| `rust/src/crypto.rs`          | AES-256-GCM with AAD support.                                                                                                                            |

## 8. References

1. R. L. Rivest, A. Shamir, D. A. Wagner. **"Time-lock puzzles and
   timed-release Crypto."** MIT Laboratory for Computer Science
   Technical Report, 1996.
2. A. Shamir. **"How to share a secret."** _Communications of the ACM_,
   22 (11): 612–613, November 1979.
3. D. J. Bernstein. **"Curve25519: New Diffie-Hellman speed records."**
   PKC 2006.
4. Y. Nir, A. Langley. **RFC 8439: ChaCha20 and Poly1305 for IETF
   Protocols.** June 2018.
5. R. Barnes, K. Bhargavan, B. Lipp, C. Wood. **RFC 9180: Hybrid Public
   Key Encryption.** February 2022.
6. League of Entropy. **drand specification.**
   https://drand.love/docs/specification/
7. M. Blum, S. Goldwasser. **"An Efficient Probabilistic Public-Key
   Encryption Scheme Which Hides All Partial Information."** CRYPTO 1984.
   (Relevant to the quadratic-residue choice of _g_.)
