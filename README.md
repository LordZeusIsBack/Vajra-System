<div align="center">

# VAJRA

**A zero-trust cryptographic architecture for high-stakes examination distribution.**

_Makes pre-exam paper leaks mathematically impossible — not as policy, but as proof._

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status: Prototype](https://img.shields.io/badge/status-prototype-orange)](#status-and-honest-limitations)
[![Tests: 85 passing](https://img.shields.io/badge/tests-85_passing-brightgreen)](#testing)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org)
[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org)

</div>

---

> **What this is in one sentence.** Three independent cryptographic locks
> (a sequential-squaring time-lock puzzle, _k_-of-_n_ Shamir secret sharing,
> and per-centre X25519 hybrid encryption) combine with a drand beacon time
> anchor so that an examination paper cannot be decrypted — by anyone,
> including the administrator — until the configured exam-start moment, and
> only when ≥ _k_ independent regional centres cooperate.

> **What this is not.** A deployed product. See
> [ Status and honest limitations](#status-and-honest-limitations) before
> going further. This is a working prototype intended to demonstrate that
> the cryptographic infrastructure for leak-proof examination distribution
> exists and is feasible — not to be used in a live examination tomorrow.

---

## Why this exists

Every documented paper leak in India's high-stakes examination system over
the last decade exploits the same vulnerability: **the paper is in human
hands before the exam starts.** Physical printing, sealed-trunk transport,
warehouse storage, distribution to centres — each step is a leak vector,
each step depends on the trustworthiness of every human in the chain.

The legislative response — the _Public Examinations (Prevention of Unfair
Means) Act, 2024_ with its 10-year jail terms and ₹1 crore fines — is
punitive. It acts after a leak has destroyed an exam cycle. It cannot
change the fact that the paper is _physically present_ in trusted human
custody for hours or days before T=0.

VAJRA changes what is _physically possible_. The paper is sealed under
three mathematically independent constraints, each of which must be
satisfied at T=0 for decryption to occur. No single party can defeat all
three. The administrator never holds the decryption key after lock-time
completes. Centres hold only their assigned piece, useless in isolation.

This is not a claim that the system is unbreakable. It is a claim that
the human-trust attack surface has been replaced with a cryptographic one
— and that the cryptographic one is, by published academic consensus,
much harder to break.

A detailed motivation, including specific incidents (NEET-UG 2024,
UPSC CSE Prelims 2025, SSC clerical 2024, BPSC teacher recruitment 2024)
and their sources, is on the landing page:
**[VAJRA homepage](https://vajra-system.vercel.app/)**

## Quick links by audience

If you are a **journalist or policy researcher**, start with
[ARCHITECTURE.md](docs/ARCHITECTURE.md) for the technical story written
in prose, and the landing page for incident context. Specific factual
claims in this README are footnoted; everything is independently
verifiable.

If you are a **cryptographer or security engineer**, the meat is in
[`python/lock_pipeline.py`](python/lock_pipeline.py) (orchestration),
[`python/centers.py`](python/centers.py) (per-centre hybrid encryption),
[`python/drand_client.py`](python/drand_client.py) (time anchor), and
[`rust/src/puzzle.rs`](rust/src/puzzle.rs) (RSW time-lock). Test suite
is [`python/tests/`](python/tests/) — 85 passing tests covering both
positive and adversarial paths. Audit findings are
[welcomed via GitHub issues](https://github.com/LordZeusIsBack/Vajra-System/issues).

If you are a **developer who wants to try it**, jump to
[ Quick start](#quick-start) below. End-to-end run takes ~5 minutes
once dependencies are in place.

If you are an **examination board considering this seriously**, please
read [DEPLOYMENT.md](docs/DEPLOYMENT.md). That document is intentionally
written as a gap analysis between what this prototype demonstrates and
what production deployment would require. It is not a "ready to deploy"
guide — that document does not yet exist, because the work to write it
has not been done.

## Architecture in one diagram

```
                          LOCK TIME (Admin side, T = -days)
  ┌─────────────────────────────────────────────────────────────────┐
  │  exam.pdf                                                       │
  │     │                                                           │
  │     ▼                                                           │
  │  ┌──────────────────────┐                                       │
  │  │  RSW Time-Lock       │  inner layer — sequential squaring    │
  │  │  AES-256-GCM(K, pdf) │  K = g^(2^T_ops) mod N                │
  │  └─────────┬────────────┘                                       │
  │            │ locked.json                                        │
  │            ▼                                                    │
  │  ┌──────────────────────┐                                       │
  │  │  Outer AES-256-GCM   │  outer layer — random data_key        │
  │  │  AAD = SHA256(round) │  drand round-binding via AAD          │
  │  └─────────┬────────────┘                                       │
  │            │ payload                                            │
  │            ▼                                                    │
  │  ┌──────────────────────┐                                       │
  │  │  Shamir SSS k-of-n   │  data_key split into n pieces         │
  │  └─────────┬────────────┘                                       │
  │            │ n shares                                           │
  │            ▼                                                    │
  │  ┌──────────────────────┐                                       │
  │  │  Per-centre X25519   │  each share encrypted to              │
  │  │  + ChaCha20-Poly1305 │  one specific centre's pubkey         │
  │  └─────────┬────────────┘                                       │
  │            │                                                    │
  │            ▼                                                    │
  │       IPFS  +  signed manifest  (public, anyone can fetch,      │
  │                                  no one can read)               │
  └─────────────────────────────────────────────────────────────────┘

                          UNLOCK TIME (T = 0)
  ┌─────────────────────────────────────────────────────────────────┐
  │   k centres each decrypt their own shard (private keys local)   │
  │                              │                                  │
  │                              ▼                                  │
  │   plaintext shares submitted to coordinator                     │
  │                              │                                  │
  │                              ▼                                  │
  │   drand round R confirmed published (multi-relay agreement)     │
  │                              │                                  │
  │                              ▼                                  │
  │   Shamir combine → data_key → outer AES-GCM unwrap →            │
  │   sequential squaring → K → inner AES-GCM unwrap → exam.pdf     │
  └─────────────────────────────────────────────────────────────────┘
```

For a written walkthrough see [ARCHITECTURE.md](docs/ARCHITECTURE.md).
For the operational ceremony see [DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Quick start

The minimum to run VAJRA locally is: Python ≥ 3.11, Rust ≥ 1.75, and a
local IPFS daemon (Kubo).

### Prerequisites

```bash
# 1. Python with uv  (https://docs.astral.sh/uv/)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. Rust  (https://rustup.rs/)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 3. IPFS Kubo  (https://docs.ipfs.tech/install/command-line/)
#    On Linux/macOS see the link; on Windows use the installer.
ipfs init
```

### One-time setup

```bash
git clone https://github.com/LordZeusIsBack/Vajra-System
cd Vajra-System

# Build the Rust binary (release mode — it's measurably faster, and the
# benchmark numbers calibrating the time-lock depend on release perf)
cd rust && cargo build --release && cd ..

# Install Python dependencies
cd python && uv sync && cd ..
```

### Run an end-to-end demo

```bash
# Terminal 1: start IPFS
ipfs daemon

# Terminal 2: configure and start the source vault
cd python
cp env.example .env
# Open .env and set MANIFEST_HMAC_SECRET to a real 64-hex string:
#   python -c "import secrets; print(secrets.token_hex(32))"
# Then generate 5 centre keypairs:
uv run python vajra_keygen.py bulk --n 5 --out-dir ./keys
# And start the server (it will pick up ./keys/centers.json from .env):
uv run fastapi dev main.py

# Terminal 3: lock an exam
curl -X POST http://127.0.0.1:8000/api/v1/lock \
    -F "file=@your_exam.pdf" \
    -F "exam_start_seconds=60"
# Note the manifest_cid in the response — call it $CID below.

# Terminal 4: each "centre" decrypts its own shard
#  (in production, each centre runs this on their own machine;
#   here we run from one terminal for brevity)
cd python
uv run python vajra_center.py decrypt-share $CID \
    --my-key ./keys/CENTER_000.json \
    --out /tmp/share_000.json
uv run python vajra_center.py decrypt-share $CID \
    --my-key ./keys/CENTER_002.json \
    --out /tmp/share_002.json
uv run python vajra_center.py decrypt-share $CID \
    --my-key ./keys/CENTER_004.json \
    --out /tmp/share_004.json

# Coordinator combines (note: NO keypair files in the coordinator's directory)
uv run python vajra_coordinator.py combine $CID \
    --share /tmp/share_000.json \
    --share /tmp/share_002.json \
    --share /tmp/share_004.json \
    --vajra ../rust/target/release/vajra \
    --out exam_recovered.pdf \
    --skip-drand-check        # for offline test; remove in real usage

# Verify byte-for-byte recovery
md5sum your_exam.pdf exam_recovered.pdf
# The two hashes should be identical.
```

A `Makefile` at the project root wraps the most common of these commands:

```bash
make rs-build    # cargo build --release
make py-sync     # uv sync
make py-server   # fastapi dev main.py
make test        # pytest tests/
```

## Repository layout

```
vajra/
├── README.md                   # you are here
├── LICENSE                     # Apache 2.0
├── NOTICE                      # third-party attributions
├── Makefile                    # convenience wrappers
├── .gitignore
│
├── docs/
│   ├── ARCHITECTURE.md                             # detailed system architecture
│   ├── DEPLOYMENT.md                               # gap analysis for production deployment
│   ├── Vajra_Architecture_Detailed_v1.md           # first version of the design document
│   └── Vajra_Architecture_Detailed_v2.md           # second and current version of the design document
│
├── python/                     # orchestration, IPFS, drand, per-centre
│   ├── pyproject.toml
│   ├── env.example             # copy to .env and fill in
│   ├── main.py                 # FastAPI Source Vault server
│   ├── lock_pipeline.py        # end-to-end lock orchestration
│   ├── reconstruct.py          # single-machine reconstruction (helper)
│   ├── vajra_center.py         # per-centre CLI (decrypt-share)
│   ├── vajra_coordinator.py    # coordinator CLI (combine)
│   ├── vajra_keygen.py         # X25519 keypair ceremony
│   ├── centers.py              # per-centre hybrid encryption
│   ├── shamir.py               # GF(2^8) k-of-n secret sharing
│   ├── drand_client.py         # multi-relay drand client + AAD
│   ├── manifest.py             # HMAC-signed manifest format
│   ├── ipfs_client.py          # Kubo HTTP RPC wrapper
│   ├── config.py               # pydantic-settings loader
│   └── tests/                  # 85 tests
│       ├── test_centers.py     #   per-centre encryption
│       ├── test_drand.py       #   round arithmetic + multi-relay
│       ├── test_roundtrip.py   #   manifest + Shamir + outer AES-GCM
│       └── test_split_flow.py  #   end-to-end decentralized flow
│
└── rust/                       # the RSW time-lock puzzle
    ├── Cargo.toml
    └── src/
        ├── main.rs             # CLI (generate, lock, solve, bench)
        ├── puzzle.rs           # RSW puzzle: Miller-Rabin, gen, solve
        └── crypto.rs           # AES-256-GCM with AAD
```

## Testing

```bash
cd python
uv run pytest tests/ -v
# Expected: 85 passed
```

The test suite covers:

- **`test_roundtrip.py`** — Shamir split/reconstruct, outer AES-GCM tamper
  detection, manifest HMAC including tamper detection in every field
  (puzzle CID, payload CID, shard CIDs, centre pubkeys, drand round, chain
  hash). Off-by-one drand round in AAD must fail decryption.

- **`test_drand.py`** — round arithmetic (boundary cases, time-before-genesis,
  inverse property), AAD determinism, multi-relay agreement (4 cases:
  all agree, majority with one disagreement, no majority, all relays down),
  policy gate (refuses before publish time, accepts after).

- **`test_centers.py`** — X25519 keypair generation (uniqueness across
  runs), registry I/O (duplicate ID/pubkey detection, malformed entries),
  encrypt/decrypt round-trip across various plaintext sizes, wrong-privkey
  failure mode, tampered ciphertext and ephemeral-pubkey detection, full
  Shamir × per-centre integration.

- **`test_split_flow.py`** — full decentralized reconstruction flow with
  in-memory IPFS fake: each "centre" decrypts only their own shard, share
  files load/save round-trip, coordinator rejects wrong manifest CID,
  duplicate indices, and centre-id-mismatch attacks.

Rust integration tests:

```bash
cd rust
cargo test --release
```

## Status and honest limitations

**This is a prototype.** Every component described in this README and the
linked documents is real and runs. The cryptographic primitives are
standard and well-audited. The system has been validated locking and
unlocking real PDFs end-to-end.

**It is not production-ready.** Specifically:

1. The RSW modulus is **1024-bit (two 512-bit primes)** in the current
   default configuration. This is acceptable for a prototype but well
   below the 2048-bit threshold considered safe against nation-state
   adversaries. Production must use ≥ 2048-bit moduli.

2. The time-lock parameter `T_ops` is calibrated to the **administrator's
   hardware** via a 2-second benchmark. A centre with a faster CPU will
   finish the squaring before T=0; a slower one will finish after. The
   drand time-anchor partially mitigates this by enforcing a _minimum_
   wall-clock time (decryption refuses if drand round R hasn't published),
   but does not enforce a _maximum_. A complete solution requires
   timelock encryption (TLE) against drand itself — see DEPLOYMENT.md
   3.1.

3. **Centre private key custody is left to the operator.** This prototype
   stores private keys as plain JSON files. Production requires HSM
   custody, key rotation, and an attested boot environment at each centre.

4. **No formal security audit has been performed.** The cryptographic
   constructions used are standard and individually audited; the
   composition is novel and would require professional review before any
   real deployment.

5. **The coordinator briefly holds all k plaintext Shamir shares**
   during reconstruction. In a real deployment this is the most
   sensitive moment in the entire system — the only point at which an
   attacker who compromises the coordinator can recover `data_key`.
   Production-grade reconstruction would use secure multi-party
   computation so no single machine ever holds all shares
   simultaneously. This is out of scope here.

6. **The manifest is HMAC-signed, not Ed25519-signed.** This means
   verification requires the symmetric secret. Production should switch
   to public-key signatures so anyone can verify a manifest without
   holding the signing key.

7. **Watermarking and forensic traceability** (described in the original
   architecture document as "Tier 3") are not implemented. Once the PDF is decrypted at a centre, photographs of the screen are still possible. Watermarking would make a leaked photograph
   instantly traceable to a specific centre/room/time.

8. **The "centers.json" registry is integrity-critical and not currently
   signed.** An attacker who replaces a centre's pubkey before lock-time
   would be able to decrypt that centre's shard. The registry should be
   signed by an offline admin key in production.

For the full gap analysis, including suggested production
parameters, see [DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Contributing

Independent review is the most valuable contribution at this stage.

If you can demonstrate a cryptographic attack against any of the claims
in this README or in ARCHITECTURE.md, open a GitHub issue. The claims
will be retracted or the system will be fixed.

If you find a bug, open a GitHub issue with reproduction steps. PRs
welcome on documentation, test coverage, and code clarity. Substantial
architectural changes should be discussed in an issue first.

Anybody contributing code agrees to license their contribution under
Apache 2.0 as well (per 5 of the LICENSE).

## Citation

If you reference VAJRA in academic or policy work, please cite as:

```bibtex
@misc{sharma2026vajra,
  author = {Sharma, Anubhav},
  title  = {VAJRA: A Zero-Trust Cryptographic Architecture for High-Stakes
            Examination Distribution},
  year   = {2026},
  url    = {https://vajra-system.vercel.app},
  note   = {Prototype. Source code available at https://github.com/LordZeusIsBack/Vajra-System}
}
```

## Contact

- **Email:** anubhavsharma5645@gmail.com
- **LinkedIn:** [linkedin.com/in/anubhav-sharma-ai](https://www.linkedin.com/in/anubhav-sharma-ai)
- **GitHub:** [@LordZeusIsBack](https://github.com/LordZeusIsBack)

Inquiries from examination boards, journalists, policy researchers,
and cryptographers are welcomed.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The cryptographic constructions used in VAJRA are based on published
academic work and well-established primitives. VAJRA does not claim
original cryptographic invention; it composes known primitives into
an examination-distribution-specific protocol. See NOTICE for the
academic lineage.

---

<div align="center">
<sub><strong>VAJRA · वज्र</strong><br>
The diamond that cannot be cut. The thunderbolt that arrives at once.</sub>
</div>
