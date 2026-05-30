# VAJRA: A Zero-Trust Digital Pipeline for High-Stakes Examination Distribution

## 1. Executive Summary
The **VAJRA Architecture** is a decentralized, cryptographically-enforced framework designed to eliminate human-centric vulnerabilities in the high-stakes examination lifecycle (e.g., NEET, UPSC, SSC, JEE). By replacing physical trust with mathematical certainty, VAJRA ensures that exam content is inaccessible to all parties—including administrators—until the exact moment of the examination start, and only when a configurable threshold of independent regional centres cooperate.

### The Name: Why "Vajra"?
In Sanskrit, **Vajra** (वज्र) carries a dual meaning:
* **The Diamond:** Symbolizing **indestructibility** and clarity. The encrypted data cannot be "broken" or previewed.
* **The Thunderbolt:** Symbolizing **decisive speed** and irresistible force. Once the time is right, the system delivers the paper instantaneously.

### What Has Changed Since v1.0
This document is **v2.0**, reflecting the current implementation. The original v1.0 design (three tiers, RSW puzzle, IPFS distribution, steganographic watermarking) has been extended with two additional cryptographic constraints and a public time anchor:

| Component | v1.0 | v2.0 (current) |
| :--- | :--- | :--- |
| Time-lock puzzle | ✓ | ✓ |
| Shamir secret sharing | Mentioned | ✓ Implemented |
| Per-centre key addressing | — | ✓ X25519 + ChaCha20-Poly1305 |
| Wall-clock time anchor | — | ✓ drand beacon (League of Entropy) |
| Decentralized reconstruction | — | ✓ Centre + Coordinator CLIs |
| Forensic watermarking | Specified | Placeholder (planned) |

---

## 2. High-Level Architecture
The system is divided into three distinct tiers, ensuring no single point of failure or compromise. A public time anchor (drand) binds all three tiers to a verifiable wall-clock moment.

| Tier | Name | Role | Core Technology |
| :--- | :--- | :--- | :--- |
| **Tier 1** | **The Source Vault** | Preparation & Cryptographic Locking | FastAPI · Rust · RSW puzzle · Shamir SSS · X25519 |
| **Tier 2** | **The Distribution Web** | Decentralized Transport | IPFS (Kubo) · HMAC-signed manifests |
| **Tier 3** | **The Reconstruction Ceremony** | Decentralized Decryption | Centre CLI · Coordinator CLI · Rust solver |
| **Anchor** | **The Time Beacon** | Wall-Clock Binding | drand · multi-relay agreement |

---

## 3. Tier 1: Ingestion & The "Vajra Lock"

The Source Vault accepts an exam PDF and applies **three independent cryptographic locks** in sequence, plus a time anchor binding all three to a future moment. Any one lock, on its own, is insufficient to recover the exam. All three together can only be satisfied at the configured exam-start time.

### 3.1. The Time Lock (RSW Puzzle)
The innermost lock is the **Rivest-Shamir-Wagner (RSW)** time-lock puzzle. This prevents "early leaks" by forcing the computer to perform a sequential calculation that cannot be parallelized.

**The Math of the Lock:**
1.  **Setup:** The administrator generates two large secret primes $p$ and $q$ and calculates $N = p \times q$.
2.  **Complexity Calculation:** Let $T$ be the time until the exam. Let $S$ be the number of squaring operations a standard CPU can perform per second. Total operations $T_{ops} = T \times S$.
3.  **The Shortcut (Admin only):** The admin uses $\phi(N) = (p-1)(q-1)$ to calculate:
    $$e = 2^{T_{ops}} \pmod{\phi(N)}$$
    $$K = g^e \pmod N$$
    *Where $K$ is the decryption key, hashed through SHA-256 to derive a 32-byte AES key.*
4.  **The Lock:** The admin discards $p, q,$ and $\phi(N)$. The only way to find $K$ now is to start with $g$ and square it $T_{ops}$ times.
5.  **The Inner Encryption:** The exam PDF is encrypted under AES-256-GCM keyed by SHA-256($K$). This produces `locked.json`.

> ⚠ **Timing nuance.** $T_{ops}$ is calibrated to the *administrator's* hardware via a 2-second benchmark. Centres with faster CPUs finish before T=0; slower ones finish after. The drand time anchor (4) closes the lower bound by refusing reconstruction before the beacon publishes. Closing the upper bound — making decryption *cryptographically* impossible before T=0 — requires full timelock encryption against drand; see [DEPLOYMENT.md 2.2](DEPLOYMENT.md).

### 3.2. The Consensus Lock (Shamir's Secret Sharing)
After the inner encryption, a fresh random 32-byte `data_key` wraps `locked.json` in an outer AES-256-GCM layer. The `data_key` itself is then split using **Shamir's Secret Sharing** over GF(2⁸):

* **Mechanism:** The 32-byte key is split into $n$ shares; any $k$ shares can reconstruct it; $k-1$ shares reveal **literally zero information** about the key.
* **Property:** This is *information-theoretic* security, not computational. No amount of computing power can recover the key from $k-1$ shares — the information is mathematically not there.
* **Default:** $n = 10, k = 8$. Configurable per-exam via the lock endpoint.

To leak the paper, an attacker would need to compromise **at least k centres simultaneously**. Not bribery of one official. Not theft of one trunk. Coordinated breach of a configurable threshold of independent organizations.

### 3.3. The Addressed Lock (Per-Centre Encryption)
Each of the $n$ Shamir shares is further hybrid-encrypted to a specific centre's **X25519 public key** before it ever leaves the Source Vault.

* **Scheme:** Ephemeral X25519 ECDH → HKDF-SHA256 → ChaCha20-Poly1305 AEAD (essentially HPKE base mode, RFC 9180).
* **Per-Shard Output:** `(ephemeral_pubkey, nonce, ciphertext)`. Each shard becomes a sealed envelope addressed to exactly one centre.
* **Registry:** A `centers.json` file maps centre IDs to their X25519 pubkeys. The administrator never sees a private key — centres generate keypairs locally and submit only the pubkey.

Without the matching X25519 private key, an encrypted shard on IPFS is computationally useless. The administrator's machine, after this step, holds zero information that would let it decrypt any individual shard.

### 3.4. Manifest Construction
A signed JSON manifest is constructed listing:
* Public puzzle parameters ($N, g, T_{ops}$) → as an IPFS CID
* Outer-locked payload → as an IPFS CID
* Each encrypted shard → as IPFS CIDs, in order
* Each centre's ID and pubkey
* drand chain hash, target round, and publish time

The whole manifest is signed with HMAC-SHA256 (or, in production, Ed25519). Tampering with any field — a CID, a centre pubkey, a drand round — invalidates the signature.

---

## 4. The Time Anchor: drand (League of Entropy)
Independent of the three locks, VAJRA binds each exam to a specific moment in **publicly verifiable wall-clock time** using the **drand** distributed randomness beacon, operated by the League of Entropy (Cloudflare, Protocol Labs, EPFL, and other independent organizations).

### 4.1. How the Anchor Works
* **The Beacon:** drand publishes a fresh threshold-BLS-signed random value every 30 seconds. The round number for any future moment is deterministic; the *signature* for that round cannot exist until threshold signers cooperate at that moment.
* **The Binding:** VAJRA computes:

    AAD = SHA256("vajra-v1" || target_round || chain_hash)

This value is used as **Additional Authenticated Data** in both AES-GCM encryption layers. Tampering with the manifest's target round changes the AAD, breaking decryption cryptographically.
* **The Policy Gate:** At reconstruction time, the coordinator queries multiple drand relays and refuses to proceed unless ≥2 relays agree the target round has published.

### 4.2. What the Anchor Defeats
* **Clock manipulation:** A local NTP attacker cannot fool the system into decrypting early — drand is queried over HTTPS from multiple independent relays.
* **Hardware variance attacks:** Even if a centre's CPU is fast enough to solve the time-lock early, the coordinator script refuses to proceed before the drand round publishes.
* **Post-hoc disputes:** "When exactly was T=0?" has an answer that's publicly auditable months or years later.

---

## 5. Tier 2: The Distribution (IPFS & Immutability)

### 5.1. Decentralized Transport via IPFS
To prevent a central server hack, the encrypted shards and the outer payload are uploaded to **IPFS**, with shards distributed round-robin across multiple Kubo nodes for redundancy.

* **Content Addressing:** Files are stored based on their **CID (Content Identifier)** — a cryptographic hash of the content.
* **Zero-Trust Retrieval:** Centres do not "download a file"; they "request a CID."
* **Public Network, Private Content:** Anyone can fetch any CID. Without the matching X25519 private key (and without ≥k cooperating centres), the fetched ciphertext is useless.

### 5.2. Immutability & Rejection Logic
* **The CID Rule:** If a single bit of the encrypted payload is altered (e.g., a hacker tries to inject a fake question), the CID changes entirely.
* **Manifest Integrity:** The manifest's HMAC covers all CIDs and all centre pubkeys. If a CID in the manifest doesn't match what was signed, verification fails before any IPFS fetch occurs.
* **Defense in Depth:** Even if HMAC verification were bypassed, the AES-GCM AAD bound to the drand round provides a second cryptographic check.

### 5.3. Manifest Distribution
The signed manifest is itself uploaded to IPFS and produces its own CID. This single string — typically ~60 characters, e.g. `bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi` — is what the administrator publishes (via official notification, social media, embedded in candidate admit cards as a QR code). Possession of the CID grants the ability to fetch and verify the manifest; it does not grant the ability to decrypt anything.

---

## 6. Tier 3: The Reconstruction Ceremony

The decryption ceremony is **decentralized**. No single party holds enough information to reconstruct the exam. The ceremony has two roles, performed on physically separate machines:

### 6.1. The Centre Role
Each participating centre runs the `vajra_center` CLI on their own machine:

```
vajra_center decrypt-share <manifest_cid> \
    --my-key MY_KEYPAIR.json \
    --out my_share.json
```

This script:
1. Fetches the manifest from IPFS and verifies its HMAC signature.
2. Looks up this centre's index in the manifest's `centers` array.
3. Fetches *only* this centre's encrypted shard from IPFS.
4. Decrypts the shard locally using the centre's X25519 private key.
5. Writes a small share file containing the plaintext Shamir share.

The centre's machine never sees other centres' keys, other centres' shards, the `data_key`, or the exam PDF. The plaintext share alone reveals nothing about the `data_key`.

### 6.2. The Coordinator Role
A coordinator collects ≥$k$ share files from cooperating centres and runs:

```
vajra_coordinator combine <manifest_cid> \
    --share share_001.json --share share_003.json [... ≥k total ...] \
    --vajra path/to/vajra \
    --out exam.pdf
```

This script:
1. Verifies the manifest HMAC.
2. Cross-checks each share file (manifest CID matches, no duplicate indices, centre IDs at claimed indices match the manifest).
3. **Drand gate:** Verifies the target round has published via multi-relay agreement.
4. Re-derives the AAD from manifest fields.
5. Combines the $k$ plaintext shares via Shamir Lagrange interpolation → `data_key`.
6. Decrypts the outer AES-GCM payload → `locked.json`.
7. Invokes `vajra solve --aad-hex <AAD>` — the Rust binary performs $T_{ops}$ sequential squarings (~$T$ seconds of CPU work).
8. Decrypts the inner AES-GCM layer → exam PDF.

### 6.3. The Rust Runtime
The local solver is a **Rust CLI**. Rust is chosen for:
* **Performance:** Solving the time-lock puzzle requires maximum CPU efficiency. Pure-Rust big-integer arithmetic (`num-bigint`) achieves ~1 million squarings/sec on a 1024-bit modulus.
* **Memory Safety:** Eliminates common vulnerabilities (buffer overflows) that could be used to extract the key from memory during computation.
* **Portability:** A single static binary runs on every major platform.

### 6.4. Dynamic Forensic Watermarking (Planned)
Once the PDF is decrypted for display or printing, a **Sentinel layer** would apply forensic watermarks before display.

* **Hidden Data:** Using LSB (Least Significant Bit) steganography or frequency-domain watermarking via **OpenCV**.
* **The Payload:** The watermark embeds the **Centre ID, Room Number, and Timestamp** into the background of the PDF.
* **Leak Detection:** If a proctor or student photographs the printed paper and shares it, a simple scan of the image reveals exactly which centre and room the leak originated from.

> 📋 **Status:** Specified, not yet implemented. The placeholder lives at `python/steg.py`. See [DEPLOYMENT.md 2.6](DEPLOYMENT.md) for the implementation plan.

---

## 7. Security Comparison Matrix

| Threat Vector | Traditional System | VAJRA Architecture |
| :--- | :--- | :--- |
| **Admin Pre-Leak** | Possible (Admin has full access) | **Bounded** (Admin destroys $p, q$ at lock time; $K$ recoverable only via sequential squaring that completes at T=0) |
| **Server Hack** | Single point of failure | **Mitigated** (Decentralized IPFS + per-centre encryption — even all shards together are useless without ≥k privkeys) |
| **Transit Theft** | Physical hijacking of papers | **Irrelevant** (Nothing transits in plaintext; ciphertext-only on IPFS) |
| **Clock Manipulation** | Not applicable | **Cryptographically Bound** (drand AAD + multi-relay agreement) |
| **Photo Leak (post-decrypt)** | Hard to trace | **Instantly Traceable** (Forensic watermarking — *planned*) |
| **Inside Job (Single Centre)** | Catastrophic (one bribe leaks paper) | **Bounded** (One centre = one share = zero information about data_key) |
| **Coordinated Inside Job (≥k Centres)** | Catastrophic | **Detectable & Configurable** (Set $k$ high; cooperation across diverse jurisdictions; audit trail visible on-chain via drand) |
| **Manifest Tampering** | Not applicable | **Cryptographically Caught** (HMAC + AAD binding) |

---

## 8. Future Roadmap

### Phase 1: Hardened Time Anchor (Highest Priority)
* **Timelock Encryption (TLE)** against drand using Boneh-Franklin identity-based encryption with the drand chain pubkey as master public key. This closes the upper-bound timing gap — decryption becomes *mathematically* impossible before the target drand round publishes, not just policy-refused.
* Estimated effort: 1-2 weeks integration + 1 week testing. See [DEPLOYMENT.md 2.2](DEPLOYMENT.md).

### Phase 2: Production Cryptography
* **Migrate to 2048-bit RSA primes** (from current 1024-bit) for the RSW puzzle. The current parameters are prototype-grade; production requires ≥2048-bit moduli.
* **Replace HMAC with Ed25519** for manifest signing, so verification requires no shared secret.
* **Sign the centres registry** with an offline Ed25519 key to prevent pubkey substitution attacks at the registry level.

### Phase 3: Hardware-Secured Key Custody
* **Centre-side:** YubiKey or equivalent smartcard holding the X25519 private key on-device. Decryption operations happen inside the token; the key never enters host memory.
* **Admin-side:** HSM custody of the manifest signing key.
* **Estimated cost** at national scale (~5,000 centres): ₹2.25 crore in YubiKey hardware — a rounding error against the cost of one cancelled exam cycle.

### Phase 4: Forensic Watermarking
* Implementation of the LSB/frequency-domain watermarking described in 6.4.
* Integration point already exists at `python/steg.py`.
* Estimated effort: ~1 week.

### Phase 5: Secure Multi-Party Coordinator
* Replace the current Shamir-combine-on-coordinator step with **secure multi-party computation** (MPC) so no single machine ever holds all $k$ plaintext shares simultaneously.
* Lower-effort intermediate: run the coordinator inside a **Trusted Execution Environment** (Intel SGX, AMD SEV, AWS Nitro Enclaves).

### Phase 6: Real-World Pilot
* Single-exam pilot on a mid-stakes state recruitment exam (~50,000 candidates, ~50 centres).
* Independent third-party cryptographic audit.
* Operational ceremony rehearsals with the participating examination authority.

A complete gap analysis between the current prototype and production deployment is in **[DEPLOYMENT.md](DEPLOYMENT.md)**. A rigorous technical reference for cryptographers and security engineers is in **[ARCHITECTURE.md](ARCHITECTURE.md)**.

---

## 9. What This Is, and What It Is Not

**This is a working prototype.** Every component described above is real, runs end-to-end, and is independently testable. The cryptographic primitives are well-known and well-audited. The system has been validated locking and unlocking real PDFs with byte-for-byte recovery.

**This is not a deployed product.** Production use would require all of Phase 1-3 above, plus a formal third-party security audit, plus operational integration with existing examination infrastructure. The purpose of this work is to demonstrate that the cryptographic infrastructure for tamper-evident, leak-proof examination distribution exists and is feasible — not to be used in a live examination tomorrow.

**The conversation we want to start** is whether examination integrity should depend on procedural trust at all, when the mathematics to remove that dependency is now within reach.

---

*Document Version: 2.0.0*
*Status: Architecture — current to manifest v1.3*
*See also: [README.md](../README.md) · [ARCHITECTURE.md](ARCHITECTURE.md) · [DEPLOYMENT.md](DEPLOYMENT.md)*
