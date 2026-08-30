# Deployment Considerations

_A gap analysis between the current VAJRA prototype and what would be
required for use in a live high-stakes examination._

This document is explicitly aspirational. None of what follows has been
done. It is included because (a) examination boards considering this
work deserve a clear-eyed view of what production would entail, and (b)
the gaps are themselves part of the technical story — they describe
where the next research and engineering effort should go.

If you are looking for a deployment runbook for the current prototype,
you will not find one here. The current code is fit for demonstration
and audit, not for live examinations. That statement holds even if all
components individually pass their tests.

---

## 1. The fundamental question

Should examination integrity depend on procedural trust at all, when
the cryptographic infrastructure to remove that dependency exists?

VAJRA's claim is that the answer should be: **only where cryptography
genuinely cannot help.** The decryption of an exam paper before T=0 is
a problem cryptography can address completely. The integrity of the
exam _centre_ during the exam — proctoring, identification, copying —
is largely outside cryptography's reach.

Production deployment of VAJRA would therefore mean:

1. **Cryptographic distribution**, fully replacing physical printing
   and sealed-trunk transport.
2. **Hardware-secured key custody** at each centre.
3. **Operational ceremony** rehearsed between the examining body and
   the regional centres, with clear roles and failure procedures.
4. **Forensic watermarking** for the post-T=0 attack surface
   (photographs, etc.) — currently unimplemented.

The remainder of this document expands each of these.

## 2. What the prototype does _not_ yet do

A complete list of known gaps. Each is sized and prioritised.

### 2.1. Cryptographic parameter sizes — **must fix**

| Parameter                         | Prototype          | Production target                       |
| --------------------------------- | ------------------ | --------------------------------------- |
| RSW prime size                    | 512 bits each      | ≥ 1024 bits each                        |
| RSW modulus _N_                   | 1024 bits          | ≥ 2048 bits                             |
| Number of cooperating centres _k_ | demo-only (3-of-5) | 30-of-50 or higher, per regional layout |

1024-bit _N_ is acceptable for a prototype. It is _not_ acceptable for
a national-scale exam — it is within the range of nation-state factoring
capability and would not be defensible if challenged. 2048-bit is the
minimum starting point; current cryptographic recommendation is 3072-bit
or larger for material that must remain confidential for years.

**Effort:** trivial code change — `gen_prime(1024, …)` in
`puzzle.rs::generate`. Increases generation time from ~2 seconds to
roughly 30 seconds, and solve time scales linearly. No security analysis
needed; this is just running the existing code at production parameters.

### 2.2. Timelock encryption against drand — **biggest missing piece**

The current drand integration uses the beacon for two purposes:

- **AAD binding** (cryptographic): the manifest's target_round is welded
  to the AES-GCM authentication tag. An attacker cannot silently change
  which round was used.
- **Policy gate** (operational): the coordinator script refuses to run
  the time-lock if the local clock or relays indicate the round hasn't
  published.

But the policy gate is, literally, a script. A determined attacker with
the manifest, _k_ centre privkeys, and `puzzle.json` can run `vajra
solve` directly, bypass the gate, and decrypt early.

The fix is **timelock encryption (TLE)**: a Boneh–Franklin
identity-based encryption scheme using the drand chain's BLS public key
as the master public key, and a future round number as the encryption
identity. The decryption key for round _R_ is exactly the drand
signature at round _R_, which is mathematically impossible to compute
before the beacon emits it. This construction is implemented in the
reference `drand-tlock` library (Go) and has Rust and Python ports.

**What this would change in VAJRA.** Instead of (or in addition to) the
RSW time-lock, the inner AES-GCM key would be TLE-encrypted to the
target round. The administrator could not decrypt early because the
required signature does not yet exist. The drand network — operated by
multiple independent organisations under a threshold scheme — is the
only entity that can produce it, and only at the scheduled time.

The RSW puzzle could be kept as a defence-in-depth layer (in case drand
were ever compromised) or replaced entirely. Likely both have value.

**Effort:** significant. TLE has Python implementations (e.g.
`drand-tlock` ports) but VAJRA's lock and unlock pipelines would need
restructuring. Estimate: 1-2 weeks for an implementation + 1 week for
testing against the live drand chain.

**This is the highest priority production upgrade.** It is what would
elevate VAJRA from "cryptographic policy enforcement" to "cryptographic
time enforcement."

### 2.3. Manifest signature — **easy, must fix**

The current manifest is HMAC-SHA256-signed. Verification requires the
symmetric key `MANIFEST_HMAC_SECRET`, which means the secret has to be
distributed to every party that needs to verify (every centre, every
auditor, every journalist who wants to check). That is operationally
impractical and security-theatre-adjacent.

The fix is straightforward: replace HMAC with **Ed25519** signatures.
The administrator holds the signing key; everyone else holds only the
public key. Anyone can verify a manifest without holding any secret.

**Effort:** ~half a day. The signing/verifying code is a 10-line swap
in `manifest.py`. The harder part is operational: where does the
Ed25519 signing key live? It should be in an HSM that the administrator
accesses only at lock-time and never exposes to network-connected
systems.

### 2.4. Secure multi-party Shamir combine — **medium effort, high impact**

At the moment of reconstruction, the coordinator process holds all _k_
plaintext Shamir shares simultaneously. An attacker who compromises the
coordinator at that instant recovers `data_key` and can decrypt the
payload (given that the time-lock has separately resolved).

This is the **single most sensitive moment** in the entire system.

The fix is well-known cryptographically but non-trivial operationally:
**secure multi-party computation** (MPC) so the Lagrange interpolation
happens without any single party holding all shares. There are several
candidate protocols (BGW, SPDZ, semi-honest 2PC if you split the
coordinator into two non-colluding machines).

For VAJRA specifically, a much simpler partial fix is plausible:
require the coordinator to run inside a **Trusted Execution Environment**
(Intel SGX, AMD SEV, AWS Nitro Enclaves) so the shares are visible only
inside hardware-enforced memory protection. This is less rigorous than
full MPC but materially raises the bar against software-only attackers.

**Effort:** if going the TEE route, ~1 week of integration plus
attestation infrastructure. If going the full MPC route, ~1-3 months
depending on protocol choice.

### 2.5. Centre key custody — **must fix**

The prototype stores centre private keys as plain JSON files
(`CENTER_000.json` containing `{id, pubkey, privkey}`). For an exam
demo this is fine. For a real centre, this is unacceptable: laptop
theft, disgruntled IT staff, ransomware all trivially exfiltrate the
key.

Production requires **hardware-secured key custody**. Options:

- **YubiKey or similar smartcard** holding the X25519 key; decryption
  operations happen on the device, never extract the key to host
  memory.
- **TPM 2.0** with a sealed key bound to platform configuration
  registers (PCRs); key only unsealable if the boot chain has not
  been tampered with.
- **Dedicated HSM appliance** (Thales, AWS CloudHSM, etc.) for the
  most stringent environments.

YubiKey is the most pragmatic starting point: ~₹4,500 per device,
mature ecosystem, no infrastructure to maintain. For 5,000 centres
that's ~₹2.25 crore — a rounding error against the cost of cancelled
exam cycles.

**Effort:** the cryptography library already supports X25519 via PKCS#11
interfaces with minor changes. Operational rollout (key generation
ceremony, lost-device procedures, key rotation between exams) is the
harder problem and requires policy work, not code.

### 2.6. Forensic watermarking — **scope-extending but important**

Once VAJRA decrypts the exam paper at a centre, the paper is plaintext.
A proctor or candidate could photograph the secure terminal screen and distribute the image. VAJRA's claim is about pre-T=0 leaks, not
post-T=0 — but a complete examination-integrity story should address
both.

The original architecture document specifies LSB / frequency-domain
steganography embedding centre ID, room number, and timestamp into the
rendered PDF. A photographed page would reveal, by simple decoding of the embedded watermark, exactly which centre and room the photo originated from. This makes attribution near-instant and shifts the
operational economics of post-T=0 leaks dramatically.

**Effort:** ~1 week. Open-source implementations of robust image
watermarking exist (e.g. `pdf-watermark`, OpenCV's frequency-domain
techniques). The integration point is between `coordinator combine`
finishing and the exam being displayed on a secure CBT terminal — `python/steg.py` already marks the location.

### 2.7. Registry signing — **easy, should fix**

`centers.json` is the integrity-critical mapping from centre IDs to
their X25519 pubkeys. If an attacker can replace a centre's pubkey
before lock-time (e.g. by tampering with the file on the
administrator's filesystem), they can have that centre's shard
encrypted to _their own_ key. They then decrypt that shard at T=0
without needing the legitimate centre's cooperation.

The fix is to sign the registry with an offline admin key (Ed25519,
held in an HSM, used only for registry signing) and have the FastAPI
server refuse to load an unsigned or invalid-signature registry.

**Effort:** ~3 hours. Combines naturally with § 2.3 (manifest
signing) since both want the same kind of offline signing key.

### 2.8. Multi-region IPFS pinning — **operational**

The prototype uses a configurable list of Kubo nodes. A real
deployment would need:

- **Geographic distribution** of pinning services so a regional
  network outage doesn't render the exam undecryptable.
- **Pinning service redundancy** beyond Kubo (Pinata, Filebase,
  Web3.Storage) so a single provider's failure isn't catastrophic.
- **Mirror gateway redundancy** so centres can fetch CIDs via
  multiple HTTP gateways if their local Kubo node is unreachable.

This is straightforward operationally; the code already supports
multiple node URLs. Production would just configure more of them
and use a managed pinning service rather than running Kubo directly.

### 2.9. Audit trail and timestamping — **policy decision**

Every step in the lock pipeline currently emits structured log lines
via Python `logging`. Production should:

- Stream these to a tamper-evident log (Loki, immudb, or a
  blockchain-backed audit log) so logs cannot be retroactively
  altered to hide a breach.
- Cryptographically timestamp each operation (RFC 3161, or use the
  drand beacon itself as a timestamping authority).
- Publish the manifest CID via official channels (e.g. publish to a
  government gazette, post to an official social-media account, embed
  in candidates' admit cards as a QR code) so the binding between
  manifest and exam is publicly verifiable.

**Effort:** mostly policy. The technical pieces are well-understood.

### 2.10. Performance characterisation — **must do before any deployment**

The prototype's time-lock is calibrated to the administrator's hardware
via a 2-second benchmark. For a production exam, the squaring rate
across the fleet of regional centres must be characterised carefully:

- **Worst-case CPU** in the fleet defines the minimum _T_ops_ (so
  that the slowest centre still finishes by T=0).
- **Best-case CPU** in the fleet defines the maximum acceptable
  earliness (the fastest centre will finish first; the gap between
  the two extremes is the operational uncertainty window).

For a national-scale fleet, this gap could easily be 30-60 seconds.
That is manageable but requires the lock to be set with a deliberate
margin. With TLE (§ 2.2), this concern disappears — drand publish
time is uniform globally.

**Effort:** ~1 week of empirical benchmarking across the centre fleet
once it exists. Cannot be done without access to actual centre
hardware.

## 3. What deployment would actually look like

Sketching a realistic deployment trajectory:

### Phase 1 — Single-exam pilot (3-6 months)

- Run VAJRA end-to-end on **one mid-stakes exam** — perhaps a state
  recruitment exam with 50,000 candidates and 50 centres, where the
  consequences of a technical failure are recoverable.
- All gaps in § 2 that are marked "must fix" are addressed first.
- TLE (§ 2.2) is in place.
- Hardware key custody (§ 2.5) is in place at every participating
  centre.
- A formal cryptographic audit by an independent third party precedes
  the pilot.

### Phase 2 — Multiple-exam validation (1-2 years)

- Successful Phase 1 pilots roll out to additional state exams.
- Forensic watermarking (§ 2.6) is added.
- MPC or TEE coordinator (§ 2.4) is added.
- Operational ceremonies are codified into documented procedures with
  rehearsals, failure drills, and clear roles.

### Phase 3 — National-scale exams (3+ years)

- Only after sustained operational track record from Phase 2.
- Includes NEET, UPSC CSE, SSC. At this scale, the cost-benefit
  calculation shifts: the cost of cryptographic infrastructure (HSMs,
  pinning services, MPC) is dwarfed by the cost of a single cancelled
  exam cycle.

This trajectory is not a roadmap VAJRA's author is positioned to
execute alone. It requires partnership with examination authorities,
regional centres, security auditors, and policymakers.

## 4. Key custody — operational specifics

Because § 2.5 is the most operationally complex item, a few additional
notes on what "production key custody" actually means.

### 4.1. Centre side

Each centre would hold its X25519 private key in a hardware token
(YubiKey, or equivalent). The keypair-generation ceremony would
happen once per centre, locally, with the centre's IT staff
performing the steps under recorded video. The token never leaves
the centre; it is stored in a locked safe between exams.

The centre's decryption operation (`vajra_center decrypt-share`)
becomes:

1. Plug in the YubiKey.
2. Enter the unlock PIN (configurable retry-lockout).
3. The CLI sends the encrypted shard to the YubiKey, which performs
   the X25519 + ChaCha20-Poly1305 decryption on-device.
4. The plaintext share comes back to the CLI, never having been in
   software-accessible memory in private-key-extractable form.

### 4.2. Administrator side

The administrator's Ed25519 signing key (used for manifest and
registry signatures, § 2.3 and § 2.7) lives in an offline HSM, used
only during lock-time ceremonies. Each ceremony is recorded; the
recording, the CID, and the HSM access log all jointly form an audit
trail.

The RSW-puzzle generation in `vajra generate` should ideally happen
inside an attested enclave so the prime factors (_p_, _q_) cannot be
exfiltrated even by a compromised administrator workstation. This is
less critical than the centre-side key custody (because the
administrator's secrets are destroyed immediately after lock) but
still worth doing.

### 4.3. Key rotation

X25519 keypairs should be rotated **between exams** at minimum.
This means each exam cycle has a fresh registry. The cost is one
registration ceremony per centre per exam, which at ~10 minutes per
centre is operationally manageable.

Rotation has a strong security property: the compromise of a
centre's key after one exam does not affect any subsequent exam.

## 5. Cost estimate

Highly approximate, for context only. Assumes a 5,000-centre national
fleet.

| Item                                         | Capex (one-time) | Opex (per exam)            |
| -------------------------------------------- | ---------------- | -------------------------- |
| YubiKeys, 5,000 × ₹4,500                     | ₹2.25 crore      | —                          |
| Centre training, 5,000 centres × 1 hour      | —                | ₹50 lakh                   |
| HSM appliance (admin signing)                | ₹15 lakh         | ₹2 lakh maintenance        |
| Pinning service (managed IPFS, multi-region) | —                | ₹3-5 lakh                  |
| Third-party cryptographic audit              | —                | ₹15-30 lakh per major exam |
| TLE integration + ongoing engineering        | ₹40-60 lakh      | ₹20 lakh / year            |
| Forensic watermarking implementation         | ₹15 lakh         | —                          |
| **Approximate totals**                       | **₹3-4 crore**   | **₹20-30 lakh / exam**     |

For comparison, the operational cost of a major paper leak — running
a re-examination cycle for 24 lakh candidates — has been estimated
in published reporting to be ₹500-1500 crore in direct examination
costs, plus the diffuse economic cost of a year of lost preparation
across millions of candidates.

The cryptographic infrastructure is one to two orders of magnitude
cheaper than a single avoided leak.

## 6. Failure modes worth thinking through

What goes wrong, and what happens when it does:

| Failure                                             | Likelihood                                                | Severity                            | Mitigation                                                                                             |
| --------------------------------------------------- | --------------------------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------ |
| One centre's YubiKey is lost or fails               | Low                                                       | Low (drop to _k_+1 of *n*−1)        | Maintain _n_ ≫ _k_ margin.                                                                             |
| One IPFS node goes offline mid-exam                 | Medium                                                    | Low (other nodes serve the content) | Multi-provider pinning.                                                                                |
| Drand chain has an outage at T=0                    | Very low                                                  | High (cannot decrypt)               | Fall back to RSW-only mode if drand is unreachable for > N minutes (operational policy).               |
| Bug in cryptographic code                           | Low if audited                                            | Catastrophic                        | Independent audit; bug-bounty programme.                                                               |
| Centre staff under coercion at T=0                  | Medium (threshold protects against few; not against many) | Depends on _k_                      | Set _k_ high. Make threshold breach require coordinated effort across diverse jurisdictions/operators. |
| The administrator's signing HSM is compromised      | Very low                                                  | Catastrophic (forged manifests)     | Two-person HSM access; HSM hardware tamper evidence.                                                   |
| The drand chain's threshold signers are compromised | Astronomically low                                        | Catastrophic                        | Diversify: use multiple drand chains if available; consider TLE against more than one chain.           |

Several of these collapse to the same answer: **set _k_ and _n_
generously, use defense in depth, and maintain operational
diversity.** These are exam-board policy choices, not cryptographic
ones, and they should be made deliberately rather than defaulted.

## 7. What is not yet known

Honest list of open questions:

1. **At-scale performance.** The prototype has been tested with
   _n_ = 10 centres and small PDFs. Behaviour at _n_ = 5000 is
   extrapolation, not measurement.
2. **Network behaviour during national-scale concurrent reconstruction.**
   When 5000 centres simultaneously fetch from IPFS at T=0, what
   happens? Probably fine — IPFS is content-addressed and caches —
   but it has not been tested.
3. **Legal status.** Where does cryptographic decryption fit in
   the regulatory framework of "official examination conduct"?
   Established examination law assumes paper. Updating that framework
   is a policy problem outside this document's scope.
4. **Edge cases in the reconstruction ceremony.** What if a centre
   submits a malformed share? What if two centres disagree about
   which manifest CID is the right one? Some of these are addressed
   in the current code (the coordinator rejects malformed shares);
   others would emerge only under operational stress.
5. **Compatibility with existing examination management systems.**
   NTA, UPSC, and SSC each have their own software. Integration
   points need to be identified.

---

## 8. The honest summary

VAJRA is **technically feasible** as a national-scale exam
distribution system. The cryptographic primitives are mature and
well-audited. The composition is novel but its security properties
follow from standard arguments.

The work to move from prototype to deployment is substantial but
finite: well-understood engineering on top of well-understood
cryptography. It is not a research project; it is a production
engineering project.

What it requires from the world that exists outside this repository
is partnership — examination authorities willing to pilot, regional
centres willing to take key custody seriously, auditors willing to
review, and policymakers willing to update the regulatory framework
to accommodate cryptographic distribution alongside (or instead of)
physical printing.

The author of this prototype welcomes that conversation.
