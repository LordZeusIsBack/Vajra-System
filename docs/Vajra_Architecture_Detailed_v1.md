# VAJRA: A Zero-Trust Digital Pipeline for High-Stakes Examination Distribution

## 1. Executive Summary
The **VAJRA Architecture** is a decentralized, cryptographically-enforced framework designed to eliminate human-centric vulnerabilities in the high-stakes examination lifecycle (e.g., NEET, JEE). By replacing physical trust with mathematical certainty, VAJRA ensures that exam content is inaccessible to all parties—including administrators—until the exact moment of the examination start.

### The Name: Why "Vajra"?
In Sanskrit, **Vajra** (वज्र) carries a dual meaning:
* **The Diamond:** Symbolizing **indestructibility** and clarity. The encrypted data cannot be "broken" or previewed.
* **The Thunderbolt:** Symbolizing **decisive speed** and irresistible force. Once the time is right, the system delivers the paper instantaneously.

---

## 2. High-Level Architecture
The system is divided into three distinct tiers, ensuring no single point of failure or compromise.

| Tier | Name | Role | Core Technology |
| :--- | :--- | :--- | :--- |
| **Tier 1** | **The Source Vault** | Preparation & Cryptographic Locking | FastAPI, Rust, RSW-Puzzles |
| **Tier 2** | **The Distribution Web** | Sharding & Decentralized Transport | IPFS (InterPlanetary File System) |
| **Tier 3** | **The Edge Sentinel** | Local Decryption & Forensic Tracking | Rust Runtime, OpenCV (Python) |

---

## 3. Tier 1: Ingestion & The "Vajra Lock"

### 3.1. Byte-Level Sharding
Instead of treating the exam as a single file, the Source Vault processes the PDF as a raw byte-stream.
* **Mechanism:** The file is split into $n$ discrete shards ($S_1, S_2, ... S_n$).
* **Redundancy:** Using **Shamir’s Secret Sharing**, the system can be configured such that only a threshold (e.g., 8 out of 10) of shards are required to reconstruct the file, protecting against localized data loss while maintaining security.

### 3.2. The Time-Lock Puzzle (RSW-96 Logic)
The core of the system is the **Rivest-Shamir-Wagner (RSW)** time-lock puzzle. This prevents "early leaks" by forcing the computer to perform a sequential calculation that cannot be parallelized.

**The Math of the Lock:**
1.  **Setup:** The administrator generates two large secret primes $p$ and $q$ and calculates $N = p \times q$.
2.  **Complexity Calculation:** Let $T$ be the time until the exam. Let $S$ be the number of squaring operations a standard CPU can perform per second. Total operations $T_{ops} = T \times S$.
3.  **The Shortcut (Admin only):** The admin uses $\phi(N) = (p-1)(q-1)$ to calculate:
    $$e = 2^{T_{ops}} \pmod{\phi(N)}$$
    $$K = g^e \pmod N$$
    *Where $K$ is the decryption key.*
4.  **The Lock:** The admin discards $p, q,$ and $\phi(N)$. The only way to find $K$ now is to start with $g$ and square it $T_{ops}$ times.

---

## 4. Tier 2: The Distribution (IPFS & Immutability)

### 4.1. Decentralized Transport via IPFS
To prevent a central server hack, the encrypted shards are uploaded to **IPFS**. 
* **Content Addressing:** Files are stored based on their **CID (Content Identifier)**—a cryptographic hash of the content.
* **Zero-Trust Retrieval:** The Local Centers do not "download a file"; they "request a CID."

### 4.2. Immutability & Rejection Logic
* **The CID Rule:** If a single bit of the encrypted exam paper is altered (e.g., a hacker tries to inject a fake question), the CID changes entirely.
* **Integrity Enforcement:** The Local Sentinel is programmed to *only* accept the CID signed by the Master Authority. If the hashes don't match, the system rejects the data, preventing the "tampered paper" leak vector.

---

## 5. Tier 3: The Edge Sentinel (Execution)

### 5.1. The Rust Runtime
The local exam hall runs a **Rust-based CLI**. Rust is chosen for:
* **Performance:** Solving the Time-Lock puzzle requires maximum CPU efficiency.
* **Memory Safety:** Eliminates common vulnerabilities (buffer overflows) that could be used to extract the key from memory during computation.

### 5.2. Sequential Squaring Execution
At exactly $T=0$ (e.g., 10:00 AM), the Rust CLI begins the $T_{ops}$ calculations. 
* **No Shortcut:** Because the local machine does not know $\phi(N)$, it must perform the work. 
* **Hardware Binding:** The calculation can be bound to the local machine's UUID, ensuring that a "pre-solved" key cannot be copied from one center to another.

### 5.3. Dynamic Forensic Watermarking (Steganography)
Once the PDF is decrypted for display or printing, the **Sentinel** applies a forensic layer.
* **Hidden Data:** Using LSB (Least Significant Bit) steganography or frequency-domain watermarking via **OpenCV**.
* **The Payload:** The watermark embeds the **Center ID, Room Number, and Timestamp** into the background of the PDF.
* **Leak Detection:** If a proctor or student takes a physical photograph and shares it on social media, a simple scan of the image reveals exactly which center and room the leak originated from.

---

## 6. Security Comparison Matrix

| Threat Vector | Traditional System | VAJRA Architecture |
| :--- | :--- | :--- |
| **Admin Leak** | Possible (Admin has access) | **Impossible** (Time-locked math) |
| **Server Hack** | Single Point of Failure | **Mitigated** (Decentralized IPFS) |
| **Transit Theft** | Physical hijacking of papers | **Irrelevant** (Data is encrypted shards) |
| **Photo Leak** | Hard to trace | **Instantly Traceable** (Watermarking) |
| **Inside Job** | Bribery of transport officials | **Nulled** (Human presence is irrelevant) |

---

## 7. Future Roadmap
* **Phase 1:** Rust-based Time-Lock CLI implementation.
* **Phase 2:** IPFS integration for decentralized shard hosting.
* **Phase 3:** AI-based anomaly detection for proctoring screens.

---
*Document Version: 1.0.0*
*Status: Architecture Prototype*
