/// puzzle.rs — RSW Time-Lock Puzzle core logic
///
/// The security model in one paragraph:
///   The admin generates N = p*q and picks a random base g.
///   Using the shortcut e = 2^T_ops mod φ(N), the admin computes K = g^e mod N instantly.
///   K encrypts the exam. p, q, and φ(N) are then destroyed.
///   The only way to recover K is to square g sequentially T_ops times — which takes exactly T seconds.
///   No parallelism helps; this is provably sequential.

use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::Instant;

// ─── Data Structures ────────────────────────────────────────────────────────

/// Public parameters — safe to share with every exam center via IPFS or otherwise.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PuzzleParams {
    /// RSA modulus N = p * q, big-endian hex
    pub n: String,
    /// Squaring base g, big-endian hex
    pub g: String,
    /// Exact number of sequential squarings (x = x² mod N) required to recover K
    pub t_ops: u64,
    /// Squarings/sec measured on the admin's machine at generation time.
    /// Centers use this to estimate solve time; they should re-benchmark themselves.
    pub ref_squarings_per_sec: u64,
}

/// Admin secret — holds p and q. MUST be securely deleted after `vajra lock` completes.
/// Anyone who has this file can skip the time-lock entirely.
#[derive(Serialize, Deserialize)]
pub struct AdminSecret {
    /// Prime factor p, big-endian hex
    pub p: String,
    /// Prime factor q, big-endian hex
    pub q: String,
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

fn from_hex(s: &str) -> BigUint {
    BigUint::from_bytes_be(&hex::decode(s).expect("Invalid hex in puzzle file"))
}

fn to_hex(n: &BigUint) -> String {
    hex::encode(n.to_bytes_be())
}

// ─── Primality Testing ───────────────────────────────────────────────────────

/// Miller-Rabin probabilistic primality test.
/// With 25 rounds, the probability of a false positive is < 4^(-25) ≈ 10^(-15).
fn is_probable_prime(n: &BigUint, rounds: u32, rng: &mut impl RngCore) -> bool {
    let zero = BigUint::zero();
    let one = BigUint::one();
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);

    if n < &two   { return false; }
    if n == &two  { return true;  }
    if n == &three{ return true;  }
    if n % &two == zero { return false; }

    // Factor out 2s from n-1 so that: n - 1 = 2^r * d
    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut r = 0u32;
    while &d % &two == zero {
        d >>= 1;
        r += 1;
    }

    'witness: for _ in 0..rounds {
        // Random witness in [2, n-2]
        let a = rng.gen_biguint_range(&two, &(n - &two));
        let mut x = a.modpow(&d, n);

        if x == one || x == n_minus_1 {
            continue 'witness;
        }

        for _ in 0..r - 1 {
            x = (&x * &x) % n;
            if x == n_minus_1 {
                continue 'witness;
            }
        }
        return false; // Composite
    }
    true // Probably prime
}

/// Generate a random probable prime of exactly `bits` bits.
pub fn gen_prime(bits: u64, rng: &mut impl RngCore) -> BigUint {
    let top_bit = BigUint::one() << (bits - 1) as usize;
    loop {
        let mut n = rng.gen_biguint(bits);
        n |= &top_bit;       // Guarantee bit length (set MSB)
        n |= BigUint::one(); // Guarantee odd (set LSB)

        if is_probable_prime(&n, 25, rng) {
            return n;
        }
    }
}

// ─── Benchmarking ────────────────────────────────────────────────────────────

/// Run modular squarings for `duration_ms` milliseconds and return squarings/sec.
/// Uses the same x = x² mod n operation that the solver uses — so the measurement
/// accurately reflects the actual puzzle workload on this hardware.
pub fn benchmark(n: &BigUint, duration_ms: u64) -> u64 {
    let mut x = BigUint::from(3u32); // Non-trivial starting value
    let deadline = Instant::now() + std::time::Duration::from_millis(duration_ms);
    let mut count = 0u64;

    while Instant::now() < deadline {
        x = (&x * &x) % n;
        count += 1;
    }

    let elapsed_secs = duration_ms as f64 / 1000.0;
    (count as f64 / elapsed_secs) as u64
}

// ─── Puzzle Generation ───────────────────────────────────────────────────────

/// Generate puzzle parameters for a target lock duration.
///
/// Returns:
///  - `PuzzleParams`: share this publicly with all exam centers
///  - `AdminSecret`:  keep this secret; DELETE it after running `vajra lock`
pub fn generate(time_seconds: u64) -> (PuzzleParams, AdminSecret) {
    let mut rng = rand::thread_rng();

    // 512 bits each → 1024-bit N. Production should use 1024-bit primes → 2048-bit N.
    println!("[1/3] Generating 512-bit prime p ...");
    let p = gen_prime(512, &mut rng);

    println!("[2/3] Generating 512-bit prime q ...");
    let q = gen_prime(512, &mut rng);

    let n = &p * &q;

    // g must be in (1, N). Use a random value; avoid 1 and N-1 (trivial).
    let g = rng.gen_biguint_range(&BigUint::from(2u32), &(&n - BigUint::from(2u32)));

    println!("[3/3] Benchmarking squarings/sec on this machine (2s sample) ...");
    let sps = benchmark(&n, 2_000);
    println!("      ↳ {sps} squarings/sec");

    // T_ops = how many squarings the center must perform to solve the puzzle.
    // This is calibrated to the admin machine's speed. Centers with different
    // hardware will solve faster or slower — see README for the implication.
    let t_ops = time_seconds.saturating_mul(sps);
    println!("      ↳ T_ops = {t_ops}  ({time_seconds}s × {sps} sq/s)\n");

    let params = PuzzleParams {
        n: to_hex(&n),
        g: to_hex(&g),
        t_ops,
        ref_squarings_per_sec: sps,
    };
    let secret = AdminSecret {
        p: to_hex(&p),
        q: to_hex(&q),
    };

    (params, secret)
}

// ─── Admin Key Derivation (Fast Path) ────────────────────────────────────────

/// Compute K = g^(2^T_ops) mod N using the φ(N) shortcut.
///
/// Math:
///   φ(N) = (p-1)(q-1)
///   e     = 2^T_ops  mod φ(N)   ← fast: O(log T_ops) multiplications
///   K     = g^e      mod N       ← fast: O(log e) multiplications
///
/// Without p and q, this shortcut is impossible; the only option is sequential squaring.
pub fn admin_compute_key(params: &PuzzleParams, secret: &AdminSecret) -> BigUint {
    let n = from_hex(&params.n);
    let g = from_hex(&params.g);
    let p = from_hex(&secret.p);
    let q = from_hex(&secret.q);

    // Euler's totient
    let phi = (&p - BigUint::one()) * (&q - BigUint::one());

    // Fast exponentiation: e = 2^T_ops mod φ(N)
    let e = BigUint::from(2u32).modpow(&BigUint::from(params.t_ops), &phi);

    // Decryption key K
    g.modpow(&e, &n)
}

// ─── Center Solver (Slow Path) ───────────────────────────────────────────────

/// Recover K by performing T_ops sequential squarings: x₀ = g, xᵢ = xᵢ₋₁² mod N.
///
/// This is the ONLY way to compute K without knowing p and q.
/// Cannot be parallelized — each step depends on the previous result.
pub fn solve(params: &PuzzleParams) -> BigUint {
    let n = from_hex(&params.n);
    let g = from_hex(&params.g);
    let total = params.t_ops;

    println!("Starting sequential squaring: {} operations", total);
    println!(
        "Expected duration: ~{}s (based on reference speed of {} sq/s)\n",
        total / params.ref_squarings_per_sec.max(1),
        params.ref_squarings_per_sec
    );

    let mut x = g;
    let start = Instant::now();

    for i in 0..total {
        // The one and only computation: x = x² mod N
        x = (&x * &x) % &n;

        // Progress reporting every 500k iterations
        if i > 0 && i % 500_000 == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            let rate = i as f64 / elapsed;
            let eta = (total - i) as f64 / rate;
            eprint!(
                "\r  {:.1}% | {:.0} sq/s | ETA {:.1}s       ",
                (i as f64 / total as f64) * 100.0,
                rate,
                eta
            );
            let _ = std::io::Write::flush(&mut std::io::stderr());
        }
    }

    let total_secs = start.elapsed().as_secs_f64();
    eprintln!("\r  100.0% | Done in {total_secs:.2}s                        ");

    x
}
