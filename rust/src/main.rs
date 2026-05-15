/// main.rs — VAJRA CLI entry point
///
/// Three commands mirror the three roles in the exam lifecycle:
///
///   vajra generate  →  Admin creates the puzzle + secret files
///   vajra lock      →  Admin encrypts the exam (then destroys the secret)
///   vajra solve     →  Center runs the time-lock, decrypts the exam at T=0
///   vajra bench     →  Utility: measure this machine's squarings/sec

mod crypto;
mod puzzle;

use clap::{Parser, Subcommand};
use std::{fs, path::PathBuf};

// ─── CLI Definition ──────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "vajra",
    about = "VAJRA — Zero-Trust Time-Lock CLI for exam distribution",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// [ADMIN] Step 1: Generate time-lock puzzle parameters + admin secret
    ///
    /// Outputs two files:
    ///   puzzle.json  — public, distribute to all exam centers + upload to IPFS
    ///   secret.json  — PRIVATE, contains p and q. DELETE after running `lock`.
    Generate {
        /// Seconds from now until the exam starts (controls puzzle difficulty)
        #[arg(short, long, value_name = "SECONDS")]
        time: u64,

        /// Where to write the public puzzle parameters
        #[arg(long, default_value = "puzzle.json", value_name = "FILE")]
        puzzle_out: PathBuf,

        /// Where to write the admin secret (p, q) — delete after locking!
        #[arg(long, default_value = "secret.json", value_name = "FILE")]
        secret_out: PathBuf,
    },

    /// [ADMIN] Step 2: Encrypt the exam using the admin shortcut (fast)
    ///
    /// The admin computes K instantly via the φ(N) shortcut, encrypts the exam,
    /// and outputs a locked file. Once done, secret.json MUST be securely deleted.
    Lock {
        /// Public puzzle parameters (from `generate`)
        #[arg(long, default_value = "puzzle.json", value_name = "FILE")]
        puzzle: PathBuf,

        /// Admin secret file containing p and q (from `generate`)
        #[arg(long, default_value = "secret.json", value_name = "FILE")]
        secret: PathBuf,

        /// Exam file to encrypt (e.g. exam.pdf)
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Output locked file
        #[arg(short, long, default_value = "locked.json", value_name = "FILE")]
        output: PathBuf,
    },

    /// [CENTER] Step 3: Solve the time-lock and decrypt the exam
    ///
    /// Performs T_ops sequential squarings — this takes exactly T seconds.
    /// Run this command at T=0 (exam start time). The exam decrypts when done.
    Solve {
        /// Public puzzle parameters (from `generate`)
        #[arg(long, default_value = "puzzle.json", value_name = "FILE")]
        puzzle: PathBuf,

        /// Locked exam file (from `lock`)
        #[arg(long, default_value = "locked.json", value_name = "FILE")]
        locked: PathBuf,

        /// Where to write the decrypted exam
        #[arg(short, long, default_value = "exam.pdf", value_name = "FILE")]
        output: PathBuf,
    },

    /// [UTILITY] Benchmark this machine's modular squaring speed
    ///
    /// Run this on each exam center machine to understand timing variance.
    /// Compare against `ref_squarings_per_sec` in puzzle.json.
    Bench {
        /// RSA modulus size in bits (use 1024 to match a real puzzle)
        #[arg(long, default_value_t = 1024, value_name = "BITS")]
        bits: u64,

        /// How long to benchmark in seconds
        #[arg(long, default_value_t = 5, value_name = "SECS")]
        duration: u64,
    },
}

// ─── Command Handlers ────────────────────────────────────────────────────────

fn cmd_generate(time: u64, puzzle_out: PathBuf, secret_out: PathBuf) {
    println!("╔══════════════════════════════════════════╗");
    println!("║     VAJRA — Generate Time-Lock Puzzle    ║");
    println!("╚══════════════════════════════════════════╝\n");
    println!("Lock duration: {time}s\n");

    let (params, secret) = puzzle::generate(time);

    // Write public params
    let puzzle_json = serde_json::to_string_pretty(&params)
        .expect("Failed to serialize puzzle params");
    fs::write(&puzzle_out, &puzzle_json)
        .unwrap_or_else(|e| panic!("Cannot write {}: {e}", puzzle_out.display()));
    println!("✓ Puzzle params written to: {}", puzzle_out.display());
    println!("  → Distribute this file to all exam centers and upload to IPFS.\n");

    // Write admin secret
    let secret_json = serde_json::to_string_pretty(&secret)
        .expect("Failed to serialize admin secret");
    fs::write(&secret_out, &secret_json)
        .unwrap_or_else(|e| panic!("Cannot write {}: {e}", secret_out.display()));
    println!("✓ Admin secret written to:  {}", secret_out.display());

    println!("\n┌─────────────────────────────────────────────────────┐");
    println!("│  ⚠  SECURITY WARNING                                │");
    println!("│                                                     │");
    println!("│  secret.json contains p and q.                     │");
    println!("│  Anyone with this file can decrypt the exam NOW.   │");
    println!("│                                                     │");
    println!("│  DELETE it immediately after running `vajra lock`. │");
    println!("│  Linux:   shred -u secret.json                     │");
    println!("│  macOS:   rm -P secret.json                        │");
    println!("└─────────────────────────────────────────────────────┘");
}

fn cmd_lock(puzzle: PathBuf, secret: PathBuf, input: PathBuf, output: PathBuf) {
    println!("╔══════════════════════════════════════════╗");
    println!("║       VAJRA — Lock Exam (Admin)          ║");
    println!("╚══════════════════════════════════════════╝\n");

    // Load files
    let params: puzzle::PuzzleParams = load_json(&puzzle, "puzzle params");
    let secret_data: puzzle::AdminSecret = load_json(&secret, "admin secret");
    let plaintext = fs::read(&input)
        .unwrap_or_else(|e| panic!("Cannot read {}: {e}", input.display()));

    println!("Input:  {} ({} bytes)", input.display(), plaintext.len());
    println!("Puzzle: {} squarings required\n", params.t_ops);

    // Admin fast path: compute K using φ(N) shortcut
    println!("Computing K via φ(N) shortcut (fast) ...");
    let k = puzzle::admin_compute_key(&params, &secret_data);
    println!("✓ K computed\n");

    // Encrypt
    println!("Encrypting with AES-256-GCM ...");
    let locked = crypto::encrypt(&k, &plaintext);
    let locked_json = serde_json::to_string_pretty(&locked)
        .expect("Failed to serialize locked payload");
    fs::write(&output, &locked_json)
        .unwrap_or_else(|e| panic!("Cannot write {}: {e}", output.display()));

    println!("✓ Locked exam written to: {}\n", output.display());
    println!("┌──────────────────────────────────────────────────────┐");
    println!("│  ⚠  NEXT STEP — CRITICAL                            │");
    println!("│                                                      │");
    println!("│  The exam is now locked. You MUST securely delete   │");
    println!("│  the admin secret file:                             │");
    println!("│                                                      │");
    println!("│  Linux:   shred -u {}   │", secret.display());
    println!("│  macOS:   rm -P {}      │", secret.display());
    println!("│                                                      │");
    println!("│  After deletion, K is unrecoverable until T=0.     │");
    println!("└──────────────────────────────────────────────────────┘");
}

fn cmd_solve(puzzle: PathBuf, locked: PathBuf, output: PathBuf) {
    println!("╔══════════════════════════════════════════╗");
    println!("║     VAJRA — Solve & Decrypt (Center)     ║");
    println!("╚══════════════════════════════════════════╝\n");

    let params: puzzle::PuzzleParams = load_json(&puzzle, "puzzle params");
    let locked_data: crypto::LockedPayload = load_json(&locked, "locked exam");

    // Slow path: sequential squaring
    let k = puzzle::solve(&params);

    // Decrypt
    println!("Decrypting exam ...");
    match crypto::decrypt(&k, &locked_data) {
        Ok(plaintext) => {
            fs::write(&output, &plaintext)
                .unwrap_or_else(|e| panic!("Cannot write {}: {e}", output.display()));
            println!("✓ Exam decrypted and saved to: {}", output.display());
            println!("  → {} bytes", plaintext.len());
        }
        Err(e) => {
            eprintln!("\n✗ Decryption failed: {e}");
            eprintln!("  This should not happen if puzzle.json and locked.json are untampered.");
            std::process::exit(1);
        }
    }
}

fn cmd_bench(bits: u64, duration: u64) {
    println!("╔══════════════════════════════════════════╗");
    println!("║         VAJRA — Hardware Benchmark       ║");
    println!("╚══════════════════════════════════════════╝\n");

    println!("Generating a {bits}-bit test modulus ...");
    let mut rng = rand::thread_rng();
    let p = puzzle::gen_prime(bits / 2, &mut rng);
    let q = puzzle::gen_prime(bits / 2, &mut rng);
    let n = &p * &q;

    println!("Running modular squaring benchmark for {duration}s ...\n");
    let sps = puzzle::benchmark(&n, duration * 1_000);

    println!("┌─────────────────────────────────────────┐");
    println!("│  Result: {sps:>10} squarings / sec      │");
    println!("│  Modulus:    {bits} bits                     │");
    println!("└─────────────────────────────────────────┘");
    println!("\nCompare this against `ref_squarings_per_sec` in puzzle.json.");
    println!("If this machine is faster, the exam will decrypt BEFORE T=0.");
    println!("If slower, it will decrypt AFTER T=0.");
}

// ─── Utility ─────────────────────────────────────────────────────────────────

fn load_json<T: serde::de::DeserializeOwned>(path: &PathBuf, label: &str) -> T {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Cannot read {} file '{}': {e}", label, path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("Cannot parse {} file '{}': {e}", label, path.display()))
}

// ─── Entry Point ─────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Generate { time, puzzle_out, secret_out } => {
            cmd_generate(time, puzzle_out, secret_out);
        }
        Commands::Lock { puzzle, secret, input, output } => {
            cmd_lock(puzzle, secret, input, output);
        }
        Commands::Solve { puzzle, locked, output } => {
            cmd_solve(puzzle, locked, output);
        }
        Commands::Bench { bits, duration } => {
            cmd_bench(bits, duration);
        }
    }
}
