use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const BIN: &str = env!("CARGO_BIN_EXE_vajra");
const AAD: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nonce: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let dir =
            std::env::temp_dir().join(format!("vajra_cli_{tag}_{}_{nonce:x}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to start vajra")
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// Generate a 1-second puzzle and lock `exam` with AAD; returns (puzzle, locked).
fn generate_and_lock(dir: &TempDir, exam: &[u8]) -> (PathBuf, PathBuf) {
    let puzzle = dir.path("puzzle.json");
    let secret = dir.path("secret.json");
    let input = dir.path("exam.pdf");
    let locked = dir.path("locked.json");
    fs::write(&input, exam).unwrap();

    let out = run(&[
        "generate",
        "--time",
        "1",
        "--puzzle-out",
        s(&puzzle),
        "--secret-out",
        s(&secret),
    ]);
    assert!(
        out.status.success(),
        "generate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = run(&[
        "lock",
        "--puzzle",
        s(&puzzle),
        "--secret",
        s(&secret),
        "--input",
        s(&input),
        "--output",
        s(&locked),
        "--aad-hex",
        AAD,
    ]);
    assert!(
        out.status.success(),
        "lock failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (puzzle, locked)
}

#[test]
fn generate_lock_solve_round_trip() {
    let dir = TempDir::new("roundtrip");
    let exam = b"%PDF-1.4\nexam body\n%%EOF".to_vec();
    let (puzzle, locked) = generate_and_lock(&dir, &exam);

    let params: serde_json::Value = serde_json::from_slice(&fs::read(&puzzle).unwrap()).unwrap();
    assert!(params["t_ops"].as_u64().unwrap() > 0);
    assert!(params["ref_squarings_per_sec"].as_u64().unwrap() > 0);

    let output = dir.path("solved.pdf");
    let out = run(&[
        "solve",
        "--puzzle",
        s(&puzzle),
        "--locked",
        s(&locked),
        "--output",
        s(&output),
        "--aad-hex",
        AAD,
    ]);
    assert!(
        out.status.success(),
        "solve failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read(&output).unwrap(), exam);
}

#[test]
fn solve_rejects_wrong_aad_and_tampering() {
    let dir = TempDir::new("reject");
    let (puzzle, locked) = generate_and_lock(&dir, b"%PDF-1.4 reject test");
    let output = dir.path("solved.pdf");

    // Wrong AAD (one bit flipped) and missing AAD.
    let mut wrong = AAD.to_string();
    wrong.replace_range(0..2, "01");
    for aad in [wrong.as_str(), ""] {
        let out = run(&[
            "solve",
            "--puzzle",
            s(&puzzle),
            "--locked",
            s(&locked),
            "--output",
            s(&output),
            "--aad-hex",
            aad,
        ]);
        assert!(!out.status.success(), "solve must fail with AAD {aad:?}");
        assert!(!output.exists(), "no plaintext may be written on failure");
    }

    // Flip one ciphertext byte.
    let mut payload: serde_json::Value =
        serde_json::from_slice(&fs::read(&locked).unwrap()).unwrap();
    let mut ct = hex::decode(payload["ciphertext"].as_str().unwrap()).unwrap();
    ct[0] ^= 0x01;
    payload["ciphertext"] = serde_json::Value::String(hex::encode(ct));
    let tampered = dir.path("tampered.json");
    fs::write(&tampered, serde_json::to_vec(&payload).unwrap()).unwrap();
    let out = run(&[
        "solve",
        "--puzzle",
        s(&puzzle),
        "--locked",
        s(&tampered),
        "--output",
        s(&output),
        "--aad-hex",
        AAD,
    ]);
    assert!(
        !out.status.success(),
        "solve must fail on tampered ciphertext"
    );
    assert!(!output.exists());
}
