/// crypto.rs — Symmetric encryption layer
///
/// Once the time-lock is solved (or bypassed by the admin), the resulting BigUint K
/// is run through SHA-256 to produce a 256-bit AES key. The exam payload is then
/// encrypted/decrypted with AES-256-GCM (authenticated, so tampering is detectable).

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use num_bigint::BigUint;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ─── Data Structures ────────────────────────────────────────────────────────

/// The locked exam file — safe to distribute publicly.
/// Without K (which requires solving the time-lock), this is computationally opaque.
#[derive(Serialize, Deserialize)]
pub struct LockedPayload {
    /// Random 12-byte AES-GCM nonce, hex encoded
    pub nonce: String,
    /// Ciphertext + 16-byte GCM authentication tag, hex encoded
    pub ciphertext: String,
}

// ─── Key Derivation ──────────────────────────────────────────────────────────

/// Derive a 32-byte AES key from BigUint K via SHA-256.
///
/// K is a 1024-bit number; we hash it to get a fixed 256-bit key.
/// SHA-256 also provides domain separation — even if K is partially predictable,
/// the key is uniform.
fn derive_aes_key(k: &BigUint) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(k.to_bytes_be());
    hasher.finalize().into()
}

// ─── Encrypt / Decrypt ───────────────────────────────────────────────────────

/// Encrypt `plaintext` using AES-256-GCM with a key derived from K.
///
/// A fresh random 96-bit nonce is generated for every call.
/// The GCM authentication tag (appended to ciphertext) ensures any tampering
/// is caught during decryption — even one flipped bit causes failure.
pub fn encrypt(k: &BigUint, plaintext: &[u8]) -> LockedPayload {
    let key_bytes = derive_aes_key(k);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .expect("Key is always 32 bytes; this cannot fail");

    // Fresh random nonce per encryption (never reuse a nonce with the same key)
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("AES-GCM encryption failed — this should not happen");

    LockedPayload {
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    }
}

/// Decrypt a `LockedPayload` using AES-256-GCM with a key derived from K.
///
/// Returns `Err` if:
///  - The key is wrong (wrong K → decryption key mismatch)
///  - The ciphertext was tampered with (GCM auth tag fails)
///  - The nonce or ciphertext hex is malformed
pub fn decrypt(k: &BigUint, locked: &LockedPayload) -> Result<Vec<u8>, String> {
    let key_bytes = derive_aes_key(k);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .expect("Key is always 32 bytes");

    let nonce_bytes = hex::decode(&locked.nonce)
        .map_err(|e| format!("Bad nonce hex: {e}"))?;
    if nonce_bytes.len() != 12 {
        return Err(format!("Nonce must be 12 bytes, got {}", nonce_bytes.len()));
    }

    let ciphertext = hex::decode(&locked.ciphertext)
        .map_err(|e| format!("Bad ciphertext hex: {e}"))?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| {
            "Decryption failed — the time-lock key is incorrect, or the \
             ciphertext has been tampered with."
                .to_string()
        })
}
