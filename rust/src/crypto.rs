/// crypto.rs — Symmetric encryption layer
///
/// Once the time-lock is solved (or bypassed by the admin), the resulting BigUint K
/// is run through SHA-256 to produce a 256-bit AES key. The exam payload is then
/// encrypted/decrypted with AES-256-GCM (authenticated, so tampering is detectable).
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
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
///
/// `aad` (additional authenticated data) is NOT encrypted — but it IS bound to
/// the auth tag. Decryption must supply the same AAD bytes or the tag fails.
/// VAJRA uses this to bind a lock to a specific drand round: the AAD is
/// `SHA256("vajra-v1" || target_round || chain_hash)`, derived identically on
/// the unlock side from manifest fields. An attacker who modifies the manifest's
/// `target_round` breaks the HMAC (rejected before decryption); and even if they
/// could bypass that, the AAD mismatch causes AES-GCM auth failure.
///
/// Pass `&[]` for empty AAD (equivalent to "no AAD" in the GCM spec).
pub fn encrypt(k: &BigUint, plaintext: &[u8], aad: &[u8]) -> LockedPayload {
    let key_bytes = derive_aes_key(k);
    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).expect("Key is always 32 bytes; this cannot fail");

    // Fresh random nonce per encryption (never reuse a nonce with the same key)
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-GCM encryption failed — this should not happen");

    LockedPayload {
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    }
}

/// Decrypt a `LockedPayload` using AES-256-GCM with a key derived from K.
///
/// `aad` must be byte-identical to the AAD supplied at encrypt time, or the
/// auth tag fails and decryption returns `Err`. Pass `&[]` if no AAD was used.
///
/// Returns `Err` if:
///  - The key is wrong (wrong K → decryption key mismatch)
///  - The AAD differs from encrypt time
///  - The ciphertext was tampered with (GCM auth tag fails)
///  - The nonce or ciphertext hex is malformed
pub fn decrypt(k: &BigUint, locked: &LockedPayload, aad: &[u8]) -> Result<Vec<u8>, String> {
    let key_bytes = derive_aes_key(k);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).expect("Key is always 32 bytes");

    let nonce_bytes = hex::decode(&locked.nonce).map_err(|e| format!("Bad nonce hex: {e}"))?;
    if nonce_bytes.len() != 12 {
        return Err(format!("Nonce must be 12 bytes, got {}", nonce_bytes.len()));
    }

    let ciphertext =
        hex::decode(&locked.ciphertext).map_err(|e| format!("Bad ciphertext hex: {e}"))?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext.as_ref(),
                aad,
            },
        )
        .map_err(|_| {
            "Decryption failed — the time-lock key is incorrect, the AAD does \
             not match, or the ciphertext has been tampered with."
                .to_string()
        })
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn key(v: u64) -> BigUint {
        BigUint::from(v)
    }

    fn flip_hex_byte(s: &str, idx: usize) -> String {
        let mut b = hex::decode(s).unwrap();
        b[idx] ^= 0x01;
        hex::encode(b)
    }

    #[test]
    fn round_trip_with_and_without_aad() {
        let aad = [0xAB_u8; 32];
        for msg in [&b""[..], b"%PDF-1.4 tiny", &[0u8; 100_000][..]] {
            let locked = encrypt(&key(42), msg, &aad);
            assert_eq!(decrypt(&key(42), &locked, &aad).unwrap(), msg);

            let locked = encrypt(&key(42), msg, &[]);
            assert_eq!(decrypt(&key(42), &locked, &[]).unwrap(), msg);
        }
    }

    #[test]
    fn nonce_is_fresh_for_each_encryption() {
        let a = encrypt(&key(7), b"same", &[]);
        let b = encrypt(&key(7), b"same", &[]);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let locked = encrypt(&key(42), b"exam", &[]);
        assert!(decrypt(&key(43), &locked, &[]).is_err());
    }

    #[test]
    fn aad_mismatch_is_rejected() {
        let aad = [1u8; 32];
        let mut other = aad;
        other[31] ^= 0x80;
        let locked = encrypt(&key(42), b"exam", &aad);
        assert!(decrypt(&key(42), &locked, &other).is_err());
        assert!(
            decrypt(&key(42), &locked, &[]).is_err(),
            "dropping the AAD must fail"
        );

        let locked_no_aad = encrypt(&key(42), b"exam", &[]);
        assert!(
            decrypt(&key(42), &locked_no_aad, &aad).is_err(),
            "adding an AAD must fail"
        );
    }

    #[test]
    fn tampered_ciphertext_tag_or_nonce_is_rejected() {
        let locked = encrypt(&key(42), b"exam paper bytes", &[9u8; 32]);
        let ct_len = hex::decode(&locked.ciphertext).unwrap().len();

        let body = LockedPayload {
            nonce: locked.nonce.clone(),
            ciphertext: flip_hex_byte(&locked.ciphertext, 0),
        };
        assert!(
            decrypt(&key(42), &body, &[9u8; 32]).is_err(),
            "flipped ciphertext byte"
        );

        let tag = LockedPayload {
            nonce: locked.nonce.clone(),
            ciphertext: flip_hex_byte(&locked.ciphertext, ct_len - 1),
        };
        assert!(
            decrypt(&key(42), &tag, &[9u8; 32]).is_err(),
            "flipped tag byte"
        );

        let nonce = LockedPayload {
            nonce: flip_hex_byte(&locked.nonce, 0),
            ciphertext: locked.ciphertext.clone(),
        };
        assert!(
            decrypt(&key(42), &nonce, &[9u8; 32]).is_err(),
            "flipped nonce byte"
        );

        let mut truncated = hex::decode(&locked.ciphertext).unwrap();
        truncated.truncate(ct_len - 1);
        let short = LockedPayload {
            nonce: locked.nonce.clone(),
            ciphertext: hex::encode(truncated),
        };
        assert!(
            decrypt(&key(42), &short, &[9u8; 32]).is_err(),
            "truncated tag"
        );
    }

    #[test]
    fn malformed_encoding_is_rejected() {
        let locked = encrypt(&key(42), b"exam", &[]);
        let short_nonce = LockedPayload {
            nonce: "00".repeat(8),
            ciphertext: locked.ciphertext.clone(),
        };
        assert!(decrypt(&key(42), &short_nonce, &[])
            .unwrap_err()
            .contains("12 bytes"));
        let bad_hex = LockedPayload {
            nonce: locked.nonce.clone(),
            ciphertext: "not hex".into(),
        };
        assert!(decrypt(&key(42), &bad_hex, &[]).is_err());
    }

    #[test]
    fn key_derivation_is_sha256_of_big_endian_k() {
        let k = BigUint::from(0x0102_0304u32);
        let expected: [u8; 32] = Sha256::digest([1u8, 2, 3, 4]).into();
        assert_eq!(derive_aes_key(&k), expected);
    }
}
