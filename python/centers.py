"""centers.py — Per-center keypairs and shard encryption (Step 2).

WHY THIS EXISTS
  Without per-center encryption, every Shamir shard goes to public IPFS in
  plaintext. Anyone with the manifest CID can fetch all n shards and
  reconstruct data_key themselves — making the k-of-n property purely
  theatrical. Shamir does no security work.

  This module gives each exam center an X25519 keypair. At lock time, the
  admin encrypts shard `i` to center `i`'s public key. Only that center
  (holding the matching private key) can decrypt their shard. IPFS becomes
  pure transport: even with all n encrypted shards in hand, an attacker
  without ≥k private keys gets nothing.

REGISTRATION MODEL (Option A from design discussion)
  Centers generate keypairs locally, give the admin their public key (and
  ONLY the public key) before any exam is locked. The admin maintains a
  centers.json registry; the lock pipeline uses it to encrypt shards. The
  admin NEVER sees a private key — preserving the zero-trust property
  that's central to the VAJRA story.

ENCRYPTION SCHEME (per-shard)
  Hybrid: ephemeral X25519 ECDH → HKDF-SHA256 → ChaCha20-Poly1305 AEAD.

  For each shard:
    1. Generate fresh ephemeral X25519 keypair (eph_sk, eph_pk).
    2. Compute shared_secret = X25519(eph_sk, center_pk).
    3. key = HKDF-SHA256(shared_secret, info="vajra-shard-v1", length=32).
    4. nonce = random 12 bytes.
    5. ciphertext = ChaCha20Poly1305(key).encrypt(nonce, share_bytes, aad=None).
    6. Output: { eph_pk_hex, nonce_hex, ciphertext_hex }.

  Center decrypts by:
    1. shared_secret = X25519(center_sk, eph_pk).
    2. key = HKDF-SHA256(shared_secret, info="vajra-shard-v1", length=32).
    3. share_bytes = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad=None).

  This is essentially HPKE base mode (RFC 9180) without the full ceremony.
  We don't bind the shard to a recipient ID via AAD here because the Shamir
  outer protocol catches a wrong center decrypting (Lagrange interpolation
  would mix shares with mismatched x-coordinates and produce garbage → AES-GCM
  auth tag fails downstream). For Layer C hardening, AAD = SHA256(exam_id ||
  center_id) would tighten this.

HONEST CAVEATS
  • This protects shards in transit and at rest on IPFS. It does NOT protect
    against a center whose machine is compromised — a stolen privkey from
    one center makes their shard recoverable. The k-of-n threshold is the
    defence: an attacker needs ≥ k compromises, not 1.
  • Forward secrecy: ephemeral sender keys give forward secrecy on the sender
    side. If a center's long-term private key leaks, ALL their past shards
    become recoverable. Rotate keypairs between exams in production.
  • The centers.json registry is integrity-critical. If an attacker swaps a
    pubkey for their own before lock, they'll be able to decrypt that shard.
    In production, sign the registry with an offline admin key; this PoC
    relies on filesystem permissions.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ── Public types ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CenterRegistration:
    """One entry from the centers registry."""
    id: str        # human-readable, e.g. "DELHI_CENTER_01"
    pubkey: str    # hex of 32-byte X25519 public key


@dataclass(frozen=True)
class EncryptedShard:
    """A Shamir share encrypted for one specific center."""
    eph_pubkey:   str   # hex of 32-byte ephemeral X25519 public key
    nonce:        str   # hex of 12-byte ChaCha20-Poly1305 nonce
    ciphertext:   str   # hex of ChaCha20-Poly1305(share_bytes) + 16-byte tag

    def to_dict(self) -> dict:
        return {
            "eph_pubkey_hex":  self.eph_pubkey,
            "nonce_hex":       self.nonce,
            "ciphertext_hex":  self.ciphertext,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "EncryptedShard":
        return cls(
            eph_pubkey = d["eph_pubkey_hex"],
            nonce      = d["nonce_hex"],
            ciphertext = d["ciphertext_hex"],
        )


class CentersError(RuntimeError):
    """Raised on any centers-module failure. Message is safe to surface."""


# ── Keypair generation + serialisation ────────────────────────────────────────


def generate_keypair() -> tuple[str, str]:
    """Generate a fresh X25519 keypair.

    Returns:
        (privkey_hex, pubkey_hex) — each 64 hex chars = 32 raw bytes.
    """
    sk = X25519PrivateKey.generate()
    sk_bytes = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sk_bytes.hex(), pk_bytes.hex()


def _load_pubkey(pubkey_hex: str) -> X25519PublicKey:
    try:
        raw = bytes.fromhex(pubkey_hex)
    except ValueError as exc:
        raise CentersError(f"Bad pubkey hex: {exc}") from exc
    if len(raw) != 32:
        raise CentersError(f"X25519 pubkey must be 32 bytes (got {len(raw)})")
    return X25519PublicKey.from_public_bytes(raw)


def _load_privkey(privkey_hex: str) -> X25519PrivateKey:
    try:
        raw = bytes.fromhex(privkey_hex)
    except ValueError as exc:
        raise CentersError(f"Bad privkey hex: {exc}") from exc
    if len(raw) != 32:
        raise CentersError(f"X25519 privkey must be 32 bytes (got {len(raw)})")
    return X25519PrivateKey.from_private_bytes(raw)


# ── Registry load/save ───────────────────────────────────────────────────────


def load_registry(path: str | Path) -> list[CenterRegistration]:
    """Load a centers registry from JSON.

    Expected file shape:
        {"centers": [{"id": "CENTER_01", "pubkey": "<64 hex>"}, ...]}

    Returns:
        List of CenterRegistration entries, in file order. The order is the
        "center index" used everywhere downstream (shard 0 → centers[0]).
    """
    path = Path(path)
    if not path.exists():
        raise CentersError(
            f"Centers registry not found at {path}. "
            f"Generate one with: python vajra_keygen.py bulk --n N --out-dir ./keys "
            f"(then set CENTERS_REGISTRY_PATH=./keys/centers.json in .env)"
        )
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise CentersError(f"Registry at {path} is not valid JSON: {exc}") from exc

    if "centers" not in raw or not isinstance(raw["centers"], list):
        raise CentersError(f"Registry at {path} missing 'centers' list")

    out: list[CenterRegistration] = []
    seen_ids: set[str] = set()
    seen_pks: set[str] = set()
    for i, entry in enumerate(raw["centers"]):
        if "id" not in entry or "pubkey" not in entry:
            raise CentersError(f"Registry entry {i} missing 'id' or 'pubkey'")
        cid = str(entry["id"])
        pk  = str(entry["pubkey"])
        if cid in seen_ids:
            raise CentersError(f"Duplicate center id in registry: {cid!r}")
        if pk in seen_pks:
            raise CentersError(
                f"Duplicate pubkey in registry for {cid!r} "
                f"— two centers must not share a key"
            )
        # Validate pubkey shape; raises CentersError if malformed
        _load_pubkey(pk)
        seen_ids.add(cid)
        seen_pks.add(pk)
        out.append(CenterRegistration(id=cid, pubkey=pk))

    if not out:
        raise CentersError(f"Registry at {path} contains zero centers")
    return out


def save_registry(centers: list[CenterRegistration], path: str | Path) -> None:
    """Write a centers registry to JSON (admin-side convenience)."""
    path = Path(path)
    obj = {"centers": [{"id": c.id, "pubkey": c.pubkey} for c in centers]}
    path.write_text(json.dumps(obj, indent=2, sort_keys=True))


# ── Per-shard encryption ──────────────────────────────────────────────────────


_HKDF_INFO = b"vajra-shard-v1"


def _derive_shard_key(shared_secret: bytes) -> bytes:
    """HKDF-SHA256 to 32 bytes with domain-separation info."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO,
    ).derive(shared_secret)


def encrypt_share_for_center(share: bytes, center_pubkey_hex: str) -> EncryptedShard:
    """Hybrid-encrypt a single Shamir share to one center's X25519 pubkey.

    Args:
        share:               Raw share bytes (e.g. the 33-byte
                             [x_coord + 32 polynomial evals] from shamir.split).
        center_pubkey_hex:   Recipient's X25519 pubkey, hex-encoded.

    Returns:
        EncryptedShard with ephemeral pubkey, nonce, and ciphertext.
    """
    if not share:
        raise CentersError("Refusing to encrypt empty share")

    recipient_pk = _load_pubkey(center_pubkey_hex)

    # Fresh ephemeral key per shard
    eph_sk = X25519PrivateKey.generate()
    eph_pk_bytes = eph_sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    shared_secret = eph_sk.exchange(recipient_pk)
    key = _derive_shard_key(shared_secret)

    nonce = secrets.token_bytes(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, share, associated_data=None)

    return EncryptedShard(
        eph_pubkey=eph_pk_bytes.hex(),
        nonce=nonce.hex(),
        ciphertext=ciphertext.hex(),
    )


def decrypt_share_with_privkey(
    encrypted: EncryptedShard,
    center_privkey_hex: str,
) -> bytes:
    """Recover the plaintext share using the center's private key.

    Returns:
        Raw share bytes, identical to what was passed into
        encrypt_share_for_center.

    Raises:
        CentersError: Wrong private key, tampered ciphertext, or bad field hex.
    """
    sk = _load_privkey(center_privkey_hex)

    try:
        eph_pk_bytes = bytes.fromhex(encrypted.eph_pubkey)
        nonce_bytes  = bytes.fromhex(encrypted.nonce)
        ct_bytes     = bytes.fromhex(encrypted.ciphertext)
    except ValueError as exc:
        raise CentersError(f"Bad hex in encrypted shard: {exc}") from exc

    if len(eph_pk_bytes) != 32:
        raise CentersError("Ephemeral pubkey must be 32 bytes")
    if len(nonce_bytes) != 12:
        raise CentersError("Nonce must be 12 bytes")

    eph_pk = X25519PublicKey.from_public_bytes(eph_pk_bytes)
    shared_secret = sk.exchange(eph_pk)
    key = _derive_shard_key(shared_secret)

    try:
        return ChaCha20Poly1305(key).decrypt(nonce_bytes, ct_bytes, associated_data=None)
    except Exception as exc:
        # InvalidTag, or any other AEAD failure
        raise CentersError(
            "Shard decryption failed. Either the private key does not match "
            "the public key the admin encrypted to, or the ciphertext has "
            "been tampered with on IPFS."
        ) from exc


# ── Admin-side helper: generate n keypairs + registry in one go ───────────────


def bulk_generate(
    n: int,
    id_prefix: str = "CENTER",
) -> tuple[list[CenterRegistration], list[tuple[str, str]]]:
    """Generate n keypairs at once. ADMIN-SIDE CONVENIENCE for the demo only.

    Returns:
        (registry, keypairs)
          registry: list of CenterRegistration (public — goes in centers.json)
          keypairs: list of (id, privkey_hex) — must be securely distributed
                    to each named center and then DROPPED by the admin.

    ⚠ In a real deployment, centers generate keypairs themselves and submit
    only the pubkey. This helper exists so the demo doesn't need k separate
    machines for the registration ceremony.
    """
    if n < 1:
        raise CentersError("n must be ≥ 1")
    if n > 999:
        raise CentersError("n must be ≤ 999 (sanity cap for IDs)")

    registry: list[CenterRegistration] = []
    privkeys: list[tuple[str, str]]    = []

    for i in range(n):
        cid = f"{id_prefix}_{i:03d}"
        sk_hex, pk_hex = generate_keypair()
        registry.append(CenterRegistration(id=cid, pubkey=pk_hex))
        privkeys.append((cid, sk_hex))

    return registry, privkeys