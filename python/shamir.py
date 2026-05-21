"""shamir.py — Shamir's Secret Sharing over GF(2^8).

WHY GF(2^8)?
  • Works natively on bytes — no bignum required.
  • Supports up to 255 shares (x-coordinates 1..255).
  • Well-audited approach; same field used inside AES.

FIELD DEFINITION
  GF(2^8) with the AES reducing polynomial: x^8 + x^4 + x^3 + x + 1.
  Addition  = XOR (no carry in characteristic-2 fields).
  Subtraction = XOR (same as addition).
  Multiplication uses shift-and-XOR with 0x1B reduction on overflow.

SHARE FORMAT  (len(secret) + 1 bytes per share)
  byte 0         : x-coordinate (1 … n, never 0 — that's the secret)
  bytes 1 … end  : f_b(x) for each byte b of the secret

RECONSTRUCTION CAVEAT (READ THIS)
  Shamir SSS does NOT detect "too few shares". With k-1 shares you get a
  well-formed but WRONG secret — no error. The defence is to know k in
  advance (it's in the manifest) and validate either:
    (a) pass exactly k shares and trust the manifest, OR
    (b) pass ≥k shares and authenticate the result downstream (we do this
        via the outer AES-GCM tag: wrong data_key → GCM auth fails).
  We support both via the `expected_threshold` argument on reconstruct().
"""

import secrets
from typing import Sequence


# ── GF(2^8) arithmetic ────────────────────────────────────────────────────────

def _gf_mul(a: int, b: int) -> int:
    """Multiply two elements of GF(2^8) (peasant multiplication)."""
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B  # low 8 bits of the reducing polynomial
        b >>= 1
    return r


def _gf_inv(a: int) -> int:
    """Multiplicative inverse via Fermat: a^(2^8 - 2) = a^254."""
    if a == 0:
        raise ZeroDivisionError("0 has no inverse in GF(2^8)")
    # Fast exponentiation in GF(2^8)
    result, base, exp = 1, a, 254
    while exp:
        if exp & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        exp >>= 1
    return result


def _poly_eval(coeffs: list[int], x: int) -> int:
    """Evaluate a GF(2^8) polynomial using Horner's method.
    coeffs[0] is the constant term (the secret byte).
    """
    acc = 0
    for c in reversed(coeffs):
        acc = _gf_mul(acc, x) ^ c
    return acc


# ── Public API ────────────────────────────────────────────────────────────────

def split(secret: bytes, n: int, k: int) -> list[bytes]:
    """Split *secret* into *n* shares where any *k* reconstruct the original.

    Each byte of the secret gets its own independent degree-(k-1) polynomial
    f_b(x) = secret[b] + r₁x + r₂x² + … + r_{k-1}x^{k-1}  (all in GF(2^8))

    Share i  =  bytes([i]) + bytes(f_b(i) for b in secret)

    Args:
        secret: Arbitrary bytes to protect (e.g. a 32-byte AES key).
        n:      Total number of shares to produce (2 ≤ n ≤ 255).
        k:      Reconstruction threshold (2 ≤ k ≤ n).

    Returns:
        List of *n* share bytestrings, each of length len(secret) + 1.

    Raises:
        ValueError: Invalid parameters or empty secret.
    """
    if not (2 <= k <= n <= 255):
        raise ValueError(f"Need 2 ≤ k ≤ n ≤ 255, got k={k}, n={n}")
    if not secret:
        raise ValueError("Secret must be non-empty")

    # Build one polynomial per secret byte
    polys: list[list[int]] = [
        [byte] + [secrets.randbelow(256) for _ in range(k - 1)]
        for byte in secret
    ]

    return [
        bytes([x]) + bytes(_poly_eval(p, x) for p in polys)
        for x in range(1, n + 1)
    ]


def reconstruct(
    shares: Sequence[bytes],
    *,
    expected_threshold: int | None = None,
) -> bytes:
    """Reconstruct the secret from *k* or more shares.

    Uses Lagrange interpolation at x=0 over GF(2^8):

        f(0) = Σᵢ yᵢ · ∏_{j≠i}  xⱼ / (xᵢ ⊕ xⱼ)

    Args:
        shares: At least *k* share bytestrings.
        expected_threshold: If given, raises ValueError unless
                            len(shares) >= expected_threshold. This is a
                            sanity check against the manifest's `k`; without
                            it, passing too few shares yields a wrong secret
                            silently (this is inherent to Shamir, not a bug).

    Returns:
        Reconstructed secret as bytes.

    Raises:
        ValueError: Duplicate x-coordinates, inconsistent share lengths, or
                    fewer than expected_threshold shares (if provided).
    """
    if not shares:
        raise ValueError("No shares provided")

    if expected_threshold is not None and len(shares) < expected_threshold:
        raise ValueError(
            f"Need at least {expected_threshold} shares to reconstruct, "
            f"got {len(shares)}. (With fewer shares Shamir returns a wrong "
            f"secret silently — refusing.)"
        )

    share_len = len(shares[0])
    if any(len(s) != share_len for s in shares):
        raise ValueError("All shares must be the same length")

    xs = [s[0] for s in shares]
    if len(set(xs)) != len(shares):
        raise ValueError("Duplicate x-coordinates detected — shares may be corrupted")
    if 0 in xs:
        raise ValueError("x=0 is reserved for the secret; shares must use x≥1")

    k = len(shares)
    secret_len = share_len - 1  # drop the x-coordinate byte

    result = bytearray(secret_len)
    for byte_idx in range(secret_len):
        ys = [s[1 + byte_idx] for s in shares]

        # Lagrange interpolation at x=0
        acc = 0
        for i in range(k):
            # Numerator:   yᵢ · ∏_{j≠i} xⱼ
            # Denominator: ∏_{j≠i} (xᵢ ⊕ xⱼ)
            num = ys[i]
            den = 1
            for j in range(k):
                if i == j:
                    continue
                num = _gf_mul(num, xs[j])
                den = _gf_mul(den, xs[i] ^ xs[j])  # XOR = subtraction in GF(2^8)
            acc ^= _gf_mul(num, _gf_inv(den))       # XOR = addition in GF(2^8)

        result[byte_idx] = acc

    return bytes(result)


# ── Self-test (run with: python shamir.py) ────────────────────────────────────

if __name__ == "__main__":
    import sys

    print("Running Shamir SSS self-test …")
    test_secret = secrets.token_bytes(32)
    failures = 0

    for (n, k) in [(3, 2), (5, 3), (10, 8), (20, 15)]:
        all_shares = split(test_secret, n, k)

        # 1. Exactly k shares should reconstruct correctly.
        if reconstruct(all_shares[:k], expected_threshold=k) != test_secret:
            print(f"  FAIL n={n} k={k}: k-share reconstruction wrong")
            failures += 1
            continue

        # 2. More than k shares should also work.
        if reconstruct(all_shares, expected_threshold=k) != test_secret:
            print(f"  FAIL n={n} k={k}: n-share reconstruction wrong")
            failures += 1
            continue

        # 3. Too few shares should RAISE (with expected_threshold).
        if k > 2:
            try:
                reconstruct(all_shares[:k - 1], expected_threshold=k)
                print(f"  FAIL n={n} k={k}: should have raised on k-1 shares")
                failures += 1
                continue
            except ValueError:
                pass  # expected

        # 4. Too few shares WITHOUT expected_threshold should NOT match
        #    (proves the silent-wrong-result hazard exists; we just guard against it).
        if k > 2:
            wrong = reconstruct(all_shares[:k - 1])
            assert wrong != test_secret, (
                "Unlikely-but-possible chance collision; rerun the test."
            )

        print(f"  PASS n={n} k={k}")

    if failures:
        print(f"\n{failures} test(s) failed.")
        sys.exit(1)
    print("\nAll tests passed ✓")
