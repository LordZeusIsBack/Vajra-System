"""vajra_keygen.py — Center-key ceremony CLI.

THREE COMMANDS

  1. `python vajra_keygen.py generate --id MY_CENTER --out keypair.json`
     [CENTER-SIDE] Generate a keypair, save (privkey + pubkey) to a JSON file.
     The center keeps this file and sends ONLY the pubkey to the admin.

  2. `python vajra_keygen.py bulk --n 10 --out-dir ./keys/`
     [ADMIN, DEMO ONLY] Generate n keypairs at once. Writes one
     <CENTER_NNN>.json per center plus centers.json registry.
     Real deployment: never use this. Real centers generate their own keypair.

  3. `python vajra_keygen.py extract-pubkey --in keypair.json`
     [CENTER-SIDE] Print the public key from a keypair file. Use to email
     the admin without leaking your private key.

OUTPUT FORMAT (keypair.json — center-held)
  { "id": "CENTER_07", "pubkey": "<hex>", "privkey": "<hex>" }

OUTPUT FORMAT (centers.json — admin-held, public)
  { "centers": [ { "id": "CENTER_007", "pubkey": "<hex>" }, ... ] }
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from centers import (
    bulk_generate,
    generate_keypair,
    save_registry,
)

# ── Subcommand handlers ──────────────────────────────────────────────────────


def cmd_generate(args: argparse.Namespace) -> int:
    sk_hex, pk_hex = generate_keypair()
    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"Refusing to overwrite {out} (use --force)", file=sys.stderr)
        return 1
    obj = {"id": args.id, "pubkey": pk_hex, "privkey": sk_hex}
    out.write_text(json.dumps(obj, indent=2, sort_keys=True))
    # Best-effort permission tighten — privkey is sensitive
    try:
        out.chmod(0o600)
    except OSError:
        pass  # Windows etc.
    print(f"✓ Wrote keypair → {out}")
    print(f"  Center id:  {args.id}")
    print(f"  Pubkey:     {pk_hex}")
    print()
    print("Share the PUBKEY with the admin. Keep this file secret.")
    return 0


def cmd_bulk(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    if out_dir.exists() and any(out_dir.iterdir()) and not args.force:
        print(f"Refusing to write into non-empty {out_dir} (use --force)",
              file=sys.stderr)
        return 1
    out_dir.mkdir(parents=True, exist_ok=True)

    registry, privkeys = bulk_generate(args.n, id_prefix=args.id_prefix)

    for (cid, sk_hex), reg in zip(privkeys, registry):
        kp_path = out_dir / f"{cid}.json"
        kp_path.write_text(json.dumps(
            {"id": cid, "pubkey": reg.pubkey, "privkey": sk_hex},
            indent=2, sort_keys=True,
        ))
        try:
            kp_path.chmod(0o600)
        except OSError:
            pass

    registry_path = out_dir / "centers.json"
    save_registry(registry, registry_path)

    print(f"✓ Generated {args.n} keypairs in {out_dir}/")
    print(f"  Registry (public)    → {registry_path}")
    print(f"  Per-center keypairs  → {out_dir}/{args.id_prefix}_NNN.json")
    print()
    print("⚠ DEMO MODE: in production, each center generates their own keypair")
    print("   and the admin never sees a private key.")
    return 0


def cmd_extract_pubkey(args: argparse.Namespace) -> int:
    in_path = Path(args.in_path)
    if not in_path.exists():
        print(f"File not found: {in_path}", file=sys.stderr)
        return 1
    try:
        data = json.loads(in_path.read_text())
    except json.JSONDecodeError as exc:
        print(f"Not valid JSON: {exc}", file=sys.stderr)
        return 1
    if "pubkey" not in data:
        print(f"No 'pubkey' field in {in_path}", file=sys.stderr)
        return 1
    print(data["pubkey"])
    return 0


# ── Argparse wiring ───────────────────────────────────────────────────────────


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="vajra-keygen",
        description="Generate and manage VAJRA center keypairs.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="Generate one keypair for a single center")
    g.add_argument("--id", required=True, help="Center ID (e.g. DELHI_01)")
    g.add_argument("--out", required=True, help="Output keypair JSON path")
    g.add_argument("--force", action="store_true", help="Overwrite if exists")
    g.set_defaults(func=cmd_generate)

    b = sub.add_parser("bulk", help="[DEMO] Generate n keypairs + registry at once")
    b.add_argument("--n", type=int, required=True, help="Number of centers")
    b.add_argument("--out-dir", required=True, help="Output directory")
    b.add_argument("--id-prefix", default="CENTER", help="Prefix for center IDs")
    b.add_argument("--force", action="store_true", help="Allow writing into non-empty dir")
    b.set_defaults(func=cmd_bulk)

    e = sub.add_parser("extract-pubkey", help="Print pubkey from a keypair file")
    e.add_argument("--in", dest="in_path", required=True, help="Keypair JSON file")
    e.set_defaults(func=cmd_extract_pubkey)

    return p.parse_args()


def main() -> int:
    args = _parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
