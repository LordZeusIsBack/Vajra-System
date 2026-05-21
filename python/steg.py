"""steg.py — Forensic watermarking stub (Phase 3 / future work).

Once the Rust CLI decrypts the exam PDF, this module will:
  1. Parse the PDF (pypdf / pikepdf)
  2. Rasterise each page (pdf2image → PIL)
  3. Embed center metadata (Center ID, Room #, Timestamp) via LSB steganography
  4. Re-encode the watermarked images back into a print-ready PDF

Architecture doc reference: Tier 3 §5.3 — Dynamic Forensic Watermarking

Usage (future):
  python steg.py --pdf exam.pdf --center-id CENT42 --room 7 --out stamped.pdf
"""

import sys


def main() -> None:
    print("steg.py — Forensic watermarking (not yet implemented)")
    print()
    print("Planned pipeline:")
    print("  1. Rasterise PDF pages with pdf2image")
    print("  2. Embed Center ID + Room + Timestamp via LSB steganography (Pillow)")
    print("  3. Re-assemble watermarked pages into a new PDF")
    print()
    print("Coming in Phase 3.  See Vajra_Architecture_Detailed.md §5.3.")
    sys.exit(0)


if __name__ == "__main__":
    main()
