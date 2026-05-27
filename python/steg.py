"""steg.py — Forensic watermarking placeholder (Phase 2 production work).

THIS MODULE IS INTENTIONALLY UNIMPLEMENTED.

It marks the integration point for post-T=0 forensic watermarking — the
counterpart to VAJRA's pre-T=0 cryptographic distribution. Once the
coordinator has reconstructed an exam PDF at a centre, this module
(when implemented) would embed:

  • centre ID
  • room number
  • timestamp
  • candidate session (if applicable)

into the rendered PDF using LSB or frequency-domain steganography
(via OpenCV / Pillow / pikepdf). A photograph of the printed exam paper
or screen could then be analysed by the examining authority to identify
exactly which centre and room the leak originated from.

This makes post-T=0 leak attribution near-instantaneous, shifting the
operational economics of physical-photo leaks decisively.

See:
  docs/ARCHITECTURE.md  5.5  Forensic watermarking
  docs/DEPLOYMENT.md    2.6  Forensic watermarking — scope-extending but important

Estimated implementation effort: ~1 week.
Status: not started.
"""

from __future__ import annotations

import sys


def main() -> None:
    print("steg.py — Forensic watermarking is not yet implemented.")
    print()
    print("This module is a deliberate placeholder marking the integration")
    print("point for post-T=0 watermarking. See docs/DEPLOYMENT.md 2.6.")
    print()
    print("To contribute: open a GitHub issue describing your approach")
    print("before submitting a PR — the watermarking design needs to be")
    print("agreed on first.")
    sys.exit(0)


if __name__ == "__main__":
    main()
