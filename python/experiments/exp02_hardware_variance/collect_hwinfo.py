import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent))

from common import host_info, runtime_state


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--label", default="", help="paper label, e.g. M4 (optional)")
    ap.add_argument("--out-dir", type=Path, default=SCRIPT_DIR / "hwinfo")
    args = ap.parse_args()

    info = host_info()
    info["label"] = args.label
    info["collected_at_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    info["state_at_collection"] = runtime_state()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in info["Machine"]) or "unknown"
    out = args.out_dir / f"{safe}.json"
    out.write_text(json.dumps(info, indent=2))
    print(json.dumps(info, indent=2))
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
