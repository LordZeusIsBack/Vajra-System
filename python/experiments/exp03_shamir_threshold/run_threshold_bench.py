import argparse
import csv
import os.path
import secrets
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import shamir

FIELDS = ["key_index", "k", "n", "shares_used", "success", "matches_original",
          "error", "time_seconds"]


def run_experiment(keys: int = 1, include_zero: bool = False, n: int = 10,
                   thresholds: tuple[int, ...] = (3, 5, 8, 10)) -> list[dict]:
    results = []
    first_j = 0 if include_zero else 1
    for key_index in range(keys):
        original_key = secrets.token_bytes(32)
        for k in thresholds:
            shares = shamir.split(original_key, n, k)
            for num_shares in range(first_j, n + 1):
                test_shares = shares[:num_shares]
                success = matches_original = False
                error = ""
                start_time = time.perf_counter()
                try:
                    reconstructed_key = shamir.reconstruct(test_shares)
                    success = True
                    matches_original = reconstructed_key == original_key
                except Exception as exc:
                    error = str(exc)
                elapsed = time.perf_counter() - start_time
                results.append({
                    "key_index": key_index,
                    "k": k,
                    "n": n,
                    "shares_used": num_shares,
                    "success": success,
                    "matches_original": matches_original,
                    "error": error,
                    "time_seconds": elapsed,
                })
    return results


def summarize(results: list[dict]) -> None:
    bad = [r for r in results
           if r["matches_original"] != (r["shares_used"] >= r["k"])]
    keys = len({r["key_index"] for r in results})
    print(f"{len(results)} calls over {keys} key(s); "
          f"{len(results) - len(bad)} matched the threshold prediction "
          f"(key recovered iff j >= k).")
    for r in bad:
        print(f"  UNEXPECTED: key {r['key_index']} k={r['k']} j={r['shares_used']}")
    zero = [r for r in results if r["shares_used"] == 0]
    if zero:
        errors = {r["error"] for r in zero}
        print(f"j = 0: {sum(not r['success'] for r in zero)}/{len(zero)} raised; errors: {errors}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keys", type=int, default=1, help="independent random keys (default 1)")
    ap.add_argument("--include-zero", action="store_true", help="also run j = 0")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "raw_results.csv"))
    args = ap.parse_args()

    results = run_experiment(keys=args.keys, include_zero=args.include_zero)
    with open(args.out, "w", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(results)
    summarize(results)
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
