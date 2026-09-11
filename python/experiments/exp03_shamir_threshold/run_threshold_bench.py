import csv
import os.path
import secrets
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import shamir

def run_experiment():
    n = 10
    thresholds = [3, 5, 8, 10]
    results = []

    original_key = secrets.token_bytes(32)

    for k in thresholds:
        shares = shamir.split(original_key, n, k)

        for num_shares in range(1, n + 1):
            test_shares = shares[:num_shares]

            start_time = time.perf_counter()
            success = False
            matches_original = False

            try:
                reconstructed_key = shamir.reconstruct(test_shares)
                success = True
                matches_original = (reconstructed_key == original_key)
            except Exception:
                success = False

            elapsed = time.perf_counter() - start_time

            results.append({
                "k": k,
                "n": n,
                "shares_used": num_shares,
                "success": success,
                "matches_original": matches_original,
                "time_seconds": elapsed
            })

    output_path = os.path.join(os.path.dirname(__file__), 'raw_results.csv')
    with open(output_path, 'w', newline='') as fp:
        writer = csv.DictWriter(fp, fieldnames=["k", "n", "shares_used", "success", "matches_original", "time_seconds"])
        writer.writeheader()
        writer.writerows(results)

if __name__ == '__main__':
    run_experiment()
