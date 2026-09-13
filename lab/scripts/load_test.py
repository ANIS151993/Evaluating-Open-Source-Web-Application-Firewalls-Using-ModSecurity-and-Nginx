#!/usr/bin/env python3
"""
Lightweight concurrent load generator standing in for `wrk` (Section III-D),
for environments where installing wrk isn't convenient. Fires a fixed
number of requests at a target concurrency and reports latency percentiles,
matching the columns of Table VI (Latency Distribution Across Load Levels).

Usage:
    python3 load_test.py --target http://localhost:8080 --concurrency 50 \
        --requests 2000 --out ../results/latency_waf_c50.json

Run once against the WAF endpoint (8080) and once against the baseline
endpoint (8081, ModSecurity disabled) at each concurrency level to
reproduce the Base vs. +WAF comparison.
"""
import argparse
import concurrent.futures
import json
import statistics
import time

import requests

PATH = "/rest/products/search?q=juice"


def one_request(base_url):
    t0 = time.perf_counter()
    try:
        r = requests.get(f"{base_url}{PATH}", timeout=10)
        status = r.status_code
    except requests.RequestException:
        status = -1
    return (time.perf_counter() - t0) * 1000.0, status


def percentile(data, p):
    data = sorted(data)
    k = (len(data) - 1) * (p / 100)
    f, c = int(k), min(int(k) + 1, len(data) - 1)
    if f == c:
        return data[f]
    return data[f] + (data[c] - data[f]) * (k - f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--concurrency", type=int, default=20)
    ap.add_argument("--requests", type=int, default=1000)
    ap.add_argument("--out", required=True)
    ap.add_argument("--raw-out", default=None, help="optional path to dump the raw per-request latency list (ms) as JSON")
    args = ap.parse_args()

    latencies = []
    statuses = {}
    t_start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = [ex.submit(one_request, args.target) for _ in range(args.requests)]
        for fut in concurrent.futures.as_completed(futures):
            lat, status = fut.result()
            latencies.append(lat)
            statuses[status] = statuses.get(status, 0) + 1
    wall = time.perf_counter() - t_start

    result = {
        "target": args.target,
        "concurrency": args.concurrency,
        "requests": args.requests,
        "wall_seconds": wall,
        "achieved_rps": args.requests / wall,
        "median_ms": statistics.median(latencies),
        "p95_ms": percentile(latencies, 95),
        "p99_ms": percentile(latencies, 99),
        "status_counts": statuses,
    }
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)

    if args.raw_out:
        with open(args.raw_out, "w") as f:
            json.dump(latencies, f)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
