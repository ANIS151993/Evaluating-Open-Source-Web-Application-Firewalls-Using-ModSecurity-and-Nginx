#!/usr/bin/env python3
"""
Replays the labeled attack corpus (attack_payloads.py) against a target and
records whether ModSecurity blocked each request (HTTP 403/406) or the
request reached the application. Mirrors Section III-D / Table IV of the
paper.

Usage:
    python3 run_attacks.py --target http://localhost:8080 --out ../results/attacks_waf.json
    python3 run_attacks.py --target http://localhost:8081 --out ../results/attacks_baseline.json
"""
import argparse
import json
import time
import uuid

import requests

from attack_payloads import CATEGORIES, ZERO_DAY

BLOCK_CODES = {403, 406}


def send(target, category, payload, txid):
    url = f"{target}/rest/products/search"
    try:
        r = requests.get(
            url,
            params={"q": payload},
            headers={"X-Test-Transaction-Id": txid, "X-Test-Category": category},
            timeout=10,
        )
        return r.status_code
    except requests.RequestException as exc:
        return f"error:{exc.__class__.__name__}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    results = []
    for category, payloads in CATEGORIES.items():
        for payload in payloads:
            txid = str(uuid.uuid4())
            status = send(args.target, category, payload, txid)
            blocked = isinstance(status, int) and status in BLOCK_CODES
            results.append(
                {
                    "txid": txid,
                    "category": category,
                    "payload": payload,
                    "status": status,
                    "blocked": blocked,
                }
            )
            time.sleep(0.05)

    for label, payload in ZERO_DAY:
        txid = str(uuid.uuid4())
        status = send(args.target, "zero_day", payload, txid)
        blocked = isinstance(status, int) and status in BLOCK_CODES
        results.append(
            {
                "txid": txid,
                "category": "zero_day",
                "label": label,
                "payload": payload,
                "status": status,
                "blocked": blocked,
            }
        )
        time.sleep(0.05)

    with open(args.out, "w") as f:
        json.dump(results, f, indent=2)

    total = len(results)
    blocked = sum(1 for r in results if r["blocked"])
    print(f"Sent {total} attack requests to {args.target}")
    print(f"Blocked (403/406): {blocked} ({blocked/total*100:.1f}%)")

    by_cat = {}
    for r in results:
        c = by_cat.setdefault(r["category"], {"total": 0, "blocked": 0})
        c["total"] += 1
        c["blocked"] += r["blocked"]
    for cat, stats in by_cat.items():
        rate = stats["blocked"] / stats["total"] * 100
        print(f"  {cat:15s} {stats['blocked']:3d}/{stats['total']:3d}  ({rate:.1f}%)")


if __name__ == "__main__":
    main()
