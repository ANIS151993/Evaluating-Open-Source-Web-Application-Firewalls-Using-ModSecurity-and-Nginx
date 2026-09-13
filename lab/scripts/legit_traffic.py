#!/usr/bin/env python3
"""
Generates benign Juice Shop traffic (browsing, search, auth, reviews) to
measure the false-positive rate, mirroring the "Legitimate Traffic Corpus"
described in Section III-D. Records which requests ModSecurity blocked
(a false positive, since none of this traffic is malicious).

Usage:
    python3 legit_traffic.py --target http://localhost:8080 --count 500 \
        --out ../results/legit_waf.json
"""
import argparse
import json
import random
import time
import uuid

import requests

BLOCK_CODES = {403, 406}

SEARCH_TERMS = [
    "apple", "juice", "banana", "OWASP", "shirt", "sticker", "book",
    "green smoothie", "carrot", "lemon", "melon", "coffee",
]

REVIEW_TEXT = [
    "Great product, would buy again!",
    "Fast shipping & good packaging.",
    "Not what I expected, but still ok.",
    "5 stars <3 love it",
    "Tastes better than the last batch — thanks!",
    "Item arrived slightly damaged but support was helpful.",
]

PATHS = [
    ("GET", "/", None),
    ("GET", "/rest/products/search", lambda: {"q": random.choice(SEARCH_TERMS)}),
    ("GET", "/api/Products", None),
    ("GET", "/api/Challenges", None),
    ("GET", "/rest/product/1/reviews", None),
    ("GET", "/static/favicon.ico", None),
    ("GET", "/assets/public/images/products/apple_juice.jpg", None),
]


def send(target, method, path, params, txid):
    url = f"{target}{path}"
    try:
        r = requests.request(
            method, url, params=params,
            headers={"X-Test-Transaction-Id": txid, "X-Test-Category": "legit"},
            timeout=10,
        )
        return r.status_code
    except requests.RequestException as exc:
        return f"error:{exc.__class__.__name__}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--count", type=int, default=200)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    results = []
    for i in range(args.count):
        method, path, params_fn = random.choice(PATHS)
        params = params_fn() if params_fn else None

        # Occasionally post a free-text review to exercise the parameter-
        # scoped exclusion for rule 941100 (Section III-E, Cycle 3).
        if random.random() < 0.15:
            method, path = "POST", "/api/Feedbacks"
            params = {"comment": random.choice(REVIEW_TEXT), "rating": random.randint(1, 5)}

        txid = str(uuid.uuid4())
        status = send(args.target, method, path, params, txid)
        blocked = isinstance(status, int) and status in BLOCK_CODES
        results.append({
            "txid": txid, "method": method, "path": path,
            "params": params, "status": status, "blocked": blocked,
        })
        if i % 50 == 0:
            time.sleep(0.2)

    with open(args.out, "w") as f:
        json.dump(results, f, indent=2)

    total = len(results)
    blocked = sum(1 for r in results if r["blocked"])
    print(f"Sent {total} legitimate requests to {args.target}")
    print(f"False positives (blocked): {blocked} ({blocked/total*100:.2f}%)")


if __name__ == "__main__":
    main()
