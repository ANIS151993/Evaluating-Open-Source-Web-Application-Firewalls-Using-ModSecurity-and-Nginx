#!/usr/bin/env python3
"""
Parses ModSecurity's JSON audit log and tallies which rule IDs fired most
often, reproducing Table V's "Top False Positive Rule Contributors"
analysis.

The owasp/modsecurity-crs image writes one JSON object per line to stdout
by default (MODSEC_AUDIT_LOG=/dev/stdout), so capture it first with:

    docker compose logs -t --no-color waf > ../results/waf_raw.log

then run:

    python3 analyze_audit_log.py ../results/waf_raw.log

`docker compose logs` prefixes each line with a timestamp and container
name (e.g. "waf-lab-proxy  | {...}"); this script strips that prefix and
skips any line that isn't a JSON object (access log lines, startup banner,
etc.), so it also works if you point it at a raw file with SecAuditLog set
to a real path instead of /dev/stdout.
"""
import json
import sys
from collections import Counter


def extract_json_line(line):
    idx = line.find("{")
    if idx == -1:
        return None
    candidate = line[idx:].strip()
    if not candidate.startswith('{"transaction"'):
        return None
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return None


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <docker-compose-logs-output.log>")
        sys.exit(1)

    rule_hits = Counter()
    rule_msgs = {}
    tx_count = 0
    blocked_count = 0

    with open(sys.argv[1], "r", errors="ignore") as f:
        for line in f:
            tx = extract_json_line(line)
            if tx is None:
                continue
            tx_count += 1
            transaction = tx.get("transaction", {})
            response = transaction.get("response", {})
            if response.get("http_code") in (403, 406):
                blocked_count += 1
            for m in transaction.get("messages", []):
                details = m.get("details", {})
                rule_id = details.get("ruleId")
                if rule_id:
                    rule_hits[rule_id] += 1
                    rule_msgs[rule_id] = (m.get("message") or "")[:80]

    print(f"Transactions parsed: {tx_count}")
    print(f"Blocked (403/406): {blocked_count}")
    print()
    print(f"{'Rule ID':10s} {'Hits':6s}  Message")
    for rule_id, count in rule_hits.most_common(20):
        print(f"{rule_id:10s} {count:6d}  {rule_msgs.get(rule_id, '')}")


if __name__ == "__main__":
    main()
