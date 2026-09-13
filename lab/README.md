# WAF Evaluation Lab

A runnable reproduction of the testbed described in Section III of
*"Open-Source Web Application Firewall Implementation Using ModSecurity
Engine: A Performance and Security Evaluation Framework."*

```
Client ──▶ Nginx + ModSecurity v3 (OWASP CRS 3.3) ──▶ OWASP Juice Shop
              │
              └─▶ audit log (JSON, one transaction per line)
```

A second, WAF-disabled copy of the same proxy (`baseline`, port 8081) is
started alongside it so you can compare "with WAF" vs. "without WAF"
directly — the same comparison used for Table VI/VII and Fig. 9/10 in the
paper.

This is a **local, defensive-security teaching lab**: the "attacks" are
sent by you, from your own machine, against a Juice Shop instance you
control. Nothing here targets a third party.

## Requirements

- Docker + Docker Compose v2 (`docker compose version`)
- Python 3.9+ with the `requests` package (`pip install requests`)

## Quick start

```bash
cd lab
./run_full_evaluation.sh
```

This brings up the stack, replays the labeled attack corpus and a
legitimate-traffic corpus against both the WAF and the baseline, runs a
latency comparison, and analyzes the resulting ModSecurity audit log. Raw
JSON results are written to `results/`.

To tear down: `docker compose down`.

## What's in here

| Path | Purpose |
|---|---|
| `docker-compose.yml` | Juice Shop backend + Nginx/ModSecurity/CRS proxy (port 8080) + WAF-disabled baseline proxy (port 8081) |
| `nginx/custom-rules.conf` | The paper's Section III-E tuning exclusions (Rule 930100 for `/static/`, `/assets/`; parameter-scoped exclusion for 941100 on review/feedback text) |
| `scripts/attack_payloads.py` | Labeled payload sets for SQLi, XSS, LFI, RCE, SSRF, path traversal, plus 4 zero-day-style variants — mirrors Table II |
| `scripts/run_attacks.py` | Replays the attack corpus against a target, records blocked vs. passed (Table IV) |
| `scripts/legit_traffic.py` | Replays benign Juice Shop browsing/search/review traffic to measure false positives |
| `scripts/load_test.py` | Concurrent load generator reporting median/P95/P99 latency (a `wrk` substitute — see note below) |
| `scripts/analyze_audit_log.py` | Parses the ModSecurity JSON audit log and tallies rule-ID hit counts (Table V) |
| `run_full_evaluation.sh` | Runs the whole cycle end to end |

## Reproducing the four tuning cycles (Section III-E)

The paper's methodology is Detect → Analyze → Exclude → Enforce, repeated
over three cycles. To reproduce a cycle:

1. **Baseline (PL1, threshold 5, no exclusions):** comment out the rule
   blocks in `nginx/custom-rules.conf`, then
   `docker compose up -d --force-recreate waf`.
2. **Cycle 1 (URI exclusions):** restore the `930100` exclusion block only.
3. **Cycle 2 (threshold 7):** `ANOMALY_INBOUND=7 docker compose up -d waf`.
4. **Cycle 3 (parameter exclusions):** restore both exclusion blocks and
   keep `ANOMALY_INBOUND=7`.

After each cycle, re-run `run_full_evaluation.sh` and compare
`results/attacks_waf.json` (detection) against `results/legit_waf.json`
(false positives) to see where your own run lands relative to Table III.

## Honesty note on reproducing the paper's exact numbers

This lab reproduces the paper's **architecture and methodology** faithfully
— same request path, same rule set, same tuning workflow, same class of
attack payloads. It will **not** reproduce the paper's exact percentages
(98.4% detection, 4.3% FPR, 11.8ms latency) on the nose, because:

- The published numbers come from a larger, dedicated run (50,000 legitimate
  requests, 9,200 attack requests, dedicated 4-vCPU cloud VM, SQLMap/
  XSStrike/Commix/Burp/Dotdotpwn as payload generators) — this repo ships a
  smaller, curated payload set so anyone can run it on a laptop in minutes
  without installing five separate offensive tools.
- Hardware, CRS version drift, and container resource limits will shift
  latency figures.
- If you install SQLMap/XSStrike/Commix locally, wire them into
  `scripts/run_with_external_tools.sh`-style drivers against
  `http://localhost:8080` for a closer match to the original tool set.

Treat this lab as a **reproducibility and teaching artifact** — a way for a
reviewer or visitor to verify the mechanism works as described and to run
their own measurement — not as a byte-for-byte replay of the original data
collection run.

## Latency tool note

The paper's own testbed used `wrk`. This repo uses a small Python
`ThreadPoolExecutor`-based generator (`scripts/load_test.py`) instead, so
the lab has no extra system dependency beyond Python + `requests`. If you
have `wrk` installed, feel free to swap it in — the audit log and blocking
behavior are unaffected by which load tool drives the traffic.
