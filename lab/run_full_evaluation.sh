#!/usr/bin/env bash
# Runs the complete evaluation cycle described in Section III of the paper:
# attack corpus + legitimate corpus against both the WAF and the baseline,
# then the audit-log rule analysis. Results land in ./results/.
set -euo pipefail
cd "$(dirname "$0")"

PY=python3
if [ -x "/home/marc/.venvs/lab/bin/python3" ]; then
    PY="/home/marc/.venvs/lab/bin/python3"
fi

echo "== Bringing up the lab (juice-shop, waf, baseline) =="
docker compose up -d
echo "Waiting for services to warm up..."
sleep 8

mkdir -p results

echo
echo "== Attack corpus vs. WAF (localhost:8080) =="
"$PY" scripts/run_attacks.py --target http://localhost:8080 --out results/attacks_waf.json

echo
echo "== Attack corpus vs. baseline, no WAF (localhost:8081) =="
"$PY" scripts/run_attacks.py --target http://localhost:8081 --out results/attacks_baseline.json

echo
echo "== Legitimate traffic vs. WAF (false-positive check) =="
"$PY" scripts/legit_traffic.py --target http://localhost:8080 --count 500 --out results/legit_waf.json

echo
echo "== Latency: baseline vs. WAF at concurrency 20 =="
"$PY" scripts/load_test.py --target http://localhost:8081 --concurrency 20 --requests 500 --out results/latency_baseline_c20.json
"$PY" scripts/load_test.py --target http://localhost:8080 --concurrency 20 --requests 500 --out results/latency_waf_c20.json

echo
echo "== Capturing and analyzing the ModSecurity audit log =="
docker compose logs -t --no-color waf > results/waf_raw.log
"$PY" scripts/analyze_audit_log.py results/waf_raw.log

echo
echo "Done. Raw results are in ./results/."
