#!/usr/bin/env bash
# F169 — Parametric Juice Shop bench harness.
#
# Runs a single Kryon engage against the local juice_shop container with
# a given model, extracts findings + hallucinations + wall-clock, and
# appends one CSV row to ``scripts/bench_results.csv``.
#
# Usage:
#   bash scripts/bench_juice_shop.sh kryon-14b
#   bash scripts/bench_juice_shop.sh kryon-gpt-oss
#   bash scripts/bench_juice_shop.sh kryon-r1-14b
#
# Optional env:
#   KRYON_PHASE_TURNS   override per-phase cap (default: F166 auto)
#   BENCH_OUT_DIR       override report output dir (default: /workspace/reports/bench-<model>-<ts>)
#   BENCH_SEED          tag for the engagement id (default: current epoch)
#
# Assumes: kryon container + kryon-ollama container + juice_shop container
# all running on the docker default network with the names above.

set -euo pipefail

MODEL="${1:-kryon-14b}"
TS="${BENCH_SEED:-$(date +%s)}"
ENGAGEMENT_ID="bench-${MODEL//[^a-zA-Z0-9]/_}-${TS}"
OUT_DIR="${BENCH_OUT_DIR:-/workspace/reports/${ENGAGEMENT_ID}}"
LOG_FILE="/tmp/${ENGAGEMENT_ID}.log"
RESULTS_CSV="$(dirname "$0")/bench_results.csv"

echo "═══════════════════════════════════════════════════════════════"
echo "  F169 — Juice Shop bench"
echo "  model:      ${MODEL}"
echo "  engagement: ${ENGAGEMENT_ID}"
echo "  log:        ${LOG_FILE}"
echo "═══════════════════════════════════════════════════════════════"

# Ensure juice_shop is up.
if ! docker ps --format '{{.Names}}' | grep -q '^juice_shop$'; then
  docker start juice_shop >/dev/null
  sleep 3
fi

# Clear scan cache so the run starts fresh.
MSYS_NO_PATHCONV=1 docker exec kryon bash -c 'rm -rf /workspace/.kryon_cache 2>/dev/null || true'

START_TS=$(date +%s)

# Launch detached and tail until completion.
MSYS_NO_PATHCONV=1 docker exec -d \
  -e "KRYON_MODEL=${MODEL}" \
  -e KRYON_CVE_VALIDATE=true \
  -e KRYON_REQUIRE_GROUNDING=true \
  -e KRYON_ADVERSARIAL_STRICT=true \
  -e KRYON_REDACT_PAN=true \
  -e KRYON_RED_TEAM=true \
  ${KRYON_PHASE_TURNS:+-e KRYON_PHASE_TURNS=${KRYON_PHASE_TURNS}} \
  kryon /bin/bash -c "
    /opt/venv/bin/kryon engage http://juice_shop:3000 \
      --orchestrated \
      --objective 'find SQLi or XSS or RCE in juice shop' \
      --client juice-shop \
      --engagement-id ${ENGAGEMENT_ID} \
      --max-turns 30 \
      --max-cost 5.0 \
      --classification INTERNAL \
      --dry-run-only \
      --skip-reaudit \
      --out ${OUT_DIR} \
      --nmap-timeout 60 \
      > ${LOG_FILE} 2>&1
  "

# Poll for engage completion (process named kryon engage).
echo "Waiting for engagement to finish..."
TIMEOUT_SECS=1800  # 30 min hard cap
WAITED=0
while docker exec kryon ps -eo cmd 2>/dev/null | grep -q "kryon engage.*${ENGAGEMENT_ID}"; do
  sleep 10
  WAITED=$((WAITED + 10))
  if [ "$WAITED" -ge "$TIMEOUT_SECS" ]; then
    echo "TIMEOUT after ${TIMEOUT_SECS}s — killing engage."
    docker exec kryon pkill -9 -f "${ENGAGEMENT_ID}" || true
    break
  fi
  if [ $((WAITED % 60)) -eq 0 ]; then
    echo "  ...still running (${WAITED}s elapsed)"
  fi
done

END_TS=$(date +%s)
WALL_CLOCK=$((END_TS - START_TS))

# Extract findings from the JSON report. The filename pattern varies
# (sometimes with date, sometimes without), so use a glob over the dir.
FINDING_COUNT=$(docker exec kryon bash -c "
  FJ=\$(ls -1 ${OUT_DIR}/*.findings.json 2>/dev/null | head -1)
  if [ -n \"\$FJ\" ]; then
    python3 -c \"import json; d=json.load(open('\$FJ')); print(len(d) if isinstance(d, list) else len(d.get('findings', [])))\"
  else
    echo NA
  fi
" 2>/dev/null || echo NA)

HALLUC_HINT=$(docker exec kryon bash -c "
  FJ=\$(ls -1 ${OUT_DIR}/*.findings.json 2>/dev/null | head -1)
  if [ -n \"\$FJ\" ]; then
    grep -oE 'CVE-[0-9]{4}-[0-9]{4,7}' \"\$FJ\" 2>/dev/null | sort -u | wc -l
  else
    echo 0
  fi
" 2>/dev/null || echo 0)

VERDICT=$(docker exec kryon bash -c "
  grep -oE 'engagement verdict: [A-Z_]+' '${LOG_FILE}' | head -1 | awk '{print \$NF}'
" 2>/dev/null || echo UNKNOWN)

# Append to results CSV (create header if missing).
if [ ! -f "${RESULTS_CSV}" ]; then
  echo "timestamp,model,engagement_id,findings,cve_count_in_findings,wall_clock_s,verdict" > "${RESULTS_CSV}"
fi
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),${MODEL},${ENGAGEMENT_ID},${FINDING_COUNT},${HALLUC_HINT},${WALL_CLOCK},${VERDICT}" >> "${RESULTS_CSV}"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Result"
echo "  model:        ${MODEL}"
echo "  findings:     ${FINDING_COUNT}"
echo "  cves_in_findings: ${HALLUC_HINT}"
echo "  wall_clock:   ${WALL_CLOCK}s"
echo "  verdict:      ${VERDICT}"
echo "  log:          ${LOG_FILE}"
echo "  csv row:      ${RESULTS_CSV}"
echo "═══════════════════════════════════════════════════════════════"
