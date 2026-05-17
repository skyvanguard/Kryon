#!/usr/bin/env bash
# F174/F175 — Parametric bench harness with multi-target + replicates.
#
# Runs N replicates of a Kryon engage against a chosen vulnerable web
# target, with a chosen model. Each replicate gets its own engagement
# ID + cleared scan cache + isolated report dir. Per-run stats are
# appended to ``scripts/bench_results.csv``; an averaged summary line
# is appended to ``scripts/bench_summary.csv``.
#
# Usage:
#   bash scripts/bench_target.sh <MODEL> [TARGET] [RUNS]
#
# Examples:
#   bash scripts/bench_target.sh kryon-gpt-oss            # juice_shop, 1 run
#   bash scripts/bench_target.sh kryon-gpt-oss dvwa 3     # DVWA, 3 replicates
#   bash scripts/bench_target.sh kryon-14b webgoat 3
#
# Supported targets (resolved to container name + port + objective):
#   juice_shop | dvwa | bwapp | webgoat
#
# Env knobs (all optional):
#   KRYON_PHASE_TURNS   override F166 per-phase cap
#   BENCH_OUT_BASE      override report parent dir (default: /workspace/reports)
#   BENCH_TIMEOUT       per-replicate timeout in seconds (default: 1800)

set -euo pipefail

MODEL="${1:-kryon-14b}"
TARGET="${2:-juice_shop}"
RUNS="${3:-1}"
TIMEOUT_SECS="${BENCH_TIMEOUT:-1800}"
OUT_BASE="${BENCH_OUT_BASE:-/workspace/reports}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_CSV="${SCRIPT_DIR}/bench_results.csv"
SUMMARY_CSV="${SCRIPT_DIR}/bench_summary.csv"

# F174 — target catalog. Each entry resolves to (container, url, objective).
case "$TARGET" in
  juice_shop)
    CONTAINER="juice_shop"
    URL="http://juice_shop:3000"
    OBJECTIVE="find SQLi or XSS or RCE in juice shop"
    ;;
  dvwa)
    CONTAINER="dvwa"
    URL="http://dvwa:80"
    OBJECTIVE="find SQLi or XSS or RCE or command injection in DVWA"
    ;;
  bwapp)
    CONTAINER="bwapp"
    URL="http://bwapp:80"
    OBJECTIVE="find SQLi or XSS or RCE or LDAP injection in bWAPP"
    ;;
  webgoat)
    CONTAINER="webgoat"
    URL="http://webgoat:8080/WebGoat"
    OBJECTIVE="find SQLi or XSS or auth bypass in WebGoat"
    ;;
  *)
    echo "ERROR: unknown target '$TARGET'. Supported: juice_shop, dvwa, bwapp, webgoat" >&2
    exit 2
    ;;
esac

echo "═══════════════════════════════════════════════════════════════"
echo "  F174/F175 — Multi-target bench"
echo "  model:    ${MODEL}"
echo "  target:   ${TARGET} (${URL})"
echo "  runs:     ${RUNS}"
echo "  timeout:  ${TIMEOUT_SECS}s/run"
echo "═══════════════════════════════════════════════════════════════"

# Ensure target container is up. WebGoat / DVWA take longer to settle
# than juice_shop, so add a configurable boot delay.
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
  echo "Starting ${CONTAINER}..."
  docker start "$CONTAINER" >/dev/null 2>&1 || {
    echo "ERROR: container '${CONTAINER}' does not exist. See docker/docker-compose.bench.yml."
    exit 3
  }
  sleep 5
fi

# Per-run stat arrays (bash 4+).
declare -a RUN_FINDINGS RUN_CVES RUN_WALLCLOCK RUN_VERDICTS

# Ensure CSV headers exist.
if [ ! -f "${RESULTS_CSV}" ]; then
  echo "timestamp,model,target,run,engagement_id,findings,cve_count_in_findings,wall_clock_s,verdict" > "${RESULTS_CSV}"
fi
if [ ! -f "${SUMMARY_CSV}" ]; then
  echo "timestamp,model,target,runs,findings_avg,findings_stddev,findings_min,findings_max,wall_clock_avg_s,satisfied_count" > "${SUMMARY_CSV}"
fi

for RUN in $(seq 1 "$RUNS"); do
  TS="$(date +%s)"
  ENGAGEMENT_ID="bench-${MODEL//[^a-zA-Z0-9]/_}-${TARGET}-r${RUN}-${TS}"
  OUT_DIR="${OUT_BASE}/${ENGAGEMENT_ID}"
  LOG_FILE="/tmp/${ENGAGEMENT_ID}.log"

  echo ""
  echo "──────────────── run ${RUN}/${RUNS} ────────────────"
  echo "  engagement: ${ENGAGEMENT_ID}"

  # Clear scan cache so replicate doesn't reuse prior failures/successes.
  MSYS_NO_PATHCONV=1 docker exec kryon bash -c 'rm -rf /workspace/.kryon_cache 2>/dev/null || true'

  START_TS=$(date +%s)

  MSYS_NO_PATHCONV=1 docker exec -d \
    -e "KRYON_MODEL=${MODEL}" \
    -e KRYON_CVE_VALIDATE=true \
    -e KRYON_REQUIRE_GROUNDING=true \
    -e KRYON_ADVERSARIAL_STRICT=true \
    -e KRYON_REDACT_PAN=true \
    -e KRYON_RED_TEAM=true \
    -e KRYON_CVE_APPLICABILITY=true \
    -e KRYON_FINDING_APPLICABILITY=true \
    ${KRYON_PHASE_TURNS:+-e KRYON_PHASE_TURNS=${KRYON_PHASE_TURNS}} \
    ${KRYON_REASONING_EFFORT:+-e KRYON_REASONING_EFFORT=${KRYON_REASONING_EFFORT}} \
    kryon /bin/bash -c "
      /opt/venv/bin/kryon engage ${URL} \
        --orchestrated \
        --objective '${OBJECTIVE}' \
        --client bench \
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

  WAITED=0
  while docker exec kryon ps -eo cmd 2>/dev/null | grep -q "kryon engage.*${ENGAGEMENT_ID}"; do
    sleep 10
    WAITED=$((WAITED + 10))
    if [ "$WAITED" -ge "$TIMEOUT_SECS" ]; then
      echo "  TIMEOUT after ${TIMEOUT_SECS}s — killing"
      docker exec kryon pkill -9 -f "${ENGAGEMENT_ID}" || true
      break
    fi
    if [ $((WAITED % 120)) -eq 0 ]; then
      echo "  ...still running (${WAITED}s elapsed)"
    fi
  done

  END_TS=$(date +%s)
  WALL_CLOCK=$((END_TS - START_TS))

  FINDING_COUNT=$(docker exec kryon bash -c "
    FJ=\$(ls -1 ${OUT_DIR}/*.findings.json 2>/dev/null | head -1)
    if [ -n \"\$FJ\" ]; then
      python3 -c \"import json; d=json.load(open('\$FJ')); print(len(d) if isinstance(d, list) else len(d.get('findings', [])))\"
    else
      echo 0
    fi
  " 2>/dev/null || echo 0)

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

  RUN_FINDINGS+=("$FINDING_COUNT")
  RUN_CVES+=("$HALLUC_HINT")
  RUN_WALLCLOCK+=("$WALL_CLOCK")
  RUN_VERDICTS+=("$VERDICT")

  echo "  findings=${FINDING_COUNT} cves=${HALLUC_HINT} wall=${WALL_CLOCK}s verdict=${VERDICT}"
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),${MODEL},${TARGET},${RUN},${ENGAGEMENT_ID},${FINDING_COUNT},${HALLUC_HINT},${WALL_CLOCK},${VERDICT}" >> "${RESULTS_CSV}"
done

# F175 — averaged summary across replicates.
N="${#RUN_FINDINGS[@]}"
SUM_F=0
MIN_F=999999
MAX_F=0
SUM_WC=0
SATISFIED=0
for i in "${!RUN_FINDINGS[@]}"; do
  F=${RUN_FINDINGS[$i]}
  WC=${RUN_WALLCLOCK[$i]}
  V=${RUN_VERDICTS[$i]}
  SUM_F=$((SUM_F + F))
  SUM_WC=$((SUM_WC + WC))
  if [ "$F" -lt "$MIN_F" ]; then MIN_F=$F; fi
  if [ "$F" -gt "$MAX_F" ]; then MAX_F=$F; fi
  if [ "$V" = "SATISFIED" ]; then SATISFIED=$((SATISFIED + 1)); fi
done

AVG_F=$(python3 -c "print(f'{${SUM_F}/${N}:.2f}')")
AVG_WC=$(python3 -c "print(f'{${SUM_WC}/${N}:.1f}')")
# Standard deviation (population) for N >= 1; for N==1 it's 0.
STDDEV_F=$(python3 -c "
import math
vals=[${RUN_FINDINGS[@]/%/,}]
m=sum(vals)/len(vals)
v=sum((x-m)**2 for x in vals)/len(vals)
print(f'{math.sqrt(v):.2f}')
")

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),${MODEL},${TARGET},${N},${AVG_F},${STDDEV_F},${MIN_F},${MAX_F},${AVG_WC},${SATISFIED}" >> "${SUMMARY_CSV}"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Summary (${N} replicate(s))"
echo "  model:           ${MODEL}"
echo "  target:          ${TARGET}"
echo "  findings avg:    ${AVG_F} (stddev=${STDDEV_F}, min=${MIN_F}, max=${MAX_F})"
echo "  wall clock avg:  ${AVG_WC}s"
echo "  satisfied runs:  ${SATISFIED}/${N}"
echo "  per-run csv:     ${RESULTS_CSV}"
echo "  summary csv:     ${SUMMARY_CSV}"
echo "═══════════════════════════════════════════════════════════════"
