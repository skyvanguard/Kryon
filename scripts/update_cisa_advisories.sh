#!/usr/bin/env bash
# update_cisa_advisories.sh
#
# F84.6 — Refresh the CISA ICS Advisory Project Master CSV into
# $KRYON_HOME/datasets/cisa_ics_advisories.csv so the loader picks it
# up in preference to the repo seed.
#
# Banking-safe notes:
#   - Only this script touches the network. The loader and correlator
#     are pure I/O on the local CSV.
#   - Designed for periodic (weekly) cron / systemd-timer refresh on
#     the operator workstation, NOT inside the kryon-kali container.
#     The container reads $KRYON_HOME via the volume mount.
#   - Source: github.com/icsadvprj/ICS-Advisory-Project (ODbL v1.0).
#     Attribution lives in repo NOTICE — do not strip.
#
# Usage:
#   bash scripts/update_cisa_advisories.sh
#   KRYON_HOME=/opt/kryon-data bash scripts/update_cisa_advisories.sh

set -euo pipefail

KRYON_HOME="${KRYON_HOME:-$HOME/.kryon}"
DATASET_DIR="${KRYON_HOME}/datasets"
TARGET="${DATASET_DIR}/cisa_ics_advisories.csv"
SOURCE_URL="https://raw.githubusercontent.com/icsadvprj/ICS-Advisory-Project/main/ICS-CERT_ADV/CISA_ICS_ADV_Master.csv"

echo "==> CISA ICS Advisories refresh"
echo "    target  : ${TARGET}"
echo "    source  : ${SOURCE_URL}"
echo

mkdir -p "${DATASET_DIR}"

# Atomic replace via .tmp + mv — avoid leaving a half-written file
# that the loader would happily parse and fail on mid-row.
TMP="${TARGET}.tmp"
echo "==> Downloading Master CSV (typically ~2.8 MB) ..."
if ! curl -sSfL --retry 3 --max-time 90 -o "${TMP}" "${SOURCE_URL}"; then
  echo "ERROR: download failed. Network or upstream availability issue." >&2
  rm -f "${TMP}"
  exit 1
fi

# Sanity check: must be a CSV with the icsad_ID header. If GitHub served
# a rate-limit HTML page instead, the loader would explode on parse.
if ! head -1 "${TMP}" | grep -q '^icsad_ID,'; then
  echo "ERROR: downloaded file does not look like the expected CSV." >&2
  echo "       First line: $(head -1 "${TMP}" | head -c 200)" >&2
  rm -f "${TMP}"
  exit 2
fi

ROWS=$(($(wc -l < "${TMP}") - 1))
echo "    rows downloaded: ${ROWS}"

mv "${TMP}" "${TARGET}"

echo
echo "==> Done. Loader will now prefer ${TARGET}."
echo "    Attribution: ICS Advisory Project, ODbL v1.0. Keep NOTICE intact."
