#!/usr/bin/env bash
# evidence_run.sh — run a command with a timestamp header and persistent
# per-line timestamped log under ~/Kryon/evidence/<campaign>/.
#
# Usage: evidence_run.sh <campaign> <label> -- <command...>
# Example: evidence_run.sh research-libfoo poc -- http :3000/api/1
# Output goes to stdout AND <evidence>/<campaign>/<label>_<UTCstamp>.log
set -u
EVIDENCE_ROOT="${EVIDENCE_ROOT:-$HOME/Kryon/evidence}"
if [ $# -lt 3 ] || [ "$3" != "--" ]; then
  echo "Usage: $(basename "$0") <campaign> <label> -- <command...>" >&2
  exit 2
fi
CAMPAIGN="$1"
LABEL="$2"
shift 3
DIR="$EVIDENCE_ROOT/$CAMPAIGN"
mkdir -p "$DIR" || {
  echo "cannot create $DIR" >&2
  exit 1
}
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$DIR/${LABEL}_${STAMP}.log"
{
  echo "# command: $*"
  echo "# started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# host: $(hostname) user: $(id -un)"
  set +e
  "$@" 2>&1
  RC=$?
  set -e
  echo "# exit: $RC"
  echo "# finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  exit "$RC"
} | ts '%Y-%m-%dT%H:%M:%SZ ' | tee "$LOG"
RC=${PIPESTATUS[0]}
echo "# log saved: $LOG" >&2
exit "$RC"
