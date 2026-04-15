#!/usr/bin/env bash
# Smoke test: build + up the vulnerable lab, probe each target to confirm
# the planted vulnerabilities are actually exposed. Use before the demo.
#
# Usage:
#   ./scripts/demo/smoke_lab.sh             # build + probe + leave up
#   ./scripts/demo/smoke_lab.sh --teardown  # tear down after probing
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker/vulnerable-lab/docker-compose.yml"
TEARDOWN=0
for arg in "$@"; do
  [[ "$arg" == "--teardown" ]] && TEARDOWN=1
done

say() { printf '\033[1;36m[smoke]\033[0m %s\n' "$*"; }
ok()  { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
fail(){ printf '\033[1;31m  ✗\033[0m %s\n' "$*"; EXIT_CODE=1; }

EXIT_CODE=0

say "bring up vulnerable-lab"
docker compose -f "$COMPOSE_FILE" up -d --build >/dev/null 2>&1
say "wait 10s for services to initialise"
sleep 10

# --- target-ssh ---------------------------------------------------------------
say "probe target-ssh (127.0.0.1:2222)"
# Portable port-open check using bash /dev/tcp (works on Linux/macOS/git-bash
# without external deps).
probe_port() {
  timeout 3 bash -c ": < /dev/tcp/$1/$2" 2>/dev/null
}

if probe_port 127.0.0.1 2222; then
  ok "SSH port 2222 open"
else
  fail "SSH port 2222 not reachable"
fi

# Pull banner over a short-lived bash tcp redirect.
ssh_banner="$(timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/2222; IFS= read -r line <&3 && echo \"\$line\"" 2>/dev/null | head -1 | tr -d '\r' || true)"
if [[ "$ssh_banner" == SSH-* ]]; then
  ok "SSH banner: $ssh_banner"
else
  fail "no SSH banner (got: ${ssh_banner:-<empty>})"
fi

# Planted CWE-521: verify PermitRootLogin yes is actually in the config.
# MSYS_NO_PATHCONV=1 prevents git-bash from mangling Linux paths on Windows.
if MSYS_NO_PATHCONV=1 docker exec kryon-lab-ssh grep -E '^PermitRootLogin yes' /etc/ssh/sshd_config >/dev/null 2>&1; then
  ok "planted CWE-521: PermitRootLogin yes confirmed in sshd_config"
else
  fail "CWE-521 NOT planted — check target-ssh Dockerfile"
fi

# --- target-web ---------------------------------------------------------------
say "probe target-web (127.0.0.1:8080)"
if curl -sS -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:8080/ | grep -q 200; then
  ok "HTTP / returns 200"
else
  fail "HTTP / unreachable"
fi

# Planted CWE-306: /admin must be open (200, no auth)
admin_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:8080/admin 2>/dev/null || echo FAIL)"
if [[ "$admin_code" == "200" ]]; then
  ok "planted CWE-306: /admin returns 200 without auth"
else
  fail "/admin should return 200 (got $admin_code)"
fi

# Planted CWE-200: Server header leaks nginx version.
server_hdr="$(curl -sSI --max-time 3 http://127.0.0.1:8080/ | grep -i '^Server:' | head -1 | tr -d '\r')"
if [[ "$server_hdr" == *nginx/* ]]; then
  ok "planted CWE-200: $server_hdr"
else
  fail "server token not leaked (expected for demo)"
fi

# --- target-db ----------------------------------------------------------------
say "probe target-db (127.0.0.1:33060)"
if probe_port 127.0.0.1 33060; then
  ok "MySQL port 33060 open"
else
  fail "MySQL port 33060 not reachable"
fi

# Planted CWE-319: config should NOT have an UNCOMMENTED
# require_secure_transport=on directive.
if MSYS_NO_PATHCONV=1 docker exec kryon-lab-db cat /etc/mysql/conf.d/zz_demo.cnf \
     | grep -E '^[^#]*require_secure_transport\s*=\s*on' >/dev/null 2>&1; then
  fail "require_secure_transport=on is set — not vulnerable (broken plant)"
else
  ok "planted CWE-319: no active require_secure_transport in mysql config"
fi

# --- summary ------------------------------------------------------------------
say "summary"
if [[ $EXIT_CODE -eq 0 ]]; then
  printf '\033[1;32m  all planted vulnerabilities confirmed — lab ready for Kryon demo\033[0m\n'
else
  printf '\033[1;31m  one or more plants failed — fix before demo\033[0m\n'
fi

if [[ $TEARDOWN -eq 1 ]]; then
  say "teardown"
  docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1
  ok "lab torn down"
else
  say "lab left up. Run '$0 --teardown' when done."
fi

exit $EXIT_CODE
