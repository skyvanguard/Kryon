#!/usr/bin/env bash
# F26.1 — bring up the reproducible vulnerable lab in ONE command.
#
#   $ cd demo && bash setup.sh
#
# Fully idempotent. Running twice = no-op plus fresh PDF if you re-run
# the audit at the end.
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd .. && pwd)"

hr() { printf '\n==============================================\n'; }
say() { printf '  %s\n' "$*"; }

hr
say "Kryon F26 — one-command lab bootstrap"
hr

# 0. Ensure the kryon stack is running. If not, start it first.
if ! docker ps --format '{{.Names}}' | grep -qx kryon; then
    say "kryon container not running — starting the main stack first"
    (cd "$REPO_ROOT" && docker compose \
        -f docker/docker-compose.kali.yml \
        -f docker/docker-compose.override.yml up -d kryon)
    sleep 5
fi

# 1. ctfnet network (needed before starting targets; override compose
#    now auto-joins kryon to ctfnet on restart, but creating it first
#    here keeps the flow idempotent even on clean machines).
if ! docker network inspect ctfnet >/dev/null 2>&1; then
    say "creating network: ctfnet"
    docker network create ctfnet >/dev/null
fi

# 2. Attach kryon to ctfnet if it isn't already (safe on repeat runs).
if ! docker network inspect ctfnet --format '{{range $k,$v := .Containers}}{{.Name}} {{end}}' \
     | tr ' ' '\n' | grep -qx kryon; then
    say "attaching kryon → ctfnet"
    docker network connect ctfnet kryon >/dev/null 2>&1 || true
fi

# 3. Demo SSH key (ed25519; generated once, kept across reruns).
mkdir -p .ssh
if [ ! -f .ssh/demo_key ]; then
    say "generating demo SSH key at demo/.ssh/demo_key"
    ssh-keygen -q -N "" -t ed25519 -f .ssh/demo_key -C "kryon-demo"
else
    say "demo SSH key already present"
fi

# 4. Build + start targets.
say "building pve_fake image..."
docker compose -f docker-compose.demo.yml build --quiet pve_fake
say "starting targets (pve_fake + juice_shop)..."
docker compose -f docker-compose.demo.yml up -d
sleep 4

# 5. Ensure openssh-client is in kryon (Dockerfile.kali declares it but
#    older images might be cached without it).
if ! docker exec kryon sh -c 'command -v ssh >/dev/null 2>&1'; then
    say "installing openssh-client inside kryon (one-shot)"
    docker exec -u 0 kryon bash -c 'apt-get update -qq && apt-get install -y --no-install-recommends openssh-client >/dev/null'
fi

# 6. Install the demo key inside kryon. We don't rely on ${HOME}/.ssh
#    bind-mount — the demo key lives in repo/demo/.ssh/, separate from the
#    operator's personal ~/.ssh. `docker cp` drops it in directly. The
#    target path (/home/kryon/kryon_keys) is owned by kryon with 700 perms
#    so sshd doesn't complain about Docker Desktop Windows 777 bind-mounts.
docker exec -u 0 kryon install -d -m 700 -o kryon -g kryon /home/kryon/kryon_keys
docker cp .ssh/demo_key "kryon:/home/kryon/kryon_keys/demo_key" >/dev/null
docker exec -u 0 kryon bash -c 'chmod 600 /home/kryon/kryon_keys/demo_key && chown kryon:kryon /home/kryon/kryon_keys/demo_key'

# 7. Smoke SSH: kryon → pve_fake.
say "smoke SSH kryon → pve_fake"
MSYS_NO_PATHCONV=1 docker exec kryon ssh \
    -F /dev/null \
    -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile=/tmp/kryon_known_hosts \
    -o BatchMode=yes \
    -o IdentitiesOnly=yes \
    -i /home/kryon/kryon_keys/demo_key \
    auditor@pve_fake 'echo "  pve_fake hostname: $(hostname)"'

hr
say "Lab ready. To run a full compliance audit that will produce a real PDF:"
cat <<'EOF'

  MSYS_NO_PATHCONV=1 docker exec \
      -e KRYON_SSH_USER=auditor \
      -e KRYON_SSH_KEY=/home/kryon/kryon_keys/demo_key \
      -e KRYON_CLIENT_NAME="Banco Demo Paraguay S.A." \
      kryon python -c '
  from kryon.tools.appsec.compliance_audit import _run_compliance_pdf
  print(_run_compliance_pdf(
      host="pve_fake", framework="proxmox",
      ssh_user="auditor",
      ssh_key_path="/home/kryon/kryon_keys/demo_key",
      client_name="Banco Demo Paraguay S.A.",
  ))'

  Expected: 6 FAIL + 1 PASS, PDF in ../reports/

  Tear down:
      docker compose -f docker-compose.demo.yml down -v

EOF
hr
