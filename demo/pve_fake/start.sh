#!/bin/sh
# Fake Proxmox boot: accept pubkey from /run/auditor_pubkey (mounted by
# compose), generate sshd host keys, start sshd + nginx.
set -eu

# Seed the authorized key (compose mounts the host-side pubkey here)
if [ -f /run/auditor_pubkey ]; then
    cp /run/auditor_pubkey /home/auditor/.ssh/authorized_keys
    chmod 600 /home/auditor/.ssh/authorized_keys
    chown auditor:auditor /home/auditor/.ssh/authorized_keys
fi

# Host keys (first run only)
ssh-keygen -A 2>/dev/null || true
mkdir -p /run/sshd

# Start nginx in background
nginx

# Foreground sshd
exec /usr/sbin/sshd -D -e
