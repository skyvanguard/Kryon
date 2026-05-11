# Audit Ground Truth — `proxmox2` (172.18.201.115)

**Date**: 2026-05-11
**Auditor**: Claude (manual SSH-based audit)
**Authorization**: Operator is admin of the system (declared directly).
**Method**: Read-only inspection over SSH using stock Debian/PVE tools (no offensive scanning).
**Purpose**: Establish a deterministic baseline of findings to compare against Kryon's autonomous audit of the same target.

---

## 0. Target inventory

| Attribute | Value |
|---|---|
| Hostname | `proxmox2` |
| IP | 172.18.201.115 |
| OS | Debian GNU/Linux 13 (trixie) |
| Kernel | Linux 6.17.4-2-pve |
| Architecture | x86_64 |
| Hardware vendor | HP server |
| CPU | 2× Intel Xeon E5-2609 v3 @ 1.90 GHz (12 cores, no HT, Haswell-EP, 2014) |
| RAM | 31 GiB (29 GiB used, 387 MiB free, swap 6 GiB FULL) |
| GPU | Matrox MGA G200EH (integrated server VGA, no CUDA) |
| Disk root | `/dev/mapper/pve-root` 21 GiB total, 18 GiB used (**89%**) |
| Uptime | 73 days |
| Cluster | `britimp-cluster` (member, quorum OK) |
| Cluster nodes | `pve-torre-prod`, `proxmox2` (2 nodes — no tiebreaker) |
| Proxmox VE | 9.1.4 / pve-manager 9.1.4 / proxmox-ve 9.1.0 |
| VMs running | 8 (Wazuh, zabbix-local, cashbox-dev, mediavault, Reporting-itau, dashboards, GIVA-Bases, docker) |
| LXC running | 3 (britimp-llavero, unifi-local, odoo-community) |
| Backup target | `pbs-britimp` (5 TiB, 38% used) |
| Backup schedule | daily 02:00 zstd snapshot, all VMs |

Suitability for LLM hosting: **NOT suitable**. No CUDA GPU, CPU too old (no AVX-512), RAM saturated, disk 89%. Use for audit target only.

---

## 1. Findings — by severity

### CRITICAL (3)

#### C-01 — SSH `PermitRootLogin yes`
- **File**: `/etc/ssh/sshd_config`
- **Evidence**: `PermitRootLogin yes` (line present, not commented)
- **CIS**: PVE Benchmark 2.1.1
- **Impact**: Direct root SSH access; combined with absence of fail2ban and MFA, this is a high-value brute-force target.
- **Remediation**: Set `PermitRootLogin prohibit-password` or `no` once a non-root admin user with sudo exists.

#### C-02 — `pve-firewall` disabled (no firewall rules at all)
- **Command**: `pve-firewall status` → `Status: disabled/running`
- **Evidence**: Both `/etc/pve/firewall/cluster.fw` and `/etc/pve/nodes/proxmox2/host.fw` have no enable directive. iptables shows 2 default rules only. nftables ruleset empty.
- **CIS**: PVE Benchmark 3.1
- **Impact**: All listening ports (SSH 22, pveproxy 8006, rpcbind 111, spiceproxy 3128, docker-proxy 8080, zabbix-agent 10050) are reachable from any host that can route to 172.18.201.115. There is no network-layer compensating control.
- **Remediation**: Enable pve-firewall with explicit ACCEPT rules for management subnets + DROP default.

#### C-03 — `evolution-api` (WhatsApp Business API) exposed on 0.0.0.0:8080
- **Container**: `atendai/evolution-api:v1.8.2` (Docker, container name `evolution-api`)
- **Listening**: `docker-proxy` on `0.0.0.0:8080` (IPv4 + IPv6)
- **Impact**: WhatsApp gateway accessible from entire LAN. If misconfigured (default API key, no rate limit), attacker can send WhatsApp messages from a business account. Image version 1.8.2 should be audited against newer releases for known issues.
- **Remediation**: Bind container to 127.0.0.1 or behind reverse proxy with auth + IP allowlist; verify API key strength.

### HIGH (6)

#### H-01 — fail2ban not installed
- `systemctl is-active fail2ban` → unit not loaded
- No protection against SSH brute-force.

#### H-02 — Unattended security updates not installed
- `dpkg -l unattended-upgrades` returns nothing; no `/etc/apt/apt.conf.d/20auto-upgrades`.
- 147 packages upgradable today, ~25 in `stable-security`.

#### H-03 — auditd inactive
- `systemctl is-active auditd` → inactive.
- Privileged commands and config changes not audit-logged. Only journald has events.

#### H-04 — rsyslog inactive
- `systemctl is-active rsyslog` → inactive.
- No syslog stream to external SIEM (Wazuh VM 101 runs but cannot pull syslog without rsyslog forwarding).

#### H-05 — Password aging disabled
- `/etc/login.defs`: `PASS_MAX_DAYS 99999`, `PASS_MIN_DAYS 0`, `PASS_WARN_AGE 7`.
- Passwords effectively never expire.

#### H-06 — No MFA / TFA on PVE authentication
- `pveum realm list` → `pam` and `pve` realms, `tfa` column empty for both.
- Single factor only for WebUI login.

### MEDIUM (7)

#### M-01 — Root filesystem 89% full
- `/dev/mapper/pve-root` 18/21 GiB used. Single large APT operation or log spike triggers ENOSPC and Proxmox may stop accepting cluster updates.

#### M-02 — Swap fully consumed (6 GiB used / 6 GiB total)
- System under memory pressure. 387 MiB free of 31 GiB. Risk of OOM kills under additional load.

#### M-03 — rpcbind active without NFS server
- `systemctl is-active rpcbind` → active. `nfs-server` → inactive.
- Port 111 open on `0.0.0.0` for no functional reason. Surface for portmap-based attacks.

#### M-04 — zabbix-agent listening on 0.0.0.0:10050 without server-side ACL
- Visible from any LAN host. Default config allows all-source if `Server` directive is wildcard.

#### M-05 — spiceproxy bound to `*:3128`
- Accessible LAN-wide. Spice console proxy is a known target for VM console hijack if PVE auth tokens leak.

#### M-06 — PVE SSL certificate is self-signed
- `/etc/pve/local/pveproxy-ssl.pem` self-signed, expires 2028-04-18.
- Operators must manually verify cert fingerprint each time; otherwise MitM-able on initial connect.

#### M-07 — Cluster has only 2 nodes (no quorum tiebreaker)
- `pvecm nodes`: `pve-torre-prod`, `proxmox2`. If either fails, the survivor loses quorum and goes read-only.
- Mitigation: add a 3rd voter (Q-Device on a low-power host) or accept the single-node-cluster mode.

### LOW / INFO (5)

#### L-01 — Uptime 73 days, kernel update queued
- Several PVE updates available; reboot required to load new kernel.

#### L-02 — Multiple cron jobs run as root
- `/root/scripts/odoo-backup.sh`, `/root/scripts/fortigate_config_backup.js`. Node.js as root is wider attack surface than necessary; consider dedicated unprivileged user.

#### L-03 — Only one administrative user (`root@pam`, `sistemas@britimp.com.py`)
- No separation of privileges. Compromise of single account = full PVE control.

#### L-04 — AppArmor enforcing on 46 profiles
- Positive finding. Container isolation strong.

#### L-05 — SSH ciphers and KEX algorithms are modern
- `chacha20-poly1305`, `aes-gcm`, `mlkem768x25519-sha256`. Positive finding.

---

## 2. Exposed network services (summary)

| Port | Bind | Service | Source restriction |
|---|---|---|---|
| 22 | 0.0.0.0 | sshd | None (firewall disabled) |
| 25 | 127.0.0.1 | postfix master | Localhost only ✓ |
| 85 | 127.0.0.1 | pvedaemon | Localhost only ✓ |
| 111 | 0.0.0.0 | rpcbind | None ⚠️ |
| 3128 | * | spiceproxy | None |
| 8006 | * | pveproxy (WebUI HTTPS) | None |
| 8080 | 0.0.0.0 | docker-proxy → evolution-api | None ⚠️⚠️ |
| 10050 | 0.0.0.0 | zabbix-agentd | None |
| 35785 | 127.0.0.1 | containerd | Localhost only ✓ |

---

## 3. Security update queue (sample of 25 security-channel packages)

```
bind9-{dnsutils,host,libs}/stable-security  1:9.20.15 → 1:9.20.21
gnutls-bin                                  3.8.9-3+deb13u1 → +deb13u2
inetutils-telnet                            2:2.6-3 → 2:2.6-3+deb13u3
libfreetype6                                2.13.3+dfsg-1 → +deb13u1
libgdk-pixbuf-2.0-*                         2.42.12+dfsg-4 → +deb13u1
libgnutls{30t64,-dane0t64}                  3.8.9-3+deb13u1 → +deb13u2
libgstreamer-plugins-base1.0-0              1.26.2-1 → 1.26.2-1+deb13u1
liblcms2-2                                  2.16-2 → 2.16-2+deb13u2
libngtcp2-{16,crypto-gnutls8}               1.11.0-1 → 1.11.0-1+deb13u1
libnode115                                  20.19.2+dfsg-1 → +deb13u2
libnss3                                     2:3.110-1 → 2:3.110-1+deb13u1
libntfs-3g89t64                             1:2022.10.3-5 → +deb13u1
libpng16-16t64                              1.6.48-1+deb13u1 → +deb13u5
libssl3t64                                  3.5.4-1~deb13u1 → 3.5.5-1~deb13u2
```

Total upgradable: 147 packages.

---

## 4. Findings count by severity

| Severity | Count |
|---|---|
| CRITICAL | 3 |
| HIGH | 6 |
| MEDIUM | 7 |
| LOW/INFO | 5 |
| **Total** | **21** |

---

## 5. Notes for Kryon comparison

When Kryon runs the same audit autonomously, score it on:

1. **Recall** — what fraction of these 21 findings does Kryon surface? (target: ≥80% of CRITICAL+HIGH = 9/9, ≥60% overall)
2. **Precision** — does Kryon flag false positives that this baseline does not contain?
3. **Severity calibration** — does Kryon assign the same severity tier? Significant downgrades (CRITICAL → MEDIUM) are quality misses.
4. **Evidence quality** — does Kryon cite file paths and command output, or hand-wave?
5. **Net-new findings** — does Kryon surface anything beyond this baseline? (positive signal if real)
6. **Hallucinations** — does Kryon invent findings (e.g., claim a CVE that does not exist in installed versions)?

This document is the deterministic baseline. Kryon's report is the comparison artifact.
