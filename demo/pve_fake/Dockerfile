# Fake Proxmox VE node — Debian slim with misconfigurations that Kryon's
# 7 PVE-x.x checks should detect. Intentional bad state:
#   PVE-1.1 FAIL  self-signed cert at /etc/pve/local/pve-ssl.pem
#   PVE-1.2 PASS  nginx returns 401 on privileged paths
#   PVE-2.1 FAIL  sshd PermitRootLogin=yes PasswordAuthentication=yes
#   PVE-3.1 FAIL  domains.cfg has no default-tfa; 3 users without TFA
#   PVE-3.2 FAIL  token.cfg is 644; 2 tokens no-expiry bound to root
#   PVE-4.1 FAIL  pve-firewall stub reports disabled + cluster.fw enable=0
#   PVE-5.1 FAIL  pveversion stub reports 7.2 (EOL); apt-get -s upgrade 42 pending

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-server \
      openssl \
      curl \
      nginx \
      ca-certificates \
      procps \
      iproute2 \
      passwd \
      adduser \
  && rm -rf /var/lib/apt/lists/*

# SSH auditor user (no sudo needed — checks read config files via SSH)
RUN adduser --disabled-password --gecos "" auditor && \
    install -d -m 700 -o auditor -g auditor /home/auditor/.ssh

# Weak SSH config (intentional)
RUN sed -i \
      -e 's/^#*PermitRootLogin.*/PermitRootLogin yes/' \
      -e 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' \
      -e 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' \
      /etc/ssh/sshd_config

# Proxmox config tree
RUN mkdir -p /etc/pve/local /etc/pve/priv /etc/pve/firewall

# PVE-1.1: self-signed cert, 90-day lifetime
RUN openssl req -x509 -newkey rsa:2048 -keyout /etc/pve/local/pve-ssl.key \
      -out /etc/pve/local/pve-ssl.pem -days 90 -nodes \
      -subj '/CN=pve01.demo.bank.local' 2>/dev/null && \
    chmod 644 /etc/pve/local/pve-ssl.pem && \
    chmod 600 /etc/pve/local/pve-ssl.key

# PVE-3.1: domains.cfg without default-tfa; user.cfg with 3 privileged users, no TFA
RUN printf 'pam: pam\n\tcomment Linux PAM\n\npve: pve\n\tcomment Proxmox VE\n' \
      > /etc/pve/domains.cfg && \
    printf 'user:root@pam:1:0:::root@demo::::\nuser:admin@pam:1:0:::admin@demo::::\nuser:ops@pve:1:0:::ops@demo::::\n' \
      > /etc/pve/user.cfg

# PVE-3.2: 2 tokens no-expiry bound to root, world-readable file
RUN printf 'root@pam!backup:0:0:automated nightly backups:\nroot@pam!monitoring:0:0:zabbix integration:\n' \
      > /etc/pve/priv/token.cfg && \
    chmod 644 /etc/pve/priv/token.cfg

# PVE-4.1: cluster firewall disabled
RUN printf '[OPTIONS]\nenable: 0\npolicy_in: ACCEPT\npolicy_out: ACCEPT\n' \
      > /etc/pve/firewall/cluster.fw

# PVE-4.1: pve-firewall stub
RUN printf '#!/bin/sh\necho "Status: disabled/not running"\necho "Firewall enabled:      0"\n' \
      > /usr/local/bin/pve-firewall && chmod +x /usr/local/bin/pve-firewall

# PVE-5.1: pveversion stub reporting EOL 7.2
RUN printf '#!/bin/sh\necho "proxmox-ve: 7.2-1 (running kernel: 5.15.39-1-pve)"\necho "pve-manager/7.2-3/c743d6c1 (running version: 7.2-3/c743d6c1)"\necho "pve-kernel-5.15: 7.2-3"\n' \
      > /usr/local/bin/pveversion && chmod +x /usr/local/bin/pveversion

# PVE-5.1 continued: fake apt-get (simulation/upgrade emits 42 Inst lines)
RUN mv /usr/bin/apt-get /usr/bin/apt-get.real
COPY fake-apt-get /usr/bin/apt-get
RUN chmod +x /usr/bin/apt-get

# nginx on :8006, remove default, add our config
RUN rm -f /etc/nginx/sites-enabled/default
COPY nginx.conf /etc/nginx/sites-enabled/pve.conf

EXPOSE 22 8006

COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]
