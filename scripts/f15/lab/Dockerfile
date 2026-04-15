# F15.1 bench target — Ubuntu 22.04 deliberately CIS-nonconforming.
#
# Purpose: expose every compliance check to a condition it should FAIL on,
# so Kryon + Lynis can both detect the same misconfigurations and we can
# measure agreement.
#
# The image MUST NOT be used outside the lab network.

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        libpam-pwquality \
        auditd \
        nginx \
        curl \
        iproute2 \
        python3-pip \
        sudo \
        lsb-release \
    && rm -rf /var/lib/apt/lists/*

# --- 2.2.7 deliberate FAIL: SSH hardening ---
RUN mkdir -p /var/run/sshd \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 10/' /etc/ssh/sshd_config \
    && echo "Ciphers aes128-cbc,aes256-cbc,aes256-gcm@openssh.com" >> /etc/ssh/sshd_config

# --- 2.2.2 deliberate FAIL: empty-password account ---
RUN useradd -m -s /bin/bash badacct \
    && passwd -d badacct

# --- 6.3.3 deliberate FAIL: pending security updates ---
# We install apt but do NOT run `apt upgrade`. Also fake an old dpkg.log
# entry so the patch-age check sees 40-day-old upgrade.
RUN mkdir -p /var/log \
    && printf '2026-03-01 12:00:00 upgrade libc6:amd64 2.31-0ubuntu9.1 2.31-0ubuntu9.2\n' \
       > /var/log/dpkg.log

# --- 6.4.1 deliberate FAIL: nginx without security headers ---
RUN printf 'server {\n\
    listen 80 default_server;\n\
    root /var/www/html;\n\
    index index.html;\n\
    location / { try_files $uri $uri/ =404; }\n\
}\n' > /etc/nginx/sites-available/default \
    && echo "<html><body>bench target</body></html>" > /var/www/html/index.html

# --- 8.3.6 deliberate FAIL: weak password policy ---
# login.defs: PASS_MIN_LEN left at default (usually 8, below PCI 12)
# pwquality.conf: not configured (just the defaults)
# common-password: does NOT invoke pam_pwquality
RUN sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 8/' /etc/login.defs \
    && : > /etc/security/pwquality.conf \
    && printf 'password required pam_unix.so sha512 shadow\n' > /etc/pam.d/common-password

# --- 10.2.1 deliberate FAIL: auditd installed but NO rules configured ---
# auditd package present (apt install above) but we do not add watch rules
# and we do not enable the service — it won't be "active" without init.
RUN rm -f /etc/audit/rules.d/*.rules \
    && : > /etc/audit/audit.rules

# Install Lynis so the container can run both Kryon (via SSH from host) and
# Lynis locally.
RUN apt-get update && apt-get install -y --no-install-recommends lynis \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 22 80

# Entrypoint: start sshd in foreground so the container stays up for audit.
# nginx starts in background; auditd deliberately left unstarted.
CMD service nginx start && /usr/sbin/sshd -D
