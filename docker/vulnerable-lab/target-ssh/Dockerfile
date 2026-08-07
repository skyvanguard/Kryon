# Target SSH — plants CWE-521 weak auth + CWE-287 overly permissive config.
#
# Planted vulnerabilities (detectable by server-hardening playbook):
#   - PermitRootLogin yes            (CWE-521)
#   - PasswordAuthentication yes     (CWE-521)
#   - X11Forwarding yes              (CWE-250 hardening check)
#   - MaxAuthTries 10                (CWE-307 weak brute-force protection)
#   - PermitEmptyPasswords no        <- left correct, so demo shows
#                                       the scanner also recognises
#                                       safe configs.
FROM ubuntu:22.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server sudo \
    && rm -rf /var/lib/apt/lists/*

# Create an ops user with a predictable password for the demo. NEVER
# use this image outside the lab — password is in the image layer.
RUN useradd -m -s /bin/bash admin \
    && echo 'admin:demo-only-password' | chpasswd \
    && usermod -aG sudo admin \
    && echo 'admin ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/admin

# Plant the intentionally weak sshd_config.
RUN mkdir -p /var/run/sshd \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?X11Forwarding.*/X11Forwarding yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 10/' /etc/ssh/sshd_config \
    && echo 'root:demo-weak-root-password' | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
