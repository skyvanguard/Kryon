"""Active Directory compliance framework metadata.

Target: banking audits against on-prem AD (Windows Server DC) or Samba AD.
Checks are read-only: LDAP queries, SMB enumeration, password-policy
lookup. No Kerberos ticket abuse, no domain replication.

The actual checks live in `kryon.compliance.checks.active_directory.*`.

Credentials convention (avoiding breaking the frozen CheckContext):
  Read from env vars at check-time.
    KRYON_AD_DOMAIN  — e.g. "BANK.LOCAL"
    KRYON_AD_USER    — bind DN or UPN, e.g. "auditor@BANK.LOCAL"
    KRYON_AD_PASS    — password (or empty for kerberos ticket via KRB5CCNAME)
    KRYON_AD_DC      — DC hostname/IP override (default: ctx.host)
Missing creds → ERROR verdict with actionable message.

Tools we invoke (installed in the kryon container):
  ldapsearch, rpcclient, smbclient, nmap (--script), net, impacket-GetUserSPNs
If a tool is missing, check degrades to ERROR with install hint.
"""

from __future__ import annotations

from dataclasses import dataclass


FRAMEWORK_ID = "active-directory"
FRAMEWORK_NAME = "Active Directory hardening (banking profile)"
FRAMEWORK_VERSION = "1.0"

SECTIONS = {
    "1": "LDAP / LDAPS surface",
    "2": "Kerberos & tickets",
    "3": "Privileged groups",
    "4": "SMB & RPC",
    "5": "Logging & monitoring",
}


@dataclass(frozen=True)
class ADContext:
    """Hints any AD check can read via env var or default.

    Not passed through CheckContext — read at check.run() from os.environ
    so the existing runner/PDF pipeline keeps working unchanged.
    """

    domain: str = ""
    bind_user: str = ""
    bind_pass: str = ""
    dc_host: str = ""
