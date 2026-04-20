"""F31 — Generate a sample compliance PDF with plausible banking findings.

No live target needed. We construct 22 synthetic CheckResult-shaped dicts
that reflect what we routinely see in Paraguayan banking audits (PCI-DSS
+ Proxmox VE + Active Directory) and feed them straight to render_pdf().

Usage:
    docker exec kryon python /scripts/f31/generate_sample_report.py

The PDF lands in /reports (bind-mounted to ./reports on host).
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


# Each entry mirrors the CheckResult dict shape consumed by render_pdf().
# Mix chosen to represent a real first-engagement scan of a mid-size bank:
#   - Some obvious FAILs (cert self-signed, no TFA, lots of DAs)
#   - Some legitimate PASSes (firewall on, SMB signing, password policy)
#   - A couple of ERRORs where creds/tooling missing (realistic — auditor
#     rarely has 100% access on day one)

SAMPLE_HOST = "pve01.bancodemo.com.py"
SAMPLE_CLIENT = "Banco Demo Paraguay S.A."

FINDINGS: list[dict] = [
    # ===== PCI-DSS v4 (F15.1) =====
    {
        "control_id": "2.2.2",
        "control_title": "Vendor default accounts disabled or secured",
        "section": "2",
        "verdict": "PASS",
        "severity": "HIGH",
        "host": SAMPLE_HOST,
        "evidence_command": "getent shadow | awk -F: '$2 == \"\" || $2 == \"*\"' ; mysql -e 'SELECT User FROM mysql.user WHERE authentication_string=\"\"'",
        "evidence_stdout": "(no empty-password accounts found)\n(mysql: no default creds)",
        "evidence_stderr": "",
        "evidence_parsed": {"empty_shadow_entries": 0, "default_mysql_accounts": 0},
        "remediation_static": "Maintain policy: disable every vendor-default account at provisioning time; rotate root DB passwords on install.",
    },
    {
        "control_id": "2.2.7",
        "control_title": "SSH non-console admin encryption (key-only, no root)",
        "section": "2",
        "verdict": "FAIL",
        "severity": "CRITICAL",
        "host": SAMPLE_HOST,
        "evidence_command": "sshd -T | grep -E 'permitrootlogin|passwordauthentication'",
        "evidence_stdout": "permitrootlogin yes\npasswordauthentication yes",
        "evidence_stderr": "",
        "evidence_parsed": {
            "PermitRootLogin": "yes",
            "PasswordAuthentication": "yes",
            "issues": ["PermitRootLogin=yes (should be no)",
                       "PasswordAuthentication=yes (should be no)"],
        },
        "remediation_static": (
            "Edit /etc/ssh/sshd_config: PermitRootLogin no, "
            "PasswordAuthentication no. Validate sudo+key auth works for "
            "a non-root admin account BEFORE restarting sshd."
        ),
    },
    {
        "control_id": "6.3.3",
        "control_title": "Security patches applied within 30 days",
        "section": "6",
        "verdict": "FAIL",
        "severity": "HIGH",
        "host": SAMPLE_HOST,
        "evidence_command": "apt-get -s upgrade | grep -c '^Inst '",
        "evidence_stdout": "15",
        "evidence_stderr": "",
        "evidence_parsed": {"pending_security_updates": 15, "oldest_pending_days": 47},
        "remediation_static": (
            "Run `apt update && apt dist-upgrade` on a maintenance window. "
            "Subscribe to Debian security announcements and apply within 30 "
            "days per PCI-DSS 6.3.3."
        ),
    },
    {
        "control_id": "6.4.1",
        "control_title": "Public web app protection headers (HSTS/CSP/XFO/XCTO)",
        "section": "6",
        "verdict": "FAIL",
        "severity": "MEDIUM",
        "host": SAMPLE_HOST,
        "evidence_command": "curl -skI https://banca.bancodemo.com.py/ | head -15",
        "evidence_stdout": "HTTP/2 200\nserver: nginx/1.18.0\ncontent-type: text/html",
        "evidence_stderr": "",
        "evidence_parsed": {
            "HSTS": None, "CSP": None, "X-Frame-Options": None, "X-Content-Type-Options": None,
            "missing": ["Strict-Transport-Security", "Content-Security-Policy",
                        "X-Frame-Options", "X-Content-Type-Options"],
        },
        "remediation_static": (
            "Add in nginx server block:\n"
            "  add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
            "  add_header Content-Security-Policy \"default-src 'self'\" always;\n"
            "  add_header X-Frame-Options DENY always;\n"
            "  add_header X-Content-Type-Options nosniff always;"
        ),
    },
    {
        "control_id": "8.3.6",
        "control_title": "Minimum password complexity (>=12, mixed classes)",
        "section": "8",
        "verdict": "PASS",
        "severity": "HIGH",
        "host": SAMPLE_HOST,
        "evidence_command": "grep -E 'minlen|minclass' /etc/security/pwquality.conf",
        "evidence_stdout": "minlen = 12\nminclass = 3",
        "evidence_stderr": "",
        "evidence_parsed": {"minlen": 12, "minclass": 3},
        "remediation_static": "Already compliant — keep pwquality.conf under config management.",
    },
    {
        "control_id": "10.2.1",
        "control_title": "Audit trails active for privileged actions",
        "section": "10",
        "verdict": "PASS",
        "severity": "HIGH",
        "host": SAMPLE_HOST,
        "evidence_command": "systemctl is-active auditd ; ls /etc/audit/rules.d/",
        "evidence_stdout": "active\n00-base.rules  30-pci-dss-v31.rules  99-finalize.rules",
        "evidence_stderr": "",
        "evidence_parsed": {"auditd_active": True, "pci_rules_loaded": True},
        "remediation_static": "Already compliant — verify forwarding to SIEM is also configured (not in scope of this check).",
    },

    # ===== Proxmox VE hardening (F23) =====
    {
        "control_id": "PVE-1.1",
        "control_title": "Web UI SSL certificate is CA-signed and not expired",
        "section": "1",
        "verdict": "FAIL",
        "severity": "HIGH",
        "host": SAMPLE_HOST,
        "evidence_command": "openssl x509 -in /etc/pve/local/pve-ssl.pem -subject -issuer",
        "evidence_stdout": "subject=CN=pve01.bancodemo.com.py\nissuer=CN=pve01.bancodemo.com.py",
        "evidence_stderr": "",
        "evidence_parsed": {
            "subject": "CN=pve01.bancodemo.com.py",
            "issuer": "CN=pve01.bancodemo.com.py",
            "self_signed": True,
            "days_to_expiry": 211,
            "issues": ["Certificate is self-signed (subject == issuer)"],
        },
        "remediation_static": (
            "Replace with CA-signed cert. Via Web UI → Datacenter → Certificates → "
            "Upload Custom. CLI: `pvenode cert set --force <cert.pem> <key.pem>`. "
            "Use RSA >= 2048 or ECDSA P-256."
        ),
    },
    {
        "control_id": "PVE-1.2",
        "control_title": "Privileged API endpoints require authentication",
        "section": "1",
        "verdict": "PASS",
        "severity": "CRITICAL",
        "host": SAMPLE_HOST,
        "evidence_command": "curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8006/api2/json/nodes",
        "evidence_stdout": "401",
        "evidence_stderr": "",
        "evidence_parsed": {"endpoints": {
            "/api2/json/version": "200",
            "/api2/json/nodes": "401",
            "/api2/json/cluster/status": "401",
            "/api2/json/access/users": "401",
        }},
        "remediation_static": "Already compliant — privileged endpoints require auth. Keep monitoring.",
    },
    {
        "control_id": "PVE-2.1",
        "control_title": "SSH allows only key-based, non-root authentication",
        "section": "2",
        "verdict": "FAIL",
        "severity": "CRITICAL",
        "host": SAMPLE_HOST,
        "evidence_command": "sshd -T | grep -E 'permitrootlogin|passwordauth'",
        "evidence_stdout": "permitrootlogin yes\npasswordauthentication yes",
        "evidence_stderr": "",
        "evidence_parsed": {
            "PermitRootLogin": "yes",
            "PasswordAuthentication": "yes",
            "issues": ["PermitRootLogin=yes (should be no)",
                       "PasswordAuthentication=yes (should be no)"],
        },
        "remediation_static": "See PCI-DSS 2.2.7 — identical SSH hardening steps.",
    },
    {
        "control_id": "PVE-3.1",
        "control_title": "Multi-factor auth enforced for privileged Proxmox users",
        "section": "3",
        "verdict": "FAIL",
        "severity": "CRITICAL",
        "host": SAMPLE_HOST,
        "evidence_command": "cat /etc/pve/domains.cfg ; cat /etc/pve/user.cfg",
        "evidence_stdout": "pam: pam\n\npve: pve\n\nuser:root@pam:1:...:\nuser:admin@pam:1:...:\nuser:ops@pve:1:...:",
        "evidence_stderr": "",
        "evidence_parsed": {
            "realm_tfa": {"pam": False, "pve": False},
            "admin_users_no_tfa": ["root@pam", "admin@pam", "ops@pve"],
            "issues": [
                "realm 'pam' has no default-tfa",
                "realm 'pve' has no default-tfa",
                "3 privileged users without TFA: root@pam, admin@pam, ops@pve",
                "root@pam has no TFA binding",
            ],
        },
        "remediation_static": (
            "Web UI → Datacenter → Realm → edit 'pam' → Default TFA: TOTP. "
            "Then per-user: enroll each admin via Web UI → Username → TFA. "
            "Enforce root@pam first. Banking regulatory: SIB Resolución 06/2020 art.15."
        ),
    },
    {
        "control_id": "PVE-3.2",
        "control_title": "Proxmox API tokens follow least-privilege + expiry",
        "section": "3",
        "verdict": "FAIL",
        "severity": "HIGH",
        "host": SAMPLE_HOST,
        "evidence_command": "stat -c '%a %U %G' /etc/pve/priv/token.cfg ; cat /etc/pve/priv/token.cfg",
        "evidence_stdout": "644 root www-data\nroot@pam!backup:0:0:automated nightly backups:\nroot@pam!monitoring:0:0:zabbix integration:",
        "evidence_stderr": "",
        "evidence_parsed": {
            "mode": "644",
            "tokens_total": 2,
            "tokens_no_expiry": 2,
            "tokens_root_pam": 2,
            "tokens_privsep_off": 2,
            "issues": [
                "token.cfg world-permissions != 0 (mode 644)",
                "2 token(s) with no expiry",
                "2 token(s) bound to root@pam",
                "2 token(s) with privsep=0 (inherits full perms)",
            ],
        },
        "remediation_static": (
            "chmod 640 root:www-data /etc/pve/priv/token.cfg. "
            "Migrate automation to a dedicated non-root user:\n"
            "  pveum user add ci@pve --password $(pwgen -s 32 1)\n"
            "  pveum user token add ci@pve ops --privsep 1 --expire $(date -d '+1 year' +%s)\n"
            "Rotate tokens yearly."
        ),
    },
    {
        "control_id": "PVE-4.1",
        "control_title": "Datacenter firewall enabled with default-deny ingress",
        "section": "4",
        "verdict": "PASS",
        "severity": "HIGH",
        "host": SAMPLE_HOST,
        "evidence_command": "pve-firewall status ; cat /etc/pve/firewall/cluster.fw",
        "evidence_stdout": "Status: enabled/running\nenable: 1\npolicy_in: DROP",
        "evidence_stderr": "",
        "evidence_parsed": {"status": "enabled/running", "enable": "1", "policy_in": "DROP"},
        "remediation_static": "Already compliant. Review per-VM rulesets quarterly.",
    },
    {
        "control_id": "PVE-5.1",
        "control_title": "Proxmox version is supported and security patches applied",
        "section": "5",
        "verdict": "FAIL",
        "severity": "MEDIUM",
        "host": SAMPLE_HOST,
        "evidence_command": "pveversion --verbose ; apt-get -s upgrade | grep -c '^Inst '",
        "evidence_stdout": "pve-manager/8.1.4/ec5affc9e41f1d79\n42",
        "evidence_stderr": "",
        "evidence_parsed": {"version": "8.1.4", "pending_upgrades": 42,
                            "issues": ["42 package upgrades pending"]},
        "remediation_static": (
            "Run `apt update && apt dist-upgrade -y` on maintenance window. "
            "Use pve-enterprise repo in prod (requires subscription)."
        ),
    },

    # ===== Active Directory hardening (F24) =====
    {
        "control_id": "AD-1.1",
        "control_title": "LDAP signing enforced (rejects unsigned binds on 389/tcp)",
        "section": "1",
        "verdict": "FAIL",
        "severity": "HIGH",
        "host": "dc01.bancodemo.com.py",
        "evidence_command": "ldapsearch -x -H ldap://dc01:389 -D 'auditor@BANK.LOCAL' -w *** -b '' -s base namingContexts",
        "evidence_stdout": "result: 0 Success\nnamingContexts: DC=BANK,DC=LOCAL",
        "evidence_stderr": "",
        "evidence_parsed": {"simple_bind": "succeeded",
                            "issues": ["Simple bind on 389 succeeded — LDAP signing NOT enforced"]},
        "remediation_static": (
            "GPO → Domain Controller Policy → 'Domain controller: LDAP server "
            "signing requirements' = Require signing. Registry: NTDS\\Parameters\\"
            "LDAPServerIntegrity=2. Audit legacy apps first — unsigned clients break."
        ),
    },
    {
        "control_id": "AD-1.2",
        "control_title": "LDAPS (636/tcp) available with valid CA-signed cert",
        "section": "1",
        "verdict": "PASS",
        "severity": "HIGH",
        "host": "dc01.bancodemo.com.py",
        "evidence_command": "echo | openssl s_client -connect dc01:636 -servername dc01 -showcerts",
        "evidence_stdout": "subject=CN=dc01.bancodemo.com.py\nissuer=CN=BANK-CORP-CA",
        "evidence_stderr": "",
        "evidence_parsed": {
            "subject": "CN=dc01.bancodemo.com.py",
            "issuer": "CN=BANK-CORP-CA",
            "days_to_expiry": 312,
        },
        "remediation_static": "Already compliant. Keep auto-enrollment via GPO in place.",
    },
    {
        "control_id": "AD-1.3",
        "control_title": "Anonymous LDAP bind is rejected (no enumeration)",
        "section": "1",
        "verdict": "PASS",
        "severity": "HIGH",
        "host": "dc01.bancodemo.com.py",
        "evidence_command": "ldapsearch -x -H ldap://dc01:389 -b '' -s base",
        "evidence_stdout": "result: 1 Operations error\n000004DC: LdapErr: anonymous bind disallowed",
        "evidence_stderr": "",
        "evidence_parsed": {"anonymous_bind_accepted": False},
        "remediation_static": "Already compliant. Maintain dsHeuristics setting in config.",
    },
    {
        "control_id": "AD-2.1",
        "control_title": "No kerberoastable accounts with weak/stale passwords",
        "section": "2",
        "verdict": "FAIL",
        "severity": "CRITICAL",
        "host": "dc01.bancodemo.com.py",
        "evidence_command": "ldapsearch -x '...(servicePrincipalName=*)...' sAMAccountName",
        "evidence_stdout": "dn: CN=svc_oracle,...\nsAMAccountName: svc_oracle\n\ndn: CN=svc_backup,...\nsAMAccountName: svc_backup\n\ndn: CN=svc_temenos,...\nsAMAccountName: svc_temenos",
        "evidence_stderr": "",
        "evidence_parsed": {
            "kerberoastable_count": 3,
            "accounts": ["svc_backup", "svc_oracle", "svc_temenos"],
            "issues": ["3 active user account(s) with SPN (kerberoastable)"],
        },
        "remediation_static": (
            "Rotate each SPN-holder account password to >=25 random chars. "
            "Best path: migrate to Group Managed Service Accounts (gMSA):\n"
            "  New-ADServiceAccount -Name svc_oracle -DNSHostName oracle.bank.local\n"
            "gMSAs auto-rotate every 30 days — kerberoasting yields nothing useful."
        ),
    },
    {
        "control_id": "AD-2.2",
        "control_title": "krbtgt password rotated within last 180 days",
        "section": "2",
        "verdict": "FAIL",
        "severity": "CRITICAL",
        "host": "dc01.bancodemo.com.py",
        "evidence_command": "ldapsearch '(sAMAccountName=krbtgt)' pwdLastSet msDS-KeyVersionNumber",
        "evidence_stdout": "pwdLastSet: 132876543210000000\nmsDS-KeyVersionNumber: 2",
        "evidence_stderr": "",
        "evidence_parsed": {
            "last_changed_utc": "2024-02-10T09:15:32+00:00",
            "age_days": 423,
            "kvn": "2",
            "issues": ["krbtgt password is 423 days old (>180)"],
        },
        "remediation_static": (
            "Download Microsoft New-KrbtgtKeys.ps1. Run it TWICE with 10h "
            "between runs to invalidate cached tickets. Schedule semiannual. "
            "This is critical: a leaked krbtgt hash = Golden Ticket forever."
        ),
    },
    {
        "control_id": "AD-3.1",
        "control_title": "Domain Admins group has <= 5 active members",
        "section": "3",
        "verdict": "FAIL",
        "severity": "HIGH",
        "host": "dc01.bancodemo.com.py",
        "evidence_command": "ldapsearch -b 'CN=Domain Admins,CN=Users,DC=BANK,DC=LOCAL' member",
        "evidence_stdout": "(18 members — truncated)",
        "evidence_stderr": "",
        "evidence_parsed": {
            "member_count": 18,
            "threshold": 5,
            "members_sample": [
                "CN=Administrator", "CN=John Doe (IT Infra)", "CN=Jane Roe (retired 2023)",
                "CN=svc_deployment", "CN=Support Console 1", "CN=Support Console 2",
                "CN=Maria Lopez (contractor)", "CN=ADMIN_TEMP_Q1",
            ],
            "issues": ["Domain Admins has 18 members (threshold 5)"],
        },
        "remediation_static": (
            "Remove stale members (retired employees, legacy temp accounts, "
            "ended contractors). Implement JIT admin: PAM solution or "
            "Microsoft AAM. Target: <=5 permanent DAs. Audit DA monthly."
        ),
    },
    {
        "control_id": "AD-3.2",
        "control_title": "Domain password policy meets banking minimums (>=12 / complex / lockout)",
        "section": "3",
        "verdict": "PASS",
        "severity": "HIGH",
        "host": "dc01.bancodemo.com.py",
        "evidence_command": "ldapsearch -b 'DC=BANK,DC=LOCAL' -s base minPwdLength pwdProperties pwdHistoryLength lockoutThreshold",
        "evidence_stdout": "minPwdLength: 12\npwdProperties: 1\npwdHistoryLength: 24\nlockoutThreshold: 10",
        "evidence_stderr": "",
        "evidence_parsed": {
            "minPwdLength": 12,
            "pwdProperties": 1,
            "pwdHistoryLength": 24,
            "lockoutThreshold": 10,
            "maxPwdAge_days": 90,
        },
        "remediation_static": "Already compliant with banking baseline. Review at annual policy cycle.",
    },
    {
        "control_id": "AD-4.1",
        "control_title": "SMB signing required on 445/tcp (mitigates NTLM relay)",
        "section": "4",
        "verdict": "PASS",
        "severity": "CRITICAL",
        "host": "dc01.bancodemo.com.py",
        "evidence_command": "nmap -Pn -p 445 --script smb2-security-mode dc01",
        "evidence_stdout": "Message signing: required",
        "evidence_stderr": "",
        "evidence_parsed": {"message_signing": "required"},
        "remediation_static": "Already compliant. Also enable on member servers.",
    },
    {
        "control_id": "AD-5.1",
        "control_title": "Critical AD audit events logged and forwarded to SIEM",
        "section": "5",
        "verdict": "ERROR",
        "severity": "HIGH",
        "host": "dc01.bancodemo.com.py",
        "evidence_command": "nmap -Pn -p 5985,5986 dc01 ; rpcclient -U ... -c srvinfo dc01",
        "evidence_stdout": "5985/tcp filtered http\n5986/tcp filtered https\nrpcclient: NT_STATUS_IO_TIMEOUT",
        "evidence_stderr": "",
        "evidence_parsed": {
            "winrm_listening": False,
            "rpc_reachable": False,
            "note": "Event forwarding presence could not be verified remotely — requires on-DC script.",
            "issues": ["WinRM (5985/5986) not reachable — Event Forwarding to SIEM unlikely"],
        },
        "remediation_static": (
            "Enable Windows Event Collector + WEF subscription. Advanced Audit "
            "Policy Configuration → enable Logon, Kerberos, DS Access, Account "
            "Management (all Success+Failure). Forward to Splunk/Wazuh via WEF."
        ),
    },
]


# LLM narratives — short prose, in Spanish, to show what the production
# flow produces for each finding. For demo realism we hand-craft a few;
# the real engine calls compliance_narrator.narrate_all() at runtime.
SAMPLE_NARRATIVES = {
    "PVE-2.1": {
        "context_prose": (
            "El servidor Proxmox permite iniciar sesión SSH directamente como "
            "root con contraseña. En términos bancarios, esto significa que un "
            "atacante con acceso a la red de administración solo necesita "
            "adivinar una contraseña para tomar control total del hipervisor. "
            "Toda la infraestructura virtualizada (core-banking, AD, bases de "
            "datos) corre sobre este hipervisor."
        ),
        "remediation_prose": (
            "Se recomienda deshabilitar el login directo de root y forzar "
            "autenticación por llave SSH. Previamente, validar que existe una "
            "cuenta de administrador con sudo y llave funcional. El cambio "
            "requiere una ventana de mantenimiento de 15 minutos y es "
            "reversible desde la consola física."
        ),
    },
    "PVE-3.1": {
        "context_prose": (
            "Tres cuentas administrativas del hipervisor (incluida root) no "
            "tienen configurado segundo factor de autenticación. En el marco "
            "regulatorio de la SIB (Resolución 06/2020 art.15) y PCI-DSS 8.4, "
            "el MFA para accesos privilegiados no es opcional: es requisito "
            "auditable."
        ),
        "remediation_prose": (
            "Activar TFA por realm (PAM y PVE) como default. Enrolar cada "
            "administrador individualmente via el panel web. Priorizar "
            "root@pam antes que los demás. Mantener un token de respaldo "
            "guardado en bóveda física para contingencia."
        ),
    },
    "AD-2.2": {
        "context_prose": (
            "La cuenta krbtgt — que firma todos los tickets Kerberos del "
            "dominio — tiene su contraseña sin rotar hace 423 días. Si un "
            "atacante obtiene el hash de krbtgt (por compromiso previo, copias "
            "de NTDS, o dump de memoria en un DC), puede forjar 'Golden "
            "Tickets' con validez de 10 años que le dan acceso persistente "
            "indetectable por los logs normales."
        ),
        "remediation_prose": (
            "Microsoft publica el script New-KrbtgtKeys.ps1 para rotación "
            "segura. Debe ejecutarse DOS veces con 10 horas entre corridas, "
            "para invalidar los tickets emitidos previamente. Esta rotación "
            "es una operación rutinaria en entornos bancarios y debe "
            "agendarse semestralmente como política."
        ),
    },
    "AD-3.1": {
        "context_prose": (
            "El grupo 'Domain Admins' contiene 18 miembros, incluyendo cuentas "
            "de ex-empleados y contratistas cuyo engagement ya terminó. Cada "
            "miembro es equivalente a root en todo el dominio: comprometer "
            "una sola de esas cuentas equivale a comprometer toda la "
            "infraestructura Windows del banco."
        ),
        "remediation_prose": (
            "Revisar la lista completa con el equipo de RR.HH. y remover "
            "inmediatamente cualquier cuenta de persona que ya no trabaja en "
            "el banco. Para los administradores vigentes, migrar a un modelo "
            "Just-In-Time (PAM): los privilegios se conceden por tiempo "
            "limitado, solo cuando el admin los solicita y quedan auditados. "
            "Meta operativa: máximo 5 DAs permanentes."
        ),
    },
}


def _simple_repro_hash(results: list[dict]) -> str:
    """Same spirit as runner.reproducibility_hash but over plain dicts."""
    payload = json.dumps(
        [
            {k: r.get(k) for k in (
                "control_id", "control_title", "section", "verdict",
                "evidence_command", "evidence_parsed",
                "remediation_static", "severity", "host",
            )}
            for r in results
        ],
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def main() -> int:
    try:
        from kryon.reporting.compliance_pdf import render_pdf
    except ImportError as exc:
        print(f"!! reporting module not importable: {exc}", file=sys.stderr)
        return 1

    repro = _simple_repro_hash(FINDINGS)
    out_dir = Path("/reports")
    if not out_dir.is_dir():
        out_dir = Path("reports")
        out_dir.mkdir(parents=True, exist_ok=True)

    from datetime import datetime
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = out_dir / f"kryon_sample_bancodemo_{ts}.pdf"

    try:
        render_pdf(
            FINDINGS,
            repro_hash=repro,
            host=SAMPLE_HOST,
            output_path=out_path,
            narratives=SAMPLE_NARRATIVES,
            framework="all",
            client_name=SAMPLE_CLIENT,
        )
    except ImportError:
        # weasyprint missing — the HTML still got written
        pass

    # Quick summary
    counts: dict[str, int] = {}
    for f in FINDINGS:
        counts[f["verdict"]] = counts.get(f["verdict"], 0) + 1
    print(json.dumps({
        "pdf": str(out_path),
        "html": str(out_path.with_suffix(".html")),
        "findings": len(FINDINGS),
        "verdicts": counts,
        "client": SAMPLE_CLIENT,
        "host": SAMPLE_HOST,
        "repro_hash": repro,
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
