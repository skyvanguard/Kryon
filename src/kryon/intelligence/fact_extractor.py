"""FASE 1 (G1+G2) — structured fact extraction from tool outputs.

The problem: `micro_compact` truncates tool outputs to ~3-9 lines before
they reach the model. An `ldapsearch -b dc=... -s sub` that returns 283
lines of LDIF is shown to the model as the LDIF header plus a few entries.
The model can't enumerate users it never saw, so the next turn keeps
issuing variants of the same broad query instead of refining to e.g.
`(userAccountControl=4194304)` for asreproast targets.

This module parses the FULL output (before micro_compact) into
``ExtractedFacts`` — a structured snapshot the reflective runner injects
into every reflection turn. The model now reads "users: alice, bob,
carol" instead of having to remember it from a truncated transcript.

Parsers are intentionally regex-based and forgiving. Goal is the 80%
common-case extraction across the tools the AD/web agent actually uses,
not a complete LDIF/SMB parser. Unknown tools fall back to a generic
regex pass that scrapes IPs, hostnames, and hash-shaped tokens.

Banca-safe: pure functions, no I/O, no network, no LLM calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

# Krb5 ticket/AS-REP signatures (impacket and standalone). The character
# class includes ``@`` because impacket embeds ``user@DOMAIN`` in the
# hash header — leaving it out truncates the hash at the @, which also
# loses the username/domain extracted from the prefix.
_KRB5_RE = re.compile(r"\$krb5(?:asrep|tgs)\$[0-9A-Za-z*$./:_+@-]+")
# NTLM hashes from secretsdump (LMHASH:NTHASH form, both 32 hex).
_NTLM_PAIR_RE = re.compile(
    r"\b[A-Za-z0-9._$-]+:\d+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::"
)
# IPv4 dotted-quad (loose — caller filters target/RFC1918 if needed).
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Generic FQDN — letters/digits/dashes separated by dots, 2+ labels.
_FQDN_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9-]*(?:\.[a-zA-Z][a-zA-Z0-9-]*){1,}\b")
# FASE 11.K — robots.txt Disallow directive. Case-insensitive, flexible
# whitespace. Captures the path (group 1). Stops at newline / ``\n`` /
# end-of-string so multi-directive blocks tokenize cleanly. ``\\n`` is
# captured too because web_fetch_smart returns the body JSON-escaped.
_DISALLOW_PATH_RE = re.compile(
    r"disallow\s*:\s*(\S+?)(?=\\n|\n|\"|$)",
    re.IGNORECASE,
)
# CTF-style hint phrases that the model commonly misses in HTTP bodies
# AND in tool output that signals what kind of service is listening.
# Keep this list short and high-signal — every entry should be something
# that, when echoed back to the model, materially changes its next move.
_CTF_HINT_PHRASES = (
    "try a more basic connection",
    "credentials in folder",
    "older version",
    "default credentials",
    "did you read the source",
    "look at robots",
    "hint:",
    "flag{",
    "flag.txt",
    # Pyrat-style: the server eval()s input and emits Python errors when
    # the input isn't valid Python. The model on its own keeps treating
    # this as a shell / nc problem; surfacing it as a hint makes the
    # next planner pass / next reasoning turn route correctly to a
    # Python payload like ``__import__("os").system("id")``.
    "invalid syntax",
    "syntaxerror",
    "nameerror",
    "is not defined",
    "traceback (most recent call last)",
    # FASE 7 (G8) — additional Python-REPL signals observed in Pyrat
    # nmap fingerprints. These come from CPython's compile() / exec()
    # boundary and uniquely identify "service runs untrusted text
    # through the interpreter" — a stronger signal than the generic
    # SyntaxError because it pinpoints compile() specifically.
    "source code string cannot contain null bytes",
    # FASE 7 — git "dubious ownership" → known retry pattern of
    # copying the repo to a writable dir owned by the current user.
    # Surfacing this makes the next planner pass emit the bypass.
    "detected dubious ownership",
    # FASE 7 — generic filesystem-denied signal. Surfacing it lets
    # the planner suggest indirect-read paths (introspection, /proc
    # tricks, world-readable backup copies).
    "[errno 13] permission denied",
    # FASE 11.J — REPL echo marker. When the planner's foothold-confirm
    # directive ``printf 'print("kryon-probe")\n' | nc ...`` succeeds,
    # the remote eval()/exec() echoes ``kryon-probe`` back to the
    # socket. Capturing this as a hint lets ``_has_foothold`` in the
    # reflective runner recognise we already cracked past recon, so
    # downstream gates (premature-summary detector + final rejection)
    # stop firing on legitimate summaries that follow the RCE chain.
    "kryon-probe",
)


@dataclass(frozen=True)
class ExtractedFacts:
    """Snapshot of structured intel pulled from tool outputs.

    All fields are tuples (frozen, hashable, dedup at merge time). Empty
    tuple means "nothing observed", not "definitely absent".
    """

    users: tuple[str, ...] = ()
    shares: tuple[str, ...] = ()
    hashes: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    # (port, service_name) — service can be "" when only the port number
    # was observed (e.g. raw nc probe).
    services: tuple[tuple[int, str], ...] = ()
    domains: tuple[str, ...] = ()
    # (user, password) — present only after a confirmed crack/dump.
    creds: tuple[tuple[str, str], ...] = ()
    paths: tuple[str, ...] = ()
    # (software, version) — e.g. ("Microsoft-IIS", "10.0").
    versions: tuple[tuple[str, str], ...] = ()
    hints: tuple[str, ...] = ()

    def merge(self, other: ExtractedFacts) -> ExtractedFacts:
        """Return a new ExtractedFacts combining both, deduped + sorted.

        Sorting gives stable diffing in tests and a predictable
        rendering order in the prompt block.
        """
        return ExtractedFacts(
            users=_dedup_sorted(self.users + other.users),
            shares=_dedup_sorted(self.shares + other.shares),
            hashes=_dedup_sorted(self.hashes + other.hashes),
            hosts=_dedup_sorted(self.hosts + other.hosts),
            services=_dedup_sorted_pairs_int(self.services + other.services),
            domains=_dedup_sorted(self.domains + other.domains),
            creds=_dedup_sorted_pairs(self.creds + other.creds),
            paths=_dedup_sorted(self.paths + other.paths),
            versions=_dedup_sorted_pairs(self.versions + other.versions),
            hints=_dedup_sorted(self.hints + other.hints),
        )

    def is_empty(self) -> bool:
        return not any(
            (
                self.users, self.shares, self.hashes, self.hosts,
                self.services, self.domains, self.creds, self.paths,
                self.versions, self.hints,
            )
        )

    def render_for_prompt(self, *, max_per_field: int = 20) -> str:
        """Markdown block suitable for injection into a reflection turn.

        Truncates long lists (>max_per_field) to keep the prompt under
        budget. The model is told "...N more" so it knows there's data
        beyond what it sees and can request a refinement if needed.
        """
        if self.is_empty():
            return ""

        def _list_line(label: str, items: tuple, *, fmt: Callable[[object], str] = str) -> str:
            if not items:
                return ""
            shown = items[:max_per_field]
            extra = len(items) - len(shown)
            body = ", ".join(fmt(x) for x in shown)
            tail = f" (+{extra} more)" if extra > 0 else ""
            return f"- **{label}**: {body}{tail}\n"

        parts = ["## 📊 Facts extracted so far\n\n"]
        parts.append(_list_line("users", self.users))
        parts.append(_list_line("shares", self.shares))
        parts.append(_list_line("hashes", self.hashes))
        parts.append(_list_line("hosts", self.hosts))
        parts.append(
            _list_line(
                "services", self.services,
                fmt=lambda p: f"{p[0]}/{p[1]}" if p[1] else f"{p[0]}",  # type: ignore[index]
            )
        )
        parts.append(_list_line("domains", self.domains))
        parts.append(
            _list_line(
                "creds", self.creds,
                fmt=lambda c: f"{c[0]}:{c[1]}",  # type: ignore[index]
            )
        )
        parts.append(_list_line("paths", self.paths))
        parts.append(
            _list_line(
                "versions", self.versions,
                fmt=lambda v: f"{v[0]} {v[1]}",  # type: ignore[index]
            )
        )
        parts.append(_list_line("hints", self.hints))
        return "".join(p for p in parts if p)


# Reused empty value so callers don't allocate dozens of identical
# instances when most parsers return nothing.
EMPTY = ExtractedFacts()


# G5 (FASE 4) — anti-pattern detector for tool invocations.
#
# When the model issues a tool with subtly-wrong flags (nc without -q,
# ldapsearch without an objectClass filter, curl without --max-time)
# the call usually still "succeeds" syntactically but produces output
# that hangs the chunk or floods the model. Surfacing each anti-pattern
# as a structured hint in the next reflection turn nudges the planner
# and the model toward the correct flag set without overriding what
# they're trying to do.
#
# Each entry is ``(name, predicate_regex, hint_phrase)`` — predicate
# matches against the tool invocation string. Keep predicates tight so
# legitimate variants (e.g. ``nc -l -q 1 …`` server-side) don't trip
# the no-q-flag rule.
_INVOCATION_ANTI_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "nc-no-timeout-flags",
        re.compile(
            # nc invocations missing both -q and -w. Match cmd start so
            # ``echo … | nc target port`` triggers but a piped ``echo``
            # body containing the literal "nc" doesn't.
            r"(?:^|[;&|]\s*)nc\s+(?!-[a-zA-Z]*[qw])[^\s|;&]+\s+\d+",
            re.IGNORECASE,
        ),
        "nc invocation lacks -q/-w timeout flags — connection will "
        "hang until subprocess timeout. Use ``nc -q 1 -w 5 <host> "
        "<port>`` (close 1s after EOF, total 5s cap).",
    ),
    (
        "ldapsearch-no-filter",
        re.compile(
            # ldapsearch with -b but no parenthesised LDAP filter and
            # no -s base. Without the filter the query dumps the whole
            # subtree (300+ lines on a typical AD), which micro_compact
            # truncates to noise.
            r"\bldapsearch\b(?![^\n]*\(objectClass=)(?![^\n]*-s\s+base)[^\n]*-b\s+",
            re.IGNORECASE,
        ),
        "ldapsearch without an objectClass filter dumps the whole "
        "subtree (300+ lines typical). Refine with "
        "``(objectClass=user)`` and request only sAMAccountName for a "
        "clean user list.",
    ),
    (
        "curl-no-max-time",
        re.compile(
            r"\bcurl\b(?![^\n]*--max-time)(?![^\n]*-m\s+\d)[^\n]*https?://",
            re.IGNORECASE,
        ),
        "curl invocation has no ``--max-time`` — a slow target can "
        "hang the subprocess past run_command's 300s default. Add "
        "``--max-time 10`` (or ``-m 10``) for HTTP probes.",
    ),
    (
        "getnpusers-no-outputfile",
        re.compile(
            r"\bGetNPUsers(?:\.py)?\b(?![^\n]*-outputfile)",
            re.IGNORECASE,
        ),
        "GetNPUsers without ``-outputfile`` writes hashes to stdout "
        "only. Add ``-outputfile /tmp/asrep_hashes.txt`` so the next "
        "step can pipe them to hashcat.",
    ),
    (
        "hashcat-no-show",
        re.compile(
            # hashcat run that has no --show and no -m mode flag is
            # almost always a misfire (interactive prompt). The flag
            # combo we care about is "running but not showing".
            r"\bhashcat\b(?![^\n]*--show)(?![^\n]*-m\s+\d)[^\n]*\.txt",
            re.IGNORECASE,
        ),
        "hashcat run without ``--show`` and without ``-m <mode>`` is "
        "missing the mode (asrep=18200, tgs=13100, ntlm=1000). Either "
        "set the mode + wordlist, or pass ``--show`` to display "
        "already-cracked entries from the potfile.",
    ),
)


def _detect_invocation_anti_patterns(invocation: str) -> tuple[str, ...]:
    """G5 — scan a tool invocation string for the canonical
    anti-patterns. Return their hint phrases (deduplicated, sorted)
    so the next reflection turn can surface remediation."""
    if not invocation:
        return ()
    found: list[str] = []
    for _name, pattern, hint in _INVOCATION_ANTI_PATTERNS:
        if pattern.search(invocation):
            found.append(hint)
    return tuple(sorted(set(found)))


def _dedup_sorted(items: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted({i for i in items if i}))


def _dedup_sorted_pairs(items: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted({i for i in items if i[0]}))


def _dedup_sorted_pairs_int(
    items: tuple[tuple[int, str], ...]
) -> tuple[tuple[int, str], ...]:
    return tuple(sorted({i for i in items}))


def _parse_ldapsearch(output: str) -> ExtractedFacts:
    """LDIF output from ldapsearch. Extract:
      - users (sAMAccountName entries, cn= in CN=Users branch),
      - domains (defaultNamingContext / namingContexts),
      - paths (DN strings — useful as pivot intel),
      - hosts (dNSHostName entries for computer objects).
    """
    users: list[str] = []
    domains: list[str] = []
    paths: list[str] = []
    hosts: list[str] = []

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # DN lines are the densest pivot intel — keep all of them.
        if line.startswith("dn:"):
            dn_value = line[3:].strip()
            paths.append(dn_value)
            # If the DN sits under CN=Users we extract the leaf CN as a
            # candidate username.
            m = re.match(r"CN=([^,]+),CN=Users,", dn_value, re.IGNORECASE)
            if m:
                users.append(m.group(1))
            continue

        # Attribute lines: ``attr: value`` or ``attr:: base64value``.
        if ":" in line:
            attr, _, val = line.partition(":")
            attr = attr.strip().lower()
            val = val.lstrip(":").strip()
            if not val:
                continue
            if attr == "samaccountname":
                users.append(val)
            elif attr == "userprincipalname":
                # foo@bar.local → extract account + domain.
                if "@" in val:
                    user, _, dom = val.partition("@")
                    users.append(user)
                    domains.append(dom)
                else:
                    users.append(val)
            elif attr in {"defaultnamingcontext", "namingcontexts", "rootdomainnamingcontext"}:
                # "DC=thm,DC=local" → "thm.local"
                fqdn = _dn_to_fqdn(val)
                if fqdn:
                    domains.append(fqdn)
            elif attr == "dnshostname":
                hosts.append(val)

    return ExtractedFacts(
        users=_dedup_sorted(tuple(users)),
        domains=_dedup_sorted(tuple(domains)),
        paths=_dedup_sorted(tuple(paths)),
        hosts=_dedup_sorted(tuple(hosts)),
    )


def _dn_to_fqdn(dn: str) -> str:
    """``DC=thm,DC=local`` → ``thm.local``. Returns "" on non-DC DNs."""
    parts = [p.strip() for p in dn.split(",")]
    dc_parts = [p[3:] for p in parts if p.lower().startswith("dc=")]
    return ".".join(dc_parts) if dc_parts else ""


def _parse_smbclient_shares(output: str) -> ExtractedFacts:
    """``smbclient -L`` share listing. Lines look like:
        Sharename       Type      Comment
        --------        ----      -------
        ADMIN$          Disk      Remote Admin
        IPC$            IPC       Remote IPC
    """
    shares: list[str] = []
    in_table = False
    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        if "Sharename" in line and "Type" in line:
            in_table = True
            continue
        if in_table:
            if not line or line.startswith("-") or "----" in line:
                continue
            # Lines after the table header that look like blank or other
            # sections terminate the listing.
            if line.startswith(("\t", " ")) is False and not line[:1].isalpha():
                continue
            # First whitespace-separated token is the share name.
            tokens = line.split()
            if not tokens:
                continue
            candidate = tokens[0]
            # Cheap sanity: share names are short, non-IP.
            if 1 <= len(candidate) <= 80 and not _IPV4_RE.fullmatch(candidate):
                shares.append(candidate)
    return ExtractedFacts(shares=_dedup_sorted(tuple(shares)))


def _parse_nmap(output: str) -> ExtractedFacts:
    """nmap text output. Look for ``PORT     STATE SERVICE`` table lines.

    Also extracts ``Service Info: OS: ...; Host: WORKGROUP`` style
    versions when the -sV scan produced them.
    """
    services: list[tuple[int, str]] = []
    versions: list[tuple[str, str]] = []

    for raw_line in output.splitlines():
        line = raw_line.strip()
        # Match e.g. "445/tcp   open  microsoft-ds Windows Server 2019"
        m = re.match(r"^(\d{1,5})/(?:tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?$", line)
        if m:
            port = int(m.group(1))
            svc = m.group(2)
            services.append((port, svc))
            version_blob = (m.group(3) or "").strip()
            if version_blob:
                # Cheap version split: first token = software, rest = version.
                tokens = version_blob.split(maxsplit=1)
                if len(tokens) == 2:
                    versions.append((tokens[0], tokens[1][:60]))
                elif len(tokens) == 1:
                    versions.append((tokens[0], ""))

    return ExtractedFacts(
        services=_dedup_sorted_pairs_int(tuple(services)),
        versions=_dedup_sorted_pairs(tuple(versions)),
    )


def _parse_nxc(output: str) -> ExtractedFacts:
    """nxc (netexec) SMB/LDAP output. Common lines:

      SMB    10.0.0.1  445  DC01      [*] Windows 10 ... (domain:THM.LOCAL)
      LDAP   10.0.0.1  389  DC01      [+] THM.LOCAL\\guest:
      SMB    10.0.0.1  445  DC01      [+] THM.LOCAL\\alice (Pwn3d!)
    """
    users: list[str] = []
    hosts: list[str] = []
    domains: list[str] = []
    creds: list[tuple[str, str]] = []

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # domain:THM.LOCAL hint.
        m = re.search(r"\(?domain:\s*([A-Za-z0-9._-]+)\)?", line, re.IGNORECASE)
        if m:
            domains.append(m.group(1).lower())
        # DOMAIN\\user:password — confirmed creds.
        m = re.search(
            r"\b([A-Za-z0-9._-]+)\\([A-Za-z0-9._@-]+):([^\s]+)", line
        )
        if m:
            domains.append(m.group(1).lower())
            users.append(m.group(2))
            pwd = m.group(3)
            if pwd not in {"", "''", '""'}:
                creds.append((m.group(2), pwd))
        # Lone DC hostname columns ("DC01") are common but noisy — skip.

    # Pull any IPs from the line for hosts (target enumeration).
    for ip in _IPV4_RE.findall(output):
        hosts.append(ip)

    return ExtractedFacts(
        users=_dedup_sorted(tuple(users)),
        hosts=_dedup_sorted(tuple(hosts)),
        domains=_dedup_sorted(tuple(domains)),
        creds=_dedup_sorted_pairs(tuple(creds)),
    )


def _parse_impacket_getnpusers(output: str) -> ExtractedFacts:
    """impacket-GetNPUsers / GetNPUsers.py output. Krb5 AS-REP hashes
    on their own line, plus the username embedded in the hash format::

        $krb5asrep$23$alice@THM.LOCAL:abc...:xyz...
    """
    hashes = list(_KRB5_RE.findall(output))
    users: list[str] = []
    domains: list[str] = []
    for h in hashes:
        # ``$krb5asrep$23$user@DOMAIN:rest...``
        m = re.search(r"\$krb5asrep\$\d+\$([^@]+)@([^\s:]+)", h, re.IGNORECASE)
        if m:
            users.append(m.group(1))
            domains.append(m.group(2).lower())
    return ExtractedFacts(
        users=_dedup_sorted(tuple(users)),
        domains=_dedup_sorted(tuple(domains)),
        hashes=_dedup_sorted(tuple(hashes)),
    )


def _parse_impacket_getuserspns(output: str) -> ExtractedFacts:
    """GetUserSPNs.py — Kerberoast hashes (TGS). Format::

        $krb5tgs$23$*sqlsvc$THM.LOCAL$MSSQLSvc/sql01.thm.local~1433*$...
    """
    hashes = [h for h in _KRB5_RE.findall(output) if "tgs" in h]
    users: list[str] = []
    domains: list[str] = []
    for h in hashes:
        m = re.search(r"\$krb5tgs\$\d+\$\*([^$]+)\$([^$]+)\$", h, re.IGNORECASE)
        if m:
            users.append(m.group(1))
            domains.append(m.group(2).lower())
    return ExtractedFacts(
        users=_dedup_sorted(tuple(users)),
        domains=_dedup_sorted(tuple(domains)),
        hashes=_dedup_sorted(tuple(hashes)),
    )


def _parse_hashcat(output: str) -> ExtractedFacts:
    """hashcat ``--show`` / status output. Cracked lines look like::

        $krb5asrep$23$alice@...:abc...:xyz...:Password123!

    The cracked plaintext is the last colon-separated field.
    """
    creds: list[tuple[str, str]] = []
    users: list[str] = []
    for raw_line in output.splitlines():
        if "$krb5" not in raw_line:
            continue
        m = re.search(r"\$krb5(?:asrep|tgs)\$\d+\$([^@$]+)[@$]", raw_line)
        if not m:
            continue
        user = m.group(1)
        users.append(user)
        # Last colon-separated token after the hash is the password.
        parts = raw_line.rstrip().rsplit(":", 1)
        if len(parts) == 2 and parts[1] and "$krb5" not in parts[1]:
            creds.append((user, parts[1]))
    return ExtractedFacts(
        users=_dedup_sorted(tuple(users)),
        creds=_dedup_sorted_pairs(tuple(creds)),
    )


def _parse_secretsdump(output: str) -> ExtractedFacts:
    """secretsdump.py — NTLM hash dump. Lines look like::

        Administrator:500:aad3b...:31d6cfe0d16ae931b73c59d7e0c089c0:::
    """
    users: list[str] = []
    hashes: list[str] = []
    for line in output.splitlines():
        m = _NTLM_PAIR_RE.search(line)
        if m:
            hashes.append(m.group(0))
            head = m.group(0).split(":", 1)[0]
            users.append(head)
    return ExtractedFacts(
        users=_dedup_sorted(tuple(users)),
        hashes=_dedup_sorted(tuple(hashes)),
    )


def _parse_web_fetch_smart(output: str) -> ExtractedFacts:
    """web_fetch_smart returns a JSON dict. Extract server header
    versions, the URL's host/port as a (host, service) facts pair so
    downstream planner rules can target it, plus CTF-style hint phrases
    in the body.
    """
    versions: list[tuple[str, str]] = []
    hints: list[str] = []
    services: list[tuple[int, str]] = []
    hosts: list[str] = []

    # Server header. The fetch returns JSON, but we only need a couple
    # of fields — parse permissively.
    server_match = re.search(r'"server"\s*:\s*"([^"]+)"', output, re.IGNORECASE)
    if server_match:
        server = server_match.group(1)
        parts = server.split("/", 1)
        if len(parts) == 2:
            versions.append((parts[0], parts[1]))
        else:
            versions.append((server, ""))

    # Surface the fetched URL's host + port as facts. Without this the
    # planner can't fire rules that target "the service we just probed"
    # (e.g. the netcat-on-hint rule needs ``services`` populated).
    url_match = re.search(r'"final_url"\s*:\s*"([^"]+)"', output, re.IGNORECASE)
    if not url_match:
        url_match = re.search(r'"url"\s*:\s*"([^"]+)"', output, re.IGNORECASE)
    if url_match:
        u = url_match.group(1)
        host_port = re.search(r"https?://([^/:]+)(?::(\d+))?", u, re.IGNORECASE)
        if host_port:
            host = host_port.group(1)
            port_str = host_port.group(2)
            hosts.append(host)
            if port_str:
                port = int(port_str)
            else:
                # Default ports for http(s) so the planner still has signal.
                port = 443 if u.lower().startswith("https://") else 80
            # The server name from the header (if known) doubles as the
            # service label; otherwise tag generically.
            svc_label = ""
            if versions:
                svc_label = versions[0][0].lower()
            services.append((port, svc_label or "http"))

    # Hints — case-insensitive substring scan.
    lower = output.lower()
    for phrase in _CTF_HINT_PHRASES:
        if phrase in lower:
            hints.append(phrase)

    # FASE 11.K — robots.txt Disallow parsing. When the fetched URL
    # ends in ``/robots.txt`` (or the body shape matches), pull each
    # disallowed path out as a structured ``disallow:<path>`` hint.
    # The planner's recon-class rules pivot on this signal to emit
    # gobuster / ffuf directives at the model.
    if "/robots.txt" in output.lower() or "disallow:" in output.lower():
        for m in _DISALLOW_PATH_RE.finditer(output):
            path = m.group(1).strip()
            # Skip the catch-all ``/`` (blocks everything, not a useful
            # gobuster target) and empty paths.
            if not path or path == "/":
                continue
            hints.append(f"disallow:{path}")

    return ExtractedFacts(
        versions=_dedup_sorted_pairs(tuple(versions)),
        hints=_dedup_sorted(tuple(hints)),
        services=_dedup_sorted_pairs_int(tuple(services)),
        hosts=_dedup_sorted(tuple(hosts)),
    )


def _parse_generic(output: str) -> ExtractedFacts:
    """Fallback parser for unknown tools. Scrapes high-signal patterns:
    krb5 hashes, NTLM dumps, and CTF hint phrases. Conservative — does
    NOT extract IPs/FQDNs blindly, those produce more noise than signal
    when fired against arbitrary text.
    """
    hashes: list[str] = list(_KRB5_RE.findall(output))
    hashes.extend(_NTLM_PAIR_RE.findall(output))

    lower = output.lower()
    hints = [p for p in _CTF_HINT_PHRASES if p in lower]

    return ExtractedFacts(
        hashes=_dedup_sorted(tuple(hashes)),
        hints=_dedup_sorted(tuple(hints)),
    )


# Dispatch by tool name fragments. First match wins — order matters
# (most specific first).
_DISPATCH: tuple[tuple[str, Callable[[str], ExtractedFacts]], ...] = (
    ("getnpusers", _parse_impacket_getnpusers),
    ("getuserspns", _parse_impacket_getuserspns),
    ("secretsdump", _parse_secretsdump),
    ("hashcat", _parse_hashcat),
    ("ldapsearch", _parse_ldapsearch),
    ("smbclient", _parse_smbclient_shares),
    ("nxc", _parse_nxc),
    ("netexec", _parse_nxc),
    ("crackmapexec", _parse_nxc),
    ("nmap", _parse_nmap),
    ("web_fetch_smart", _parse_web_fetch_smart),
)


def extract_facts(tool_invocation: str, output: str) -> ExtractedFacts:
    """Pick the right parser based on the tool invocation string.

    ``tool_invocation`` is the full command/tool reference. For
    ``run_command`` calls this is the command line ("ldapsearch -x ..."),
    for function_tools it's the tool name ("nmap", "web_fetch_smart").
    We do a case-insensitive substring match against the dispatch table
    so e.g. "nxc smb 10.0.0.1 -u guest" routes to ``_parse_nxc``.

    When the invocation is opaque (e.g. captured from ItemCaptureHooks
    as a bare ``run_command`` without the inner command), we fall back
    to a content-based dispatch: look at the first ~400 chars of the
    output for unmistakable per-tool signatures (LDIF ``dn:`` prefix,
    smbclient ``Sharename`` header, etc.) and route accordingly.

    Unknown tools fall through to ``_parse_generic`` which scrapes the
    high-signal patterns (krb5 hashes, NTLM dumps, CTF hints).
    """
    if not output:
        return EMPTY
    haystack = (tool_invocation or "").lower()

    # G5 (FASE 4) — anti-pattern hints come from the invocation string
    # itself, independent of the parser's output. They surface in
    # facts.hints so the next reflection turn can nudge the model
    # toward the correct flag set without overriding what it's doing.
    anti_pattern_hints = _detect_invocation_anti_patterns(tool_invocation or "")

    for needle, parser in _DISPATCH:
        if needle in haystack:
            parsed = parser(output)
            if anti_pattern_hints:
                parsed = parsed.merge(
                    ExtractedFacts(hints=anti_pattern_hints)
                )
            return parsed
    # Content-based dispatch fallback. Each signature must be specific
    # enough that mismatching is unlikely; order is most-distinctive first.
    # All branches merge anti_pattern_hints so the structured intel stays
    # consistent regardless of which parser fired.
    def _attach_hints(parsed: ExtractedFacts) -> ExtractedFacts:
        if anti_pattern_hints:
            return parsed.merge(ExtractedFacts(hints=anti_pattern_hints))
        return parsed

    head = output[:400].lower()
    if "dn:" in head and ("samaccountname" in head or "namingcontext" in head):
        return _attach_hints(_parse_ldapsearch(output))
    if "sharename" in head and "type" in head and "comment" in head:
        return _attach_hints(_parse_smbclient_shares(output))
    if "starting nmap" in head or re.search(r"\d{1,5}/tcp\s+open", output[:800]):
        return _attach_hints(_parse_nmap(output))
    if "impacket" in head and "krb5asrep" in output[:1000].lower():
        return _attach_hints(_parse_impacket_getnpusers(output))
    if "impacket" in head and "krb5tgs" in output[:1000].lower():
        return _attach_hints(_parse_impacket_getuserspns(output))
    if _NTLM_PAIR_RE.search(output[:2000]):
        return _attach_hints(_parse_secretsdump(output))
    if "$krb5" in output and ("$krb5asrep$" in output or "$krb5tgs$" in output):
        # Could be hashcat --show output too; cheap disambiguator: ":Password"
        # style trailing crack tail wins for hashcat. Otherwise treat as a
        # generic hash dump (covered by _parse_generic).
        if re.search(r"\$krb5(?:asrep|tgs)\$.*:[A-Za-z0-9!@#$%^&*_-]{4,}$", output, re.MULTILINE):
            parsed = _parse_hashcat(output)
            if anti_pattern_hints:
                parsed = parsed.merge(ExtractedFacts(hints=anti_pattern_hints))
            return parsed
    generic = _parse_generic(output)
    if anti_pattern_hints:
        generic = generic.merge(ExtractedFacts(hints=anti_pattern_hints))
    return generic


__all__ = [
    "ExtractedFacts",
    "EMPTY",
    "extract_facts",
]
