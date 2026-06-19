"""Deterministic privilege-escalation analyzer. The enumeration tools collect raw
facts (SUID binaries, ``sudo -l``, writable files, capabilities, cron, kernel);
this applies deterministic rules to turn those facts into CONFIRMED escalation
vectors with explicit evidence — not LLM suggestions.

A vector is CONFIRMED when the evidence alone proves root is reachable (writable
``/etc/passwd``, a GTFOBins SUID binary, ``sudo NOPASSWD: ALL``, ``cap_setuid``,
a root-run writable cron script). It is a CANDIDATE when it depends on something
unverified here (kernel version in a known-exploit range — banners/uname can lie).

Pure: ``analyze_privesc(enum: dict) -> dict``. No network, no LLM.
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass

# GTFOBins binaries that yield root directly when SUID-root.
_GTFOBINS_SUID = frozenset({
    "bash", "sh", "dash", "zsh", "ksh", "find", "vim", "vi", "view", "rvim", "nano", "pico",
    "less", "more", "awk", "gawk", "mawk", "nawk", "perl", "python", "python2", "python3",
    "ruby", "php", "lua", "node", "env", "nmap", "cp", "mv", "tar", "zip", "gdb", "ftp",
    "socat", "busybox", "make", "gcc", "expect", "tee", "dd", "ed", "emacs", "flock",
    "ionice", "jjs", "jq", "openssl", "rsync", "scp", "sed", "setarch", "start-stop-daemon",
    "strace", "taskset", "time", "timeout", "watch", "xargs", "csh", "tclsh", "cpulimit",
})

# Capabilities that grant a path to root.
_DANGEROUS_CAPS = ("cap_setuid", "cap_setgid", "cap_dac_override", "cap_dac_read_search", "cap_sys_admin", "cap_sys_ptrace")

# (kernel_max_exclusive_or_range, cve, name). Compared as version tuples.
_KERNEL_EXPLOITS: tuple[tuple[tuple[int, ...], tuple[int, ...], str, str], ...] = (
    ((0, 0, 0), (4, 8, 3), "CVE-2016-5195", "Dirty COW"),
    ((5, 8), (5, 16, 11), "CVE-2022-0847", "Dirty Pipe"),
    ((5, 1), (5, 16, 0), "CVE-2021-22555", "Netfilter heap OOB"),
    ((3, 0), (5, 9, 0), "CVE-2021-3490", "eBPF ALU32 OOB"),
)


@dataclass
class PrivescVector:
    technique: str
    confidence: str  # CONFIRMED | CANDIDATE
    severity: str
    evidence: str
    recommendation: str


def _basename(path: str) -> str:
    return os.path.basename(path.split()[0].strip()) if path else ""


def _parse_kernel(version: str) -> tuple[int, ...] | None:
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", version or "")
    if not m:
        return None
    return tuple(int(g) for g in m.groups() if g is not None)


def _kernel_vectors(version: str) -> list[PrivescVector]:
    v = _parse_kernel(version)
    if not v:
        return []
    out: list[PrivescVector] = []
    for lo, hi, cve, name in _KERNEL_EXPLOITS:
        n = max(len(v), len(hi), len(lo))
        vp = v + (0,) * (n - len(v))
        if lo + (0,) * (n - len(lo)) <= vp < hi + (0,) * (n - len(hi)):
            out.append(PrivescVector("kernel-exploit", "CANDIDATE", "HIGH",
                f"Kernel {version} en rango de {name} ({cve}) — verificar parche real (uname es spoofeable)",
                f"Confirmar el microcódigo/parche; compilar/usar el PoC de {cve} solo en lab autorizado."))
    return out


def analyze_privesc(enum: dict) -> dict:
    """Turn a linux_privesc enumeration dict into confirmed/candidate vectors."""
    confirmed: list[PrivescVector] = []
    candidate: list[PrivescVector] = []

    for wf in enum.get("writable_files", []) or []:
        path = wf if isinstance(wf, str) else str(wf.get("path", wf))
        if "/etc/passwd" in path or "/etc/shadow" in path:
            confirmed.append(PrivescVector("writable-etc-passwd", "CONFIRMED", "CRITICAL",
                f"{path} es escribible → agregar un usuario root (openssl passwd) o crackear shadow",
                "Corregir permisos de /etc/passwd y /etc/shadow (644/640 root:root)."))

    for sb in enum.get("suid_binaries", []) or []:
        path = sb if isinstance(sb, str) else str(sb.get("path", sb))
        name = _basename(path)
        if name in _GTFOBINS_SUID:
            confirmed.append(PrivescVector("suid-gtfobins", "CONFIRMED", "CRITICAL",
                f"SUID-root en {path} ({name}) — técnica de root directa en GTFOBins",
                f"Remover el bit SUID de {path} (chmod u-s) si no es estrictamente necesario."))

    for sp in enum.get("sudo_permissions", []) or []:
        entry = sp if isinstance(sp, str) else str(sp.get("command", sp))
        low = entry.lower()
        if "nopasswd" not in low:
            continue
        after = low.split("nopasswd:", 1)[1].strip() if "nopasswd:" in low else ""
        cmds = {_basename(tok) for tok in re.split(r"[\s,]+", after) if tok}
        if "all" in after.split(",")[0].split() or after.startswith("all"):
            confirmed.append(PrivescVector("sudo-nopasswd-all", "CONFIRMED", "CRITICAL",
                f"sudo NOPASSWD que incluye ALL: '{entry.strip()[:80]}' → root sin contraseña",
                "Restringir las reglas sudo; nunca NOPASSWD: ALL; auditar /etc/sudoers."))
        elif cmds & _GTFOBINS_SUID:
            b = next(iter(cmds & _GTFOBINS_SUID))
            confirmed.append(PrivescVector("sudo-nopasswd-gtfobins", "CONFIRMED", "CRITICAL",
                f"sudo NOPASSWD en un binario GTFOBins ({b}): '{entry.strip()[:80]}'",
                f"Quitar {b} de las reglas sudo NOPASSWD (es escapable a shell root)."))

    for cap in enum.get("capabilities", []) or []:
        entry = cap if isinstance(cap, str) else str(cap.get("capability", cap))
        if any(c in entry.lower() for c in _DANGEROUS_CAPS):
            hit = next(c for c in _DANGEROUS_CAPS if c in entry.lower())
            confirmed.append(PrivescVector("dangerous-capability", "CONFIRMED", "HIGH",
                f"Capability peligrosa: '{entry.strip()[:80]}' ({hit})",
                f"Remover {hit} del binario (setcap -r) salvo justificación estricta."))

    for cj in enum.get("cron_jobs", []) or []:
        entry = cj if isinstance(cj, str) else str(cj.get("job", cj))
        if ("root" in entry.lower()) and ("writable" in entry.lower() or "(writable)" in entry.lower()):
            confirmed.append(PrivescVector("cron-writable-root", "CONFIRMED", "HIGH",
                f"Cron de root ejecuta un script/path escribible: '{entry.strip()[:80]}'",
                "Corregir permisos del script/directorio del cron; ejecutar con el mínimo privilegio."))

    kernel = (enum.get("system_info", {}) or {}).get("kernel") or (enum.get("system_info", {}) or {}).get("kernel_version", "")
    candidate.extend(_kernel_vectors(kernel))

    return {
        "confirmed_vectors": [asdict(v) for v in confirmed],
        "candidate_vectors": [asdict(v) for v in candidate],
        "root_reachable": bool(confirmed),
        "summary": f"{len(confirmed)} vector(es) confirmado(s), {len(candidate)} candidato(s)",
    }
