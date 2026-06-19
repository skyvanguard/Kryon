"""Batch R — SSH posture by parsing the unauthenticated handshake (banner +
SSH_MSG_KEXINIT, both sent before key exchange, so fully READ-ONLY, no auth).
One probe yields: Terrapin (CVE-2023-48795), weak kex/cipher/MAC/hostkey
algorithms, and a banner→CVE map (regreSSHion CVE-2024-6387).

Imports _f from service_probes (one-way; no import cycle).
"""

from __future__ import annotations

import re
import socket

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.service_probes import _f

_T = 6.0
_KEXINIT = 20


def _read_handshake(host: str, port: int) -> tuple[str, list[str]] | None:
    """Connect, read the server banner + KEXINIT (cleartext, pre-kex). Return
    (banner, [10 algorithm name-lists]) or None."""
    try:
        with socket.create_connection((host, port), timeout=_T) as s:
            s.settimeout(_T)
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(512)
                if not chunk:
                    return None
                buf += chunk
                if len(buf) > 8192:
                    return None
            idx = buf.index(b"\n")
            banner = buf[:idx].rstrip(b"\r").decode("latin-1", "replace")
            if not banner.startswith("SSH-"):
                return None
            s.sendall(b"SSH-2.0-kryon_probe\r\n")
            rest = buf[idx + 1:]
            while len(rest) < 4:
                chunk = s.recv(2048)
                if not chunk:
                    return None
                rest += chunk
            plen = int.from_bytes(rest[:4], "big")
            if plen < 1 or plen > 65536:
                return None
            while len(rest) < 4 + plen:
                chunk = s.recv(4096)
                if not chunk:
                    return None
                rest += chunk
    except (TimeoutError, OSError, ValueError):
        return None
    packet = rest[4:4 + plen]
    pad = packet[0]
    payload = packet[1:len(packet) - pad]
    if not payload or payload[0] != _KEXINIT:
        return None
    off = 17  # msg type (1) + cookie (16)
    lists: list[str] = []
    for _ in range(10):
        if off + 4 > len(payload):
            return None
        ln = int.from_bytes(payload[off:off + 4], "big")
        off += 4
        lists.append(payload[off:off + ln].decode("latin-1", "replace"))
        off += ln
    return banner, lists


_WEAK_KEX = ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "gss-group1-sha1", "rsa1024-sha1")
_WEAK_CIPHER = ("arcfour", "3des-cbc", "des-cbc", "blowfish-cbc", "cast128-cbc")
_WEAK_MAC = ("hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64", "hmac-ripemd160")
_WEAK_HOSTKEY = ("ssh-dss", "ssh-rsa")  # ssh-rsa = SHA-1 signature (deprecated)


def _check_terrapin(svc: DiscoveredService, kex: list[str], enc: list[str], mac: list[str]) -> Finding | None:
    strict = "kex-strict-s-v00@openssh.com" in kex
    if strict:
        return None
    chacha = "chacha20-poly1305@openssh.com" in enc
    cbc_etm = any(c.endswith("-cbc") for c in enc) and any(m.endswith("-etm@openssh.com") for m in mac)
    if chacha or cbc_etm:
        return _f(svc, "CWE-222", "MEDIUM", "ssh-terrapin",
                  f"SSH vulnerable a Terrapin (CVE-2023-48795) en {svc.host}:{svc.port} — sin kex-strict.",
                  f"Ofrece {'chacha20-poly1305' if chacha else 'CBC-EtM'} y NO anuncia kex-strict-s-v00@openssh.com",
                  "Actualizar OpenSSH ≥ 9.6 (habilita kex-strict); deshabilitar chacha20-poly1305 y CBC-EtM si no.")
    return None


def _check_weak_algos(svc: DiscoveredService, kex, hostkey, enc, mac) -> Finding | None:
    found = []
    found += [k for k in kex if k in _WEAK_KEX]
    found += [h for h in hostkey if h in _WEAK_HOSTKEY]
    found += [c for c in enc if c in _WEAK_CIPHER]
    found += [m for m in mac if m in _WEAK_MAC]
    if found:
        return _f(svc, "CWE-327", "LOW", "ssh-weak-algorithms",
                  f"SSH ofrece algoritmos débiles/obsoletos en {svc.host}:{svc.port}.",
                  "Anunciados: " + ", ".join(sorted(set(found))[:8]),
                  "Restringir a kex/cipher/MAC modernos (curve25519, aes-gcm, hmac-sha2-*+ETM); quitar SHA-1/CBC/arcfour.")
    return None


def _check_banner_cve(svc: DiscoveredService, banner: str) -> Finding | None:
    m = re.search(r"OpenSSH[_-](\d+)\.(\d+)", banner)
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    ver = (major, minor)
    if (8, 5) <= ver <= (9, 7):  # regreSSHion reintroduction range
        return _f(svc, "CWE-1395", "HIGH", "ssh-regresshion-candidate",
                  f"OpenSSH {major}.{minor} en {svc.host}:{svc.port} — rango afectado por regreSSHion (CVE-2024-6387, RCE root).",
                  f"Banner: {banner[:80]} (verificar: el banner es spoofeable y muchas distros backportean el fix)",
                  "Actualizar OpenSSH ≥ 9.8p1; mitigar con LoginGraceTime=0; confirmar parche real (no solo banner).")
    return None


def run_ssh_probes(svc: DiscoveredService) -> list[Finding]:
    """SSH handshake-based posture (Terrapin + weak algos + banner→CVE). Never raises."""
    out: list[Finding] = []
    try:
        hs = _read_handshake(svc.host, svc.port)
    except Exception:  # noqa: BLE001
        return out
    if not hs:
        return out
    banner, lists = hs
    kex, hostkey, enc_cs, enc_sc, mac_cs, mac_sc = (lists[i].split(",") for i in range(6))
    enc = enc_sc or enc_cs
    mac = mac_sc or mac_cs
    for f in (
        _check_terrapin(svc, kex, enc, mac),
        _check_weak_algos(svc, kex, hostkey, enc, mac),
        _check_banner_cve(svc, banner),
    ):
        if f:
            out.append(f)
    return out
