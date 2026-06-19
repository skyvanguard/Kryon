"""Deterministic Active Directory / Windows findings — SMB signing not required
(NTLM-relay enabler) and WinRM exposed (lateral-movement surface). READ-ONLY,
graceful. High value on internal engagements (the Britimp-style network audits).

Wired into the engage per-service sweep + investigate hybrid. Imports utilities
from service_probes (one-way; engage imports all the probe modules lazily, so no
import cycle).
"""

from __future__ import annotations

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.service_probes import _f, _tcp

_T = 4.0


def _smb2_negotiate_packet() -> bytes:
    """NetBIOS-framed SMB2 NEGOTIATE offering dialects 2.0.2 + 2.1."""
    header = (
        b"\xfeSMB"  # ProtocolId
        b"\x40\x00"  # StructureSize 64
        b"\x00\x00"  # CreditCharge
        b"\x00\x00\x00\x00"  # Status
        b"\x00\x00"  # Command 0 = NEGOTIATE
        b"\x00\x00"  # CreditRequest
        b"\x00\x00\x00\x00"  # Flags
        b"\x00\x00\x00\x00"  # NextCommand
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # MessageId
        b"\x00\x00\x00\x00"  # Reserved/ProcessId
        b"\x00\x00\x00\x00"  # TreeId
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # SessionId
        + b"\x00" * 16  # Signature
    )
    body = (
        b"\x24\x00"  # StructureSize 36
        b"\x02\x00"  # DialectCount 2
        b"\x01\x00"  # SecurityMode: SIGNING_ENABLED
        b"\x00\x00"  # Reserved
        b"\x00\x00\x00\x00"  # Capabilities
        + b"\x00" * 16  # ClientGuid
        + b"\x00" * 8  # ClientStartTime
        + b"\x02\x02\x10\x02"  # Dialects: 2.0.2, 2.1
    )
    smb = header + body
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _check_smb_signing(svc: DiscoveredService) -> Finding | None:
    """SMB signing NOT required = NTLM relay enabler. SMB2 NEGOTIATE response
    SecurityMode bit 0x0002 (SIGNING_REQUIRED) absent → relayable."""
    resp = _tcp(svc.host, svc.port, _smb2_negotiate_packet(), 256)
    if resp is None or len(resp) < 76 or resp[4:8] != b"\xfeSMB":
        return None  # not SMB2 / no valid response
    # NetBIOS(4) + SMB2 header(64) + body: SecurityMode at body offset 2 → 4+64+2 = 70
    security_mode = int.from_bytes(resp[70:72], "little")
    if not (security_mode & 0x0002):  # SIGNING_REQUIRED not set
        return _f(
            svc, "CWE-287", "MEDIUM", "smb-signing-not-required",
            f"SMB signing NO requerido en {svc.host}:{svc.port} — habilita ataques de NTLM relay.",
            f"SMB2 NEGOTIATE SecurityMode=0x{security_mode:04x} (sin el bit SIGNING_REQUIRED 0x0002)",
            "Forzar SMB signing (GPO: 'Microsoft network server: Digitally sign communications (always)').",
        )
    return None


def _check_winrm(svc: DiscoveredService) -> Finding | None:
    """WinRM (Windows Remote Management) exposed — remote command exec surface."""
    import urllib.error  # noqa: PLC0415
    import urllib.request  # noqa: PLC0415

    scheme = "https" if svc.port == 5986 else "http"
    ctx = None
    if scheme == "https":
        import ssl  # noqa: PLC0415

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    server = ""
    status = 0
    try:
        req = urllib.request.Request(f"{scheme}://{svc.host}:{svc.port}/wsman", headers={"User-Agent": "kryon"})
        with urllib.request.urlopen(req, timeout=_T, context=ctx) as r:  # noqa: S310
            status, server = r.status, r.headers.get("Server", "")
    except urllib.error.HTTPError as e:  # 405/401 is the EXPECTED WinRM response to GET
        status = e.code
        server = e.headers.get("Server", "") if e.headers else ""
    except (OSError, ValueError):
        return None
    if status in (401, 405) and ("Microsoft-HTTPAPI" in server or scheme == "https" or status == 405):
        return _f(
            svc, "CWE-200", "MEDIUM", "winrm-exposed",
            f"WinRM expuesto en {svc.host}:{svc.port} ({scheme}) — superficie de ejecución remota.",
            f"GET /wsman → {status} (Server: {server or 'Microsoft-HTTPAPI'})",
            "Restringir WinRM a hosts de management/VPN; usar HTTPS (5986) + auth fuerte; no exponer a internet.",
        )
    return None


def run_ad_probes(svc: DiscoveredService) -> list[Finding]:
    """SMB signing (445) + WinRM (5985/5986). Never raises."""
    out: list[Finding] = []
    try:
        if svc.service in ("microsoft-ds", "netbios-ssn", "smb") or svc.port in (445, 139):
            f = _check_smb_signing(svc)
            if f:
                out.append(f)
    except Exception:  # noqa: BLE001
        pass
    try:
        if svc.service in ("wsman", "winrm") or svc.port in (5985, 5986):
            f = _check_winrm(svc)
            if f:
                out.append(f)
    except Exception:  # noqa: BLE001
        pass
    return out
