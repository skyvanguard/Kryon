"""Deterministic Active Directory / Windows findings — SMB signing not required
(NTLM-relay enabler) and WinRM exposed (lateral-movement surface). READ-ONLY,
graceful. High value on internal engagements (the Britimp-style network audits).

Wired into the engage per-service sweep + investigate hybrid. Imports utilities
from service_probes (one-way; engage imports all the probe modules lazily, so no
import cycle).
"""

from __future__ import annotations

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.probe_base import DEFAULT_T as _T
from kryon.cli.service_probes import _f, _tcp


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


def _smbv1_negotiate_packet() -> bytes:
    """NetBIOS-framed SMBv1 SMB_COM_NEGOTIATE offering only the 'NT LM 0.12' dialect."""
    header = (
        b"\xffSMB"  # ProtocolId (SMBv1)
        b"\x72"  # Command 0x72 = NEGOTIATE
        b"\x00\x00\x00\x00"  # NT Status
        b"\x18"  # Flags
        b"\x01\x28"  # Flags2
        b"\x00\x00"  # PIDHigh
        + b"\x00" * 8  # SecurityFeatures
        + b"\x00\x00"  # Reserved
        b"\x00\x00"  # TID
        b"\x2f\x4b"  # PIDLow
        b"\x00\x00"  # UID
        b"\x00\x00"  # MID
    )
    body = b"\x00" + b"\x0c\x00" + b"\x02NT LM 0.12\x00"  # WordCount, ByteCount, dialect
    smb = header + body
    return b"\x00" + len(smb).to_bytes(3, "big") + smb


def _check_smbv1(svc: DiscoveredService) -> Finding | None:
    """SMBv1 enabled = EternalBlue / MS17-010 / WannaCry surface. A host with SMBv1
    disabled answers the SMBv1 negotiate with an SMB2 (\\xfeSMB) response or resets;
    a host with SMBv1 enabled answers with an SMBv1 (\\xffSMB) negotiate response."""
    resp = _tcp(svc.host, svc.port, _smbv1_negotiate_packet(), 256)
    if resp is None or len(resp) < 9 or resp[4:8] != b"\xffSMB":
        return None  # SMB2-only / reset / not SMB → SMBv1 not enabled
    if resp[8] != 0x72:  # the response must be to our NEGOTIATE
        return None
    return _f(
        svc, "CWE-477", "HIGH", "smbv1-enabled",
        f"SMBv1 habilitado en {svc.host}:{svc.port} — protocolo obsoleto (superficie EternalBlue/MS17-010/WannaCry).",
        "El server respondió un SMBv1 NEGOTIATE (\\xffSMB) al dialecto 'NT LM 0.12'",
        "Deshabilitar SMBv1 (GPO / Remove-WindowsFeature FS-SMB1); exigir SMBv2/3 con signing.",
    )


def _check_winrm(svc: DiscoveredService) -> Finding | None:
    """WinRM (Windows Remote Management) exposed — remote command exec surface."""
    from kryon.cli.probe_http import request  # noqa: PLC0415

    scheme = "https" if svc.port == 5986 else "http"
    # 405/401 is the EXPECTED WinRM response to a GET; request() surfaces it as the response.
    r = request(svc.host, svc.port, "/wsman", scheme=scheme, timeout=_T)
    if r is None:
        return None
    status, server = r.status, r.headers.get("server", "")
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
            for f in (_check_smb_signing(svc), _check_smbv1(svc)):
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
