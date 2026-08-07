"""F198 — Asterisk SIP + AMI discovery (banner grab read-only).

Banca-safe by design:
  - SIP OPTIONS probe (RFC 3261) on UDP/TCP 5060 — standard health-check
    method, every SIP server replies, no auth required.
  - AMI banner grab on TCP 5038 — Asterisk Manager Interface always
    sends a greeting line `Asterisk Call Manager/<version>` before any
    auth dialog.

Used by:
  - `kryon engage` Phase 2b' device family detection — routes voip/sip
    targets to the `voip-asterisk-audit` skill.
  - The `voip-asterisk-audit` skill itself for the recon phase, before
    the deterministic checks read /etc/asterisk/*.conf via SSH.

No authentication. No INVITE / no actual calls. Just OPTIONS + banner.
"""

from __future__ import annotations

import re
import socket
from dataclasses import asdict, dataclass

from kryon.cache import cache_scan_result
from kryon.sdk.agents import function_tool

_SIP_TIMEOUT_S = 3
_AMI_TIMEOUT_S = 3
_AMI_PORT = 5038
_SIP_DEFAULT_PORT = 5060


@dataclass(frozen=True)
class AsteriskFingerprint:
    """Outcome of a single-host Asterisk recon probe."""

    host: str
    sip_responded: bool = False
    sip_user_agent: str = ""
    sip_server: str = ""
    ami_responded: bool = False
    ami_version: str = ""
    is_asterisk: bool = False  # union of all evidence — AMI banner or User-Agent

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# SIP OPTIONS probe
# ---------------------------------------------------------------------------


def _build_sip_options(target: str, src_port: int = 5060) -> bytes:
    """Standard SIP OPTIONS request, RFC 3261 §11.

    The Via branch uses the RFC-required z9hG4bK magic cookie + a
    deterministic suffix so the probe is reproducible.
    """
    return (
        f"OPTIONS sip:{target} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP kryon.local:{src_port};branch=z9hG4bK-kryon-probe\r\n"
        f"From: <sip:kryon@kryon.local>;tag=kryon-probe\r\n"
        f"To: <sip:{target}>\r\n"
        "Call-ID: kryon-probe@kryon.local\r\n"
        "CSeq: 1 OPTIONS\r\n"
        "Max-Forwards: 70\r\n"
        "User-Agent: kryon-voip-recon/1.0\r\n"
        "Accept: application/sdp\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    ).encode()


_USER_AGENT_RE = re.compile(r"^User-Agent:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)
_SERVER_RE = re.compile(r"^Server:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)


def _probe_sip(host: str, port: int = _SIP_DEFAULT_PORT) -> tuple[bool, str, str]:
    """Send a SIP OPTIONS probe over UDP. Returns (responded, user_agent, server).

    Never raises — network errors collapse to (False, "", "").
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(_SIP_TIMEOUT_S)
    try:
        sock.sendto(_build_sip_options(host), (host, port))
        data, _ = sock.recvfrom(4096)
    except (TimeoutError, OSError):
        return False, "", ""
    finally:
        sock.close()

    payload = data.decode("utf-8", errors="replace")
    user_agent = ""
    server = ""
    m = _USER_AGENT_RE.search(payload)
    if m:
        user_agent = m.group(1)
    m2 = _SERVER_RE.search(payload)
    if m2:
        server = m2.group(1)
    return True, user_agent, server


# ---------------------------------------------------------------------------
# AMI banner grab
# ---------------------------------------------------------------------------


_AMI_VERSION_RE = re.compile(r"Asterisk Call Manager(?:/(?P<v>[\d.]+))?", re.IGNORECASE)


def _probe_ami(host: str, port: int = _AMI_PORT) -> tuple[bool, str]:
    """Connect to TCP `port` and read the AMI greeting line.

    Asterisk always sends e.g. `Asterisk Call Manager/2.10.6\r\n` before
    any auth dialog — that's the banner we capture. We close the
    connection before sending any auth bytes — no login attempt.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(_AMI_TIMEOUT_S)
    try:
        sock.connect((host, port))
        # Read up to 256 bytes — AMI greeting is short.
        data = sock.recv(256)
    except (TimeoutError, OSError):
        return False, ""
    finally:
        sock.close()

    line = data.decode("utf-8", errors="replace").splitlines()[0] if data else ""
    m = _AMI_VERSION_RE.search(line)
    if m:
        version = m.group("v") or ""
        return True, version
    return False, ""


# ---------------------------------------------------------------------------
# Composite
# ---------------------------------------------------------------------------


def _fingerprint_one(host: str, sip_port: int, ami_port: int) -> AsteriskFingerprint:
    sip_responded, sip_ua, sip_srv = _probe_sip(host, sip_port)
    ami_responded, ami_version = _probe_ami(host, ami_port)

    ua_blob = (sip_ua + " " + sip_srv).lower()
    is_asterisk = ami_responded or "asterisk" in ua_blob or "freepbx" in ua_blob or "fpbx" in ua_blob

    return AsteriskFingerprint(
        host=host,
        sip_responded=sip_responded,
        sip_user_agent=sip_ua,
        sip_server=sip_srv,
        ami_responded=ami_responded,
        ami_version=ami_version,
        is_asterisk=is_asterisk,
    )


# ---------------------------------------------------------------------------
# Public function-tool
# ---------------------------------------------------------------------------


@function_tool
@cache_scan_result(scan_type="asterisk_fingerprint", ttl=14400)
def asterisk_discover(target: str, sip_port: int = 5060, ami_port: int = 5038) -> str:
    """Fingerprint a target as Asterisk / FreePBX / generic SIP / unknown.

    Sends a SIP OPTIONS probe (UDP 5060) + reads the AMI banner (TCP 5038).
    Read-only — no authentication, no INVITE, no actual calls.

    Args:
        target: IP or hostname of the suspected SIP / Asterisk server.
        sip_port: SIP port (default 5060).
        ami_port: Asterisk Manager Interface port (default 5038).

    Returns:
        Human-readable summary + a final `[parsed]` line for downstream
        code (is_asterisk=, ami_version=, sip_user_agent=).

    Examples:
        asterisk_discover(target="10.0.0.50")
        asterisk_discover(target="pbx.local", sip_port=5060)
    """
    fp = _fingerprint_one(target, sip_port, ami_port)

    lines = [f"Asterisk/SIP fingerprint for {target}:"]
    if fp.sip_responded:
        lines.append(
            f"  SIP UDP {sip_port}: responded, User-Agent='{fp.sip_user_agent or '-'}' Server='{fp.sip_server or '-'}'"
        )
    else:
        lines.append(f"  SIP UDP {sip_port}: no response (timeout {_SIP_TIMEOUT_S}s)")
    if fp.ami_responded:
        lines.append(f"  AMI TCP {ami_port}: greeting received, version='{fp.ami_version or 'unknown'}'")
    else:
        lines.append(f"  AMI TCP {ami_port}: no banner (timeout {_AMI_TIMEOUT_S}s or port closed)")

    if fp.is_asterisk:
        flavour = "Asterisk"
        if "freepbx" in (fp.sip_user_agent + fp.sip_server).lower():
            flavour = "FreePBX (Asterisk-based)"
        elif fp.ami_responded and not fp.sip_responded:
            flavour = "Asterisk (AMI only — SIP may be on a different port)"
        lines.append(f"  → {flavour} confirmed.")
    elif fp.sip_responded:
        lines.append("  → SIP server confirmed, NOT Asterisk (could be Kamailio/OpenSIPS/3CX/Cisco/Polycom).")
    else:
        lines.append("  → no SIP service detected on the queried ports.")

    lines.append(
        f"\n[parsed] is_asterisk={fp.is_asterisk} "
        f"ami_version={fp.ami_version or '-'} "
        f"sip_user_agent={fp.sip_user_agent or '-'}"
    )
    return "\n".join(lines)


__all__ = ["asterisk_discover", "AsteriskFingerprint"]
