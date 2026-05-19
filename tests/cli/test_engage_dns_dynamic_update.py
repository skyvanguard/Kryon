"""F202.G — DNS dynamic UPDATE without TSIG auth detection.

Septimo (y final) check de la heptalogia DNS (F202.A/B/C/D/E/F/G).
Detecta DNS servers que aceptan RFC 2136 UPDATE sin TSIG / GSS-TSIG —
permitiendo a un atacante reescribir MX / inyectar A records de
phishing / borrar records criticos sin credenciales.

Probe: dnspython construye una UpdateMessage no-op (delete de record
inexistente) contra zone candidate (derivada de PTR del target).
RCODE NOERROR -> server procesó -> finding HIGH CWE-345.
"""

from __future__ import annotations

import os
import subprocess
import sys
import types
from unittest.mock import MagicMock, patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import DiscoveredService, _check_dns_dynamic_update


def _svc(host: str = "172.18.201.205", port: int = 53, state: str = "open") -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state=state, service="domain", product="")


def _ptr_for_zone(zone: str) -> str:
    """nslookup PTR response for the target IP yielding `zone`."""
    return (
        "Server:  UnKnown\n"
        "Address:  172.18.201.205\n"
        "\n"
        f"Name:    dc01.{zone}\n"
        f"Address:  172.18.201.205\n"
    )


def _patched_dns_response(rcode_value: int):
    """Returns a MagicMock that mimics dns.message.Message with a
    .rcode() method returning rcode_value (so we can simulate
    NOERROR / REFUSED / NOTAUTH without making real DNS calls)."""
    mock = MagicMock()
    mock.rcode.return_value = rcode_value
    return mock


# ---------------------------------------------------------------------------
# Positive — UPDATE accepted (RCODE=NOERROR)
# ---------------------------------------------------------------------------


class TestUpdateAccepted:
    def test_update_with_noerror_flags_high(self):
        """The worst case: dnspython gets a NOERROR back -> server
        processed the no-op UPDATE -> vulnerable."""
        import dns.rcode

        # Patch nslookup PTR to return a zone candidate, and patch
        # dns.query.udp to return a NOERROR response.
        def _multi(cmd, **_kw):
            return subprocess.CompletedProcess(cmd, 0, stdout=_ptr_for_zone("britimp.com.py"), stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi), \
             patch("dns.query.udp", return_value=_patched_dns_response(dns.rcode.NOERROR)):
            finding = _check_dns_dynamic_update(_svc())

        assert finding is not None
        assert finding.severity == "HIGH"
        assert finding.cwe == "CWE-345"
        assert finding.rule_id == "dns-dynamic-update-open"
        assert "britimp.com.py" in finding.message
        assert "TSIG" in finding.remediation
        assert "RFC 2136" in finding.message or "UPDATE" in finding.message


# ---------------------------------------------------------------------------
# Negative — secure RCODEs (REFUSED / NOTAUTH / FORMERR / NXRRSET)
# ---------------------------------------------------------------------------


class TestUpdateRejected:
    def test_refused_no_finding(self):
        import dns.rcode

        def _multi(cmd, **_kw):
            return subprocess.CompletedProcess(cmd, 0, stdout=_ptr_for_zone("britimp.com.py"), stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi), \
             patch("dns.query.udp", return_value=_patched_dns_response(dns.rcode.REFUSED)):
            assert _check_dns_dynamic_update(_svc()) is None

    def test_notauth_no_finding(self):
        """NOTAUTH = TSIG required."""
        import dns.rcode

        def _multi(cmd, **_kw):
            return subprocess.CompletedProcess(cmd, 0, stdout=_ptr_for_zone("britimp.com.py"), stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi), \
             patch("dns.query.udp", return_value=_patched_dns_response(dns.rcode.NOTAUTH)):
            assert _check_dns_dynamic_update(_svc()) is None

    def test_formerr_no_finding(self):
        import dns.rcode

        def _multi(cmd, **_kw):
            return subprocess.CompletedProcess(cmd, 0, stdout=_ptr_for_zone("britimp.com.py"), stderr="")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi), \
             patch("dns.query.udp", return_value=_patched_dns_response(dns.rcode.FORMERR)):
            assert _check_dns_dynamic_update(_svc()) is None


# ---------------------------------------------------------------------------
# Graceful degradation — dnspython missing / network errors
# ---------------------------------------------------------------------------


class TestGracefulDegradation:
    def test_dnspython_missing_skip_silently(self):
        """Patch the dynamic imports to raise ImportError. Check
        skips with None, no exception bubbles up."""
        # We achieve this by inserting a sys.modules stub that raises
        # on dns.update access. Cleaner approach: monkey-patch the
        # function to simulate ImportError.
        original = sys.modules.get("dns.update")
        sys.modules["dns.update"] = None  # type: ignore
        try:
            assert _check_dns_dynamic_update(_svc()) is None
        finally:
            if original is None:
                sys.modules.pop("dns.update", None)
            else:
                sys.modules["dns.update"] = original

    def test_timeout_no_finding(self):
        """dns.query.udp raises dns.exception.Timeout — caught."""
        import dns.exception

        def _multi(cmd, **_kw):
            return subprocess.CompletedProcess(cmd, 0, stdout=_ptr_for_zone("britimp.com.py"), stderr="")

        def _raise_timeout(*args, **kwargs):
            raise dns.exception.Timeout

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi), \
             patch("dns.query.udp", side_effect=_raise_timeout):
            assert _check_dns_dynamic_update(_svc()) is None

    def test_oserror_no_finding(self):
        def _multi(cmd, **_kw):
            return subprocess.CompletedProcess(cmd, 0, stdout=_ptr_for_zone("britimp.com.py"), stderr="")

        def _raise_oserror(*args, **kwargs):
            raise OSError("network unreachable")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_multi), \
             patch("dns.query.udp", side_effect=_raise_oserror):
            assert _check_dns_dynamic_update(_svc()) is None


# ---------------------------------------------------------------------------
# Reverse zones skipped — operationally sensitive
# ---------------------------------------------------------------------------


class TestReverseZoneSkipped:
    def test_in_addr_arpa_is_skipped(self):
        """Even if PTR yields only an in-addr.arpa candidate, we don't
        attempt UPDATE on reverse zones (PTR mutations are more
        sensitive operationally)."""
        import dns.rcode

        # PTR returns nothing useful -> only the reverse zone is in
        # the candidate list.
        with patch("kryon.cli.engage.subprocess.run", side_effect=lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")), \
             patch("dns.query.udp", return_value=_patched_dns_response(dns.rcode.NOERROR)) as p:
            assert _check_dns_dynamic_update(_svc()) is None
            # And dns.query.udp must NOT have been invoked because
            # the only candidate was in-addr.arpa.
            assert p.call_count == 0


# ---------------------------------------------------------------------------
# Gate — service / port filter
# ---------------------------------------------------------------------------


class TestGate:
    def test_non_dns_port_skipped(self):
        svc = DiscoveredService(host="h", port=80, state="open", service="http", product="")
        with patch("dns.query.udp", side_effect=AssertionError("must not call")):
            assert _check_dns_dynamic_update(svc) is None

    def test_closed_port_skipped(self):
        svc = DiscoveredService(host="172.18.201.205", port=53, state="closed", service="domain", product="")
        with patch("dns.query.udp", side_effect=AssertionError("must not call")):
            assert _check_dns_dynamic_update(svc) is None

    def test_no_zones_skipped(self):
        """If PTR returns nothing AND target is non-IPv4, no candidates -> skip."""
        svc = DiscoveredService(host="notanip", port=53, state="open", service="domain", product="")
        with patch("kryon.cli.engage.subprocess.run", side_effect=lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")), \
             patch("dns.query.udp", side_effect=AssertionError("must not call")):
            assert _check_dns_dynamic_update(svc) is None
