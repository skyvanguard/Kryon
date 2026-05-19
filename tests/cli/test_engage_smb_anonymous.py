"""F202.Q — SMB anonymous share enumeration detector.

Surfaced POC Britimp .200.26 mediavault: smbclient -L -N anonymous
login successful + share `rpa-teisa` listable (cliente TEISA RPA).
Tree-connect denegado (file access protected) pero share-name
disclosure es info-leak pre-attack.

Severidad: LOW por default; MEDIUM cuando share matches keywords
sensitive (banking / payment / customer / prod / rpa).
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import (
    DiscoveredService,
    _check_smb_anonymous_shares,
    _SMB_FAILURE_MARKERS,
    _SMB_SENSITIVE_KEYWORDS,
)


def _svc(host: str = "172.18.200.26", port: int = 445, state: str = "open") -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state=state, service="microsoft-ds", product="")


def _fake_smbclient(stdout: str, stderr: str = "", returncode: int = 0):
    def _run(cmd, **_kw):
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)

    return _run


# Sample outputs
_SMB_BRITIMP_RPA_TEISA = """
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	rpa-teisa       Disk
	IPC$            IPC       IPC Service (rpa-teisa server)
SMB1 disabled -- no workgroup available
"""

_SMB_BANKING_SHARES = """
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	core-banking-backup  Disk
	payment-reports      Disk
	customer-data        Disk
	IPC$            IPC       IPC Service
"""

_SMB_GENERIC_SHARES = """
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	docs            Disk
	shared-folder   Disk
	IPC$            IPC       IPC Service
"""

_SMB_ONLY_IPC = """
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	IPC$            IPC       IPC Service
"""

_SMB_REFUSED = """
session setup failed: NT_STATUS_LOGON_FAILURE
"""


# ---------------------------------------------------------------------------
# Positive — POC Britimp .200.26 RPA-TEISA case (MEDIUM)
# ---------------------------------------------------------------------------


class TestBritimpRpaTeisa:
    def test_rpa_teisa_share_promotes_medium(self):
        """The exact .200.26 case: anonymous login OK + `rpa-teisa`
        share visible. 'rpa' es keyword sensitive -> MEDIUM."""
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_smbclient(_SMB_BRITIMP_RPA_TEISA)):
            finding = _check_smb_anonymous_shares(_svc())
        assert finding is not None
        assert finding.severity == "MEDIUM"
        assert finding.cwe == "CWE-200"
        assert finding.rule_id == "smb-anonymous-list"
        assert "rpa-teisa" in finding.message or "rpa-teisa" in finding.evidence
        assert "Samba" in finding.remediation


class TestBankingKeywords:
    def test_core_banking_payment_customer_all_medium(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_smbclient(_SMB_BANKING_SHARES)):
            finding = _check_smb_anonymous_shares(_svc())
        assert finding is not None
        assert finding.severity == "MEDIUM"
        # All 3 share names should appear in evidence
        assert "core-banking-backup" in finding.evidence
        assert "payment-reports" in finding.evidence
        assert "customer-data" in finding.evidence


# ---------------------------------------------------------------------------
# Positive — generic shares (LOW)
# ---------------------------------------------------------------------------


class TestGenericShares:
    def test_generic_shares_flag_low(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_smbclient(_SMB_GENERIC_SHARES)):
            finding = _check_smb_anonymous_shares(_svc())
        assert finding is not None
        assert finding.severity == "LOW"
        assert "docs" in finding.evidence
        assert "shared-folder" in finding.evidence


# ---------------------------------------------------------------------------
# Negative — IPC$ only, refused, etc.
# ---------------------------------------------------------------------------


class TestNegative:
    def test_only_ipc_no_flag(self):
        """If anonymous login works but only IPC$ is visible, NOT
        flag. IPC$ is always present and not data-disclosing."""
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_smbclient(_SMB_ONLY_IPC)):
            assert _check_smb_anonymous_shares(_svc()) is None

    def test_login_refused_no_flag(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_smbclient(_SMB_REFUSED)):
            assert _check_smb_anonymous_shares(_svc()) is None

    def test_connection_refused_no_flag(self):
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_smbclient(
            "smbclient: Connection refused\n", returncode=1
        )):
            assert _check_smb_anonymous_shares(_svc()) is None

    def test_dollar_suffix_admin_shares_skipped(self):
        """ADMIN$, C$, etc. are admin shares always present — should
        be filtered out, NOT counted as data shares."""
        admin_only = """
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk
	C$              Disk
	IPC$            IPC       IPC Service
"""
        with patch("kryon.cli.engage.subprocess.run", side_effect=_fake_smbclient(admin_only)):
            # Only IPC$ + admin shares — should NOT flag
            assert _check_smb_anonymous_shares(_svc()) is None


# ---------------------------------------------------------------------------
# Gate — port / state / missing smbclient
# ---------------------------------------------------------------------------


class TestGate:
    def test_non_445_port_skipped(self):
        svc = DiscoveredService(host="h", port=22, state="open", service="ssh", product="")
        with patch("kryon.cli.engage.subprocess.run", side_effect=AssertionError("must not call")):
            assert _check_smb_anonymous_shares(svc) is None

    def test_closed_445_skipped(self):
        svc = DiscoveredService(host="h", port=445, state="closed", service="microsoft-ds", product="")
        with patch("kryon.cli.engage.subprocess.run", side_effect=AssertionError("must not call")):
            assert _check_smb_anonymous_shares(svc) is None

    def test_smbclient_missing_skip_silently(self):
        def _fnf(cmd, **_kw):
            raise FileNotFoundError("smbclient not installed")

        with patch("kryon.cli.engage.subprocess.run", side_effect=_fnf):
            assert _check_smb_anonymous_shares(_svc()) is None


# ---------------------------------------------------------------------------
# Keyword table sanity
# ---------------------------------------------------------------------------


class TestKeywordSanity:
    def test_rpa_in_keywords(self):
        assert "rpa" in _SMB_SENSITIVE_KEYWORDS

    def test_banking_keywords_present(self):
        for kw in ("bank", "payment", "swift", "customer"):
            assert kw in _SMB_SENSITIVE_KEYWORDS

    def test_failure_markers_lowercase(self):
        for m in _SMB_FAILURE_MARKERS:
            assert m == m.lower()
