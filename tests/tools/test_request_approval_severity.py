"""3A — action severity must reflect what the command DOES, not the severity of
the finding that motivated it.

Live against example the agent proposed benign meta-actions ("Persist findings
into the pattern library", "Generate a report", "Re-scan") tagged with the
finding's "critical" severity, which _SEV_ALIAS turned into ⚠ destructive.
_command_severity grounds the label in the command/purpose text instead.
"""

from __future__ import annotations

import pytest

from kryon.tools.validation.request_approval import _command_severity, _normalise_severity


@pytest.mark.parametrize(
    "text",
    [
        "Persist findings into the pattern library for future reference",
        "Generate a report with findings and recommendations",
        "Re-scan with more detailed output",
        "curl https://target/",
        "nmap -sV target",
    ],
)
def test_benign_actions_are_read_not_destructive(text: str) -> None:
    assert _command_severity(text) == "read"


@pytest.mark.parametrize(
    "text",
    [
        "rm -rf /var/www",
        "DROP TABLE users",
        "mkfs.ext4 /dev/sda1",
        "systemctl stop nginx && rm -rf /etc/nginx",  # destructive marker wins
    ],
)
def test_destructive_commands_are_destructive(text: str) -> None:
    assert _command_severity(text) == "destructive"


@pytest.mark.parametrize(
    "text",
    [
        "sed -i 's/foo/bar/' /etc/config",
        "systemctl reload nginx",
        "chmod 640 /etc/shadow",
    ],
)
def test_modifying_commands_are_modify(text: str) -> None:
    assert _command_severity(text) == "modify"


def test_opaque_command_falls_back_to_none() -> None:
    # No recognizable verb → caller falls back to the LLM-supplied hint.
    assert _command_severity("frobnicate the widget") is None


def test_destructive_precedence_over_read_marker() -> None:
    # "report" (read) + "rm -rf" (destructive) → destructive must win.
    assert _command_severity("generate report then rm -rf /tmp/x") == "destructive"


def test_finding_severity_no_longer_forces_destructive() -> None:
    # The LLM alias still maps 'critical' -> destructive, but the command
    # classifier is consulted FIRST for benign text, so the demo bug is fixed.
    assert _normalise_severity("critical") == "destructive"  # unchanged alias
    assert _command_severity("Generate a report") == "read"  # overrides it
