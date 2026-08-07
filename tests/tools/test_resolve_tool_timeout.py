"""Per-tool timeout heuristic: long offensive tools get 900s (not the 300s that
killed nuclei/sqlmap/hydra mid-run), interactive binaries fail fast at 60s.

Regression T3-A7 (dedicated wrappers used the 300s default) + T3-M3 (hydra/medusa
weren't classified as long-running)."""

from __future__ import annotations

import pytest

from kryon.tools.common._dispatchers import resolve_tool_timeout


@pytest.mark.parametrize(
    "cmd",
    [
        "nuclei -u https://t -tags cve",
        "sqlmap -u 'https://t/?id=1' --batch",
        "ffuf -u https://t/FUZZ -w wl",
        "gobuster dir -u https://t -w wl",
        "wpscan --url https://t",
        # T3-M3 — credential bruteforce
        "hydra -l admin -P rockyou.txt ssh://t",
        "medusa -h t -u admin -P rockyou.txt -M ssh",
        "nxc smb 10.0.0.5 -u '' -p ''",
        "kerbrute userenum -d t users.txt",
    ],
)
def test_long_tools_get_900(cmd):
    assert resolve_tool_timeout(cmd) == 900


@pytest.mark.parametrize("cmd", ["nc target 8000", "ssh user@t", "mysql -h t -u root"])
def test_quick_network_tools_get_60(cmd):
    assert resolve_tool_timeout(cmd) == 60


def test_default_for_ordinary_command():
    assert resolve_tool_timeout("cat /etc/passwd") == 300
    assert resolve_tool_timeout("cat /etc/passwd", default=120) == 120
