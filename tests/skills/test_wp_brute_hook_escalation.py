"""Structural tests for the wordpress-brute-active pre_hook CVE-2023-1874 escalation.

The hook drives a live target (wpscan brute -> wp-admin login -> theme-editor webshell), so behaviour is
validated against THM boxes, not in unit tests. These checks pin the CVE-2023-1874 subscriber->admin
escalation wiring added while validating THM Breakme (bob:soccer was a Subscriber; the theme-editor webshell
needs admin, so the hook must self-escalate via WP Data Access's unchecked wpda_role[] field first).
"""

from __future__ import annotations

import importlib.util
import inspect
from pathlib import Path

_HOOK = Path(__file__).resolve().parents[2] / "src/kryon/skills/playbooks/cwe-detection/wpscan_brute_hook.py"


def _load():
    spec = importlib.util.spec_from_file_location("wpscan_brute_hook", _HOOK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_escalation_helper_exists():
    mod = _load()
    assert callable(mod._escalate_wpda)
    # signature is (vhost, base, ck) — the live cookie jar from the cracked login
    assert list(inspect.signature(mod._escalate_wpda).parameters) == ["vhost", "base", "ck"]


def test_escalation_uses_cve_2023_1874_param_tampering():
    src = inspect.getsource(_load()._escalate_wpda)
    # the unchecked role field is the whole bug — must be posted to the profile update
    assert "wpda_role[]=administrator" in src
    assert "profile.php" in src and "action=update" in src
    # gates on getting back admin (theme-editor 200), not a blind POST
    assert "theme-editor.php" in src and '== "200"' in src


def test_webshell_invokes_escalation_when_low_priv():
    src = inspect.getsource(_load()._webshell_and_loot)
    # only escalate when the cracked user is actually low-priv (theme-editor 403), then retry the webshell
    assert "_escalate_wpda(" in src and 'te_code == "403"' in src
    assert "CVE-2023-1874" in src
