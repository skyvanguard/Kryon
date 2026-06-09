"""Command-injection regression for the Active Directory compliance checks.

The AD checks build shell command strings from environment variables
(`KRYON_AD_DOMAIN/USER/PASS/DC`). Before the fix these were interpolated
raw inside `shell=True` commands, so a malicious value such as
``x; touch /tmp/pwned`` would execute. Every interpolated value must now
pass through ``shlex.quote`` so the payload is inert.

These tests monkeypatch `run_cmd`/`check_tool` in each check module to
capture the command string the check *would* run, without touching the
network or the filesystem.
"""

from __future__ import annotations

import shlex

import pytest

from kryon.compliance.checks import active_directory as ad_pkg  # noqa: F401
from kryon.compliance.checks.active_directory import (
    c_ad_1_1_ldap_signing,
    c_ad_1_3_anon_bind,
    c_ad_3_1_domain_admins,
    c_ad_4_1_smb_signing,
    c_ad_5_1_audit_policy,
)
from kryon.compliance.checks.base import CheckContext

# A payload that, unquoted, would chain an extra command.
PAYLOAD = "x; touch /tmp/pwned"


def _capture(monkeypatch, module):
    """Patch a check module so run_cmd records commands instead of running."""
    captured: list[str] = []

    def fake_run_cmd(ctx, cmd, *, timeout_s=15, shell=False):
        captured.append(cmd if isinstance(cmd, str) else " ".join(cmd))
        return ("", "", 0)

    monkeypatch.setattr(module, "run_cmd", fake_run_cmd, raising=True)
    # check_tool would otherwise short-circuit the check with "tool missing".
    if hasattr(module, "check_tool"):
        monkeypatch.setattr(module, "check_tool", lambda ctx, tool: True, raising=True)
    return captured


def _set_ad_env(monkeypatch, **overrides):
    env = {
        "KRYON_AD_DOMAIN": "corp.local",
        "KRYON_AD_USER": "svc-audit",
        "KRYON_AD_PASS": "s3cret",
        "KRYON_AD_DC": "dc01.corp.local",
    }
    env.update(overrides)
    for key, value in env.items():
        monkeypatch.setenv(key, value)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("module", "check_cls", "poisoned_var"),
    [
        (c_ad_1_1_ldap_signing, "_LdapSigningCheck", "KRYON_AD_USER"),
        (c_ad_1_1_ldap_signing, "_LdapSigningCheck", "KRYON_AD_DC"),
        (c_ad_1_3_anon_bind, "_AnonBindCheck", "KRYON_AD_DC"),
        (c_ad_3_1_domain_admins, "_DomainAdminsCheck", "KRYON_AD_PASS"),
        (c_ad_3_1_domain_admins, "_DomainAdminsCheck", "KRYON_AD_DOMAIN"),
        (c_ad_4_1_smb_signing, "_SmbSigningCheck", "KRYON_AD_DC"),
        (c_ad_5_1_audit_policy, "_AuditPolicyCheck", "KRYON_AD_USER"),
        (c_ad_5_1_audit_policy, "_AuditPolicyCheck", "KRYON_AD_DC"),
    ],
)
def test_ad_check_quotes_env_payload(monkeypatch, module, check_cls, poisoned_var):
    captured = _capture(monkeypatch, module)
    _set_ad_env(monkeypatch, **{poisoned_var: PAYLOAD})

    check = getattr(module, check_cls)()
    check.run(CheckContext(host="localhost"))

    assert captured, "the check did not build any command"

    # Real security assertion: lex each command the way a shell would.
    # If the payload were interpolated raw, `touch` / `/tmp/pwned` would
    # surface as standalone tokens (an executable chained after `;`).
    # Quoted, the whole payload stays inside a single token.
    all_tokens: list[str] = []
    for cmd in captured:
        all_tokens.extend(shlex.split(cmd))

    assert "touch" not in all_tokens, f"payload split into executable token: {captured!r}"
    assert "/tmp/pwned" not in all_tokens, f"payload split into executable token: {captured!r}"
    # The payload must survive intact inside one token (proves it was quoted,
    # possibly composed with other vars, not dropped or fragmented).
    assert any(PAYLOAD in tok for tok in all_tokens), f"payload not preserved-and-quoted: {captured!r}"
