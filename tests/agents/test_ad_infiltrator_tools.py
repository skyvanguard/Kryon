"""Tests for ad_infiltrator post-exploitation tool registration."""


def test_ad_infiltrator_has_psexec():
    from kryon.agents.ad_infiltrator import ad_infiltrator

    tool_names = [getattr(t, "name", str(t)) for t in ad_infiltrator.tools]
    assert "psexec_lateral_movement" in tool_names, f"Missing psexec in: {tool_names}"


def test_ad_infiltrator_has_winrm():
    from kryon.agents.ad_infiltrator import ad_infiltrator

    tool_names = [getattr(t, "name", str(t)) for t in ad_infiltrator.tools]
    assert "winrm_lateral_movement" in tool_names, f"Missing winrm in: {tool_names}"


def test_ad_infiltrator_has_dump_lsass():
    from kryon.agents.ad_infiltrator import ad_infiltrator

    tool_names = [getattr(t, "name", str(t)) for t in ad_infiltrator.tools]
    assert "dump_lsass" in tool_names, f"Missing dump_lsass in: {tool_names}"


def test_ad_infiltrator_has_dcsync():
    from kryon.agents.ad_infiltrator import ad_infiltrator

    tool_names = [getattr(t, "name", str(t)) for t in ad_infiltrator.tools]
    assert "dcsync_attack" in tool_names, f"Missing dcsync_attack in: {tool_names}"
