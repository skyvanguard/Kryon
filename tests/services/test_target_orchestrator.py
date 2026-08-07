"""Contract for the shared engage-grade target orchestrator (REPL unification)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from kryon.services import target_orchestrator as O


def test_cidr_is_rejected_with_a_note():
    res = O.run_target_orchestration("10.0.0.0/24", console=MagicMock())
    assert res.note
    assert not res.services
    assert not res.findings


def test_is_cidr_and_bare_host_helpers():
    assert O._is_cidr("10.0.0.0/24") is True
    assert O._is_cidr("10.0.0.5") is False
    assert O._bare_host("https://x.com:8443/p") == "x.com"
    assert O._bare_host("10.0.0.5:22") == "10.0.0.5"


def test_service_url_scheme_mapping():
    svc22 = MagicMock(port=22, service="ssh")
    svc443 = MagicMock(port=443, service="https")
    svc9999 = MagicMock(port=9999, service="unknown")
    assert O._service_url("h", svc22) == "ssh://h:22"
    assert O._service_url("h", svc443) == "https://h:443"
    assert O._service_url("h", svc9999).startswith("tcp://")


def test_orchestration_composes_discovery_battery_compliance_dedup():
    import kryon.cli.engage as E
    import kryon.cli.investigate as I
    from kryon.cli.engage import DiscoveredService

    svcs = [
        DiscoveredService(host="10.0.0.5", port=443, state="open", service="https"),
        DiscoveredService(host="10.0.0.5", port=22, state="open", service="ssh"),
    ]
    f = MagicMock(rule_id="http-headers", cwe="CWE-693", severity="MEDIUM")

    with (
        patch.object(E, "_run_nmap", lambda h, **k: "<xml/>"),
        patch.object(E, "_parse_nmap_xml", lambda x, h: svcs),
        patch.object(E, "_detect_device_families", lambda s: ["linux"]),
        patch.object(E, "_run_device_compliance", lambda c, **k: [f]),
        patch.object(I, "_run_deterministic_phase", lambda url, **k: [f]),
        patch("kryon.repl.engine_phase.format_engine_ground_truth", lambda fs, t: f"GT:{len(fs)}"),
    ):
        res = O.run_target_orchestration("10.0.0.5", console=MagicMock())

    assert res.discovery_ran is True
    assert len(res.services) == 2
    assert res.families == ["linux"]
    assert len(res.findings) >= 2  # battery per service + compliance
    assert res.ground_truth.startswith("GT:")


def test_synthetic_service_when_discovery_empty():
    import kryon.cli.engage as E
    import kryon.cli.investigate as I

    with (
        patch.object(E, "_run_nmap", lambda h, **k: ""),
        patch.object(E, "_parse_nmap_xml", lambda x, h: []),
        patch.object(E, "_detect_device_families", lambda s: []),
        patch.object(I, "_run_deterministic_phase", lambda url, **k: []),
    ):
        res = O.run_target_orchestration("https://x.com:8443", console=MagicMock())
    # Falls back to probing the given target rather than zero coverage.
    assert len(res.services) == 1
    assert res.services[0].port == 8443


def _mk_skill(name: str, required_tools: list[str]):
    s = MagicMock()
    s.name = name
    s.required_tools = required_tools
    return s


def test_host_compliance_skill_pruned_when_no_ssh_creds():
    """Regression (example `audita <web>`): a host-compliance skill declares a
    REQUIRED run_compliance_audit pre_hook that needs SSH. Hot-swapping it against
    a remote web target with no creds fired that pre_hook, which hung ~180s on the
    unreachable host and killed the run. It must be pruned when host is unreachable."""
    import kryon.cli.engage as E
    import kryon.cli.investigate as I
    from kryon.cli.engage import DiscoveredService

    svcs = [DiscoveredService(host="1.2.3.4", port=443, state="open", service="https")]
    f = MagicMock(rule_id="http-headers", cwe="CWE-693", severity="MEDIUM")

    loader = MagicMock()
    loader.match.return_value = [
        _mk_skill("tomcat-audit", ["run_compliance_audit"]),  # host-compliance
        _mk_skill("recon-scout", ["web_fetch_smart"]),  # normal
    ]
    agent = MagicMock()
    agent._skill_loader = loader
    captured: dict = {}

    with (
        patch.object(E, "_run_nmap", lambda h, **k: "<xml/>"),
        patch.object(E, "_parse_nmap_xml", lambda x, h: svcs),
        patch.object(E, "_detect_device_families", lambda s: ["tomcat"]),
        patch.object(I, "_run_deterministic_phase", lambda url, **k: [f]),
        patch("kryon.skills.unified_agent.update_agent_skills", lambda a, sk: captured.update(skills=sk)),
        patch("kryon.repl.engine_phase.format_engine_ground_truth", lambda fs, t: "GT"),
    ):
        # No ssh_user/ssh_key -> not _host_reachable
        O.run_target_orchestration("1.2.3.4", console=MagicMock(), agent=agent)

    names = [s.name for s in captured.get("skills", [])]
    assert "tomcat-audit" not in names  # compliance pre_hook skill pruned
    assert "recon-scout" in names  # normal skill kept


def test_host_compliance_skill_kept_when_ssh_creds_present():
    """Same setup but WITH ssh creds -> host reachable -> compliance skill kept
    (its pre_hook can actually run over SSH)."""
    import kryon.cli.engage as E
    import kryon.cli.investigate as I
    from kryon.cli.engage import DiscoveredService

    svcs = [DiscoveredService(host="1.2.3.4", port=443, state="open", service="https")]
    loader = MagicMock()
    loader.match.return_value = [_mk_skill("tomcat-audit", ["run_compliance_audit"])]
    agent = MagicMock()
    agent._skill_loader = loader
    captured: dict = {}

    with (
        patch.object(E, "_run_nmap", lambda h, **k: "<xml/>"),
        patch.object(E, "_parse_nmap_xml", lambda x, h: svcs),
        patch.object(E, "_detect_device_families", lambda s: ["tomcat"]),
        patch.object(E, "_run_device_compliance", lambda c, **k: []),
        patch.object(I, "_run_deterministic_phase", lambda url, **k: []),
        patch("kryon.skills.unified_agent.update_agent_skills", lambda a, sk: captured.update(skills=sk)),
        patch("kryon.repl.engine_phase.format_engine_ground_truth", lambda fs, t: "GT"),
    ):
        O.run_target_orchestration("1.2.3.4", console=MagicMock(), agent=agent, ssh_user="root")

    names = [s.name for s in captured.get("skills", [])]
    assert "tomcat-audit" in names  # creds present -> compliance kept


# ---------------------------------------------------------------------------
# Per-stage unit tests (dependency-injected — no engage/investigate patching).
# These exercise the extracted _stage_* helpers in isolation.
# ---------------------------------------------------------------------------


def test_stage_discover_uses_injected_nmap():
    svcs = [MagicMock(port=443)]
    services, ran = O._stage_discover(
        "10.0.0.5",
        "10.0.0.5",
        discover=True,
        console=MagicMock(),
        run_nmap=lambda h: "<xml/>",
        parse_nmap_xml=lambda x, h: svcs,
    )
    assert ran is True
    assert services == svcs


def test_stage_discover_falls_back_to_synthetic_on_failure():
    def boom(h):
        raise RuntimeError("nmap down")

    services, ran = O._stage_discover(
        "https://x.com:8443",
        "x.com",
        discover=True,
        console=MagicMock(),
        run_nmap=boom,
        parse_nmap_xml=lambda x, h: [],
    )
    assert ran is False
    assert len(services) == 1 and services[0].port == 8443


def test_stage_discover_skipped_does_not_call_nmap():
    def must_not_run(h):
        raise AssertionError("nmap should not run when discover=False")

    services, ran = O._stage_discover(
        "10.0.0.5:22",
        "10.0.0.5",
        discover=False,
        console=MagicMock(),
        run_nmap=must_not_run,
        parse_nmap_xml=lambda x, h: [],
    )
    assert ran is False
    assert len(services) == 1 and services[0].port == 22


def test_stage_battery_dedups_by_port_and_survives_one_failure():
    calls: list[str] = []

    def fake_phase(url, **k):
        calls.append(url)
        if ":22" in url:
            raise RuntimeError("ssh probe failed")
        return [MagicMock(rule_id="http-headers")]

    svcs = [
        MagicMock(port=443, service="https"),
        MagicMock(port=443, service="https"),  # dup port → skipped
        MagicMock(port=22, service="ssh"),  # fails → does not abort
    ]
    findings = O._stage_battery(
        "h",
        svcs,
        max_services=24,
        console=MagicMock(),
        run_deterministic_phase=fake_phase,
        ssh_user="",
        ssh_password="",
        ssh_key="",
        db_user="",
        db_password="",
        include_dns=False,
        include_smb=False,
    )
    assert len(findings) == 1  # one 443 finding; dup skipped; 22 failed
    assert len([u for u in calls if ":443" in u]) == 1  # deduped by port


def test_stage_family_compliance_skips_when_not_reachable():
    called: list[str] = []

    def fake_compliance(console, **k):
        called.append(k["family"])
        return [MagicMock()]

    out = O._stage_family_compliance(
        ["tomcat"],
        "1.2.3.4",
        host_reachable=False,
        ssh_user="",
        ssh_key="",
        console=MagicMock(),
        run_device_compliance=fake_compliance,
        known_families={"tomcat"},
    )
    assert out == [] and called == []


def test_stage_family_compliance_runs_known_and_reachable_only():
    def fake_compliance(console, **k):
        return [MagicMock(rule_id="tomcat-x")]

    out = O._stage_family_compliance(
        ["tomcat", "unknownfam"],
        "h",
        host_reachable=True,
        ssh_user="root",
        ssh_key="",
        console=MagicMock(),
        run_device_compliance=fake_compliance,
        known_families={"tomcat"},
    )
    assert len(out) == 1  # tomcat known+reachable; unknownfam skipped


def test_stage_hot_swap_noop_without_agent():
    assert O._stage_hot_swap(None, families=["x"], findings=[], host_reachable=True, console=MagicMock()) == []


def test_stage_dedup_passthrough_when_disabled(monkeypatch):
    monkeypatch.setenv("KRYON_FINDING_DEDUP", "false")
    fs = [MagicMock(), MagicMock()]
    assert O._stage_dedup(fs) is fs


def test_stage_ground_truth_empty_findings_returns_empty():
    assert O._stage_ground_truth([], "target") == ""


def _inferred_cve_finding():
    from types import SimpleNamespace

    return SimpleNamespace(
        cwe="CWE-1395",
        severity="CRITICAL",
        host="10.0.0.5",
        rule_id="cve-2021-41773",
        message="CVE-2021-41773 aplicable en 10.0.0.5:80",
        evidence="banner Apache/2.4.49",
        verification_level="inferred",
    )


def test_stage_ground_truth_gate_off_is_byte_identical(monkeypatch):
    # Banca-safe guarantee: with the gate OFF, output must equal the base
    # ground-truth block — the CVE-context append is byte-invisible.
    for k in ("KRYON_CVE_EXPLOIT_CONTEXT", "KRYON_RED_TEAM", "KRYON_CAPABLE_MODEL"):
        monkeypatch.delenv(k, raising=False)
    from kryon.repl.engine_phase import format_engine_ground_truth

    findings = [_inferred_cve_finding()]
    assert O._stage_ground_truth(findings, "10.0.0.5") == format_engine_ground_truth(findings, "10.0.0.5")


def test_stage_ground_truth_appends_cve_context_when_gated(monkeypatch):
    import kryon.intelligence.cve_context_injector as inj

    monkeypatch.setattr(inj, "is_cve_exploit_context_enabled", lambda: True)

    async def _fake_build(findings, **kw):
        return "\n---\n## Contexto de explotación (one-day)\nPath traversal → RCE."

    monkeypatch.setattr(inj, "build_cve_exploitation_context", _fake_build)

    out = O._stage_ground_truth([_inferred_cve_finding()], "10.0.0.5")
    assert "Contexto de explotación (one-day)" in out
    assert "Path traversal → RCE." in out
    # The base ground-truth block is still there — the context is appended, not replacing.
    assert "Evidencia confirmada del motor" in out


def test_profile_intent_no_privesc_for_4b(monkeypatch):
    monkeypatch.delenv("KRYON_CAPABLE_MODEL", raising=False)
    f = MagicMock(rule_id="http-server-token", cwe="cwe-200", message="")
    _profile, intent = O._profile_intent(["nginx"], [f])
    assert "privesc" not in intent


def test_profile_intent_adds_privesc_for_capable(monkeypatch):
    # T3-A9: a capable model must have the privesc playbook available (the stateless
    # matcher never rotated to it after foothold).
    monkeypatch.setenv("KRYON_CAPABLE_MODEL", "true")
    f = MagicMock(rule_id="http-server-token", cwe="cwe-200", message="")
    _profile, intent = O._profile_intent(["nginx"], [f])
    assert "privesc" in intent
    assert "privilege escalation" in intent


def test_stage_battery_runs_web_enum_for_http_services():
    # T3-A5: the orchestrator battery must run ffuf dir-enum on HTTP services.
    svc = MagicMock(port=80, service="http")
    web_enum_calls = []

    def fake_det(url, **kw):
        return [{"det": url}]

    def fake_web_enum(url):
        web_enum_calls.append(url)
        return [{"webenum": url}]

    out = O._stage_battery(
        "10.0.0.5",
        [svc],
        max_services=5,
        console=MagicMock(),
        run_deterministic_phase=fake_det,
        ssh_user="",
        ssh_password="",
        ssh_key="",
        db_user="",
        db_password="",
        include_dns=False,
        include_smb=False,
        run_web_enum_phase=fake_web_enum,
    )
    assert web_enum_calls, "web-enum did not run for the HTTP service"
    assert any(isinstance(f, dict) and "webenum" in f for f in out)


def test_stage_battery_skips_web_enum_when_not_injected():
    svc = MagicMock(port=80, service="http")
    out = O._stage_battery(
        "10.0.0.5",
        [svc],
        max_services=5,
        console=MagicMock(),
        run_deterministic_phase=lambda url, **kw: [{"det": url}],
        ssh_user="",
        ssh_password="",
        ssh_key="",
        db_user="",
        db_password="",
        include_dns=False,
        include_smb=False,
        run_web_enum_phase=None,
    )
    assert not any(isinstance(f, dict) and "webenum" in f for f in out)
