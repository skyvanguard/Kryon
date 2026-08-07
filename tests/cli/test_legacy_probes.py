"""Batch H — legacy/IoT probes (X11, IPMI, TFTP, CUPS, BACnet, finger).

Protocol responses are mocked (no live X server / BMC / TFTP); graceful-on-
unreachable and signature precision are checked directly.
"""

from __future__ import annotations

import kryon.cli.legacy_probes as lp
from kryon.cli.engage import DiscoveredService
from kryon.cli.legacy_probes import _LEGACY_PROBES, run_legacy_probes

_DEAD = "127.0.0.1"


def _svc(port: int) -> DiscoveredService:
    return DiscoveredService(host=_DEAD, port=port, state="open", service="")


def test_run_legacy_probes_graceful_on_dead_ports():
    for port in (6000, 623, 69, 631, 47808, 79):
        assert isinstance(run_legacy_probes(_svc(port)), list)


def test_dispatch_table_well_formed():
    assert len(_LEGACY_PROBES) == 10
    for matches, probe in _LEGACY_PROBES:
        assert callable(matches) and callable(probe)


def test_rservices_detected_when_port_open(monkeypatch):
    import contextlib

    @contextlib.contextmanager
    def _fake_conn(*_a, **_k):
        yield object()  # a successful connect

    monkeypatch.setattr(lp.socket, "create_connection", _fake_conn)
    for port, name in ((512, "rexec"), (513, "rlogin"), (514, "rsh")):
        f = lp._check_rservices(_svc(port))
        assert f is not None
        assert f.rule_id == f"rservice-{name}-exposed"
        assert f.severity == "HIGH" and f.cwe == "CWE-319"


def test_rservices_none_when_unreachable(monkeypatch):
    def _refused(*_a, **_k):
        raise OSError("refused")

    monkeypatch.setattr(lp.socket, "create_connection", _refused)
    assert lp._check_rservices(_svc(514)) is None


def test_x11_open_detected(monkeypatch):
    monkeypatch.setattr(lp, "_tcp", lambda *a, **k: b"\x01\x00rest-of-setup")
    f = lp._check_x11(_svc(6000))
    assert f is not None and f.rule_id == "x11-open" and f.severity == "HIGH"


def test_x11_authenticated_returns_none(monkeypatch):
    monkeypatch.setattr(lp, "_tcp", lambda *a, **k: b"\x00\x12refused")  # 0x00 = Failed
    assert lp._check_x11(_svc(6000)) is None
    monkeypatch.setattr(lp, "_tcp", lambda *a, **k: None)
    assert lp._check_x11(_svc(6000)) is None


def test_ipmi_exposed_detected(monkeypatch):
    # RMCP reply: version 0x06, class 0x07 (IPMI) at offset 3.
    monkeypatch.setattr(lp, "_udp", lambda *a, **k: b"\x06\x00\xff\x07" + b"\x00" * 16)
    f = lp._check_ipmi(_svc(623))
    assert f is not None and f.rule_id == "ipmi-exposed"


def test_ipmi_no_response_returns_none(monkeypatch):
    monkeypatch.setattr(lp, "_udp", lambda *a, **k: None)
    assert lp._check_ipmi(_svc(623)) is None


def test_tftp_open_detected(monkeypatch):
    monkeypatch.setattr(lp, "_udp", lambda *a, **k: b"\x00\x05\x00\x01File not found\x00")  # ERROR
    assert lp._check_tftp(_svc(69)).rule_id == "tftp-open"


def test_tftp_no_response_returns_none(monkeypatch):
    monkeypatch.setattr(lp, "_udp", lambda *a, **k: None)
    assert lp._check_tftp(_svc(69)) is None


def test_cups_exposed_detected(monkeypatch):
    monkeypatch.setattr(lp, "_http_get", lambda *a, **k: (200, "<html><title>CUPS 2.4.1</title></html>"))
    assert lp._check_cups(_svc(631)).rule_id == "cups-exposed"


def test_cups_other_server_returns_none(monkeypatch):
    monkeypatch.setattr(lp, "_http_get", lambda *a, **k: (200, "<html>nginx welcome</html>"))
    assert lp._check_cups(_svc(631)) is None


def test_bacnet_exposed_detected(monkeypatch):
    monkeypatch.setattr(lp, "_udp", lambda *a, **k: b"\x81\x0b\x00\x0c\x01\x00")  # BVLC reply
    assert lp._check_bacnet(_svc(47808)).rule_id == "bacnet-exposed"


def test_finger_leak_detected(monkeypatch):
    monkeypatch.setattr(lp, "_tcp", lambda *a, **k: b"Login: root  Name: root\nDirectory: /root  Shell: /bin/bash\n")
    assert lp._check_finger(_svc(79)).rule_id == "finger-exposed"


def test_finger_no_user_info_returns_none(monkeypatch):
    monkeypatch.setattr(lp, "_tcp", lambda *a, **k: b"connection closed")
    assert lp._check_finger(_svc(79)) is None


# ---------------------------------------------------------------------------
# Batch T — TR-069 / SIP / echo
# ---------------------------------------------------------------------------


def test_tr069_rompager(monkeypatch):
    monkeypatch.setattr(lp, "_tcp", lambda *a, **k: b"HTTP/1.1 401 Unauthorized\r\nServer: RomPager/4.07\r\n\r\n")
    assert lp._check_tr069(_svc(7547)).rule_id == "tr069-cwmp-exposed"


def test_tr069_plain_http_none(monkeypatch):
    monkeypatch.setattr(lp, "_tcp", lambda *a, **k: b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")
    assert lp._check_tr069(_svc(7547)) is None


def test_sip_options(monkeypatch):
    monkeypatch.setattr(lp, "_udp", lambda *a, **k: b"SIP/2.0 200 OK\r\nUser-Agent: Asterisk PBX 18.0\r\n\r\n")
    f = lp._check_sip(_svc(5060))
    assert f is not None and f.rule_id == "sip-exposed" and "Asterisk" in f.evidence


def test_echo_reflects(monkeypatch):
    monkeypatch.setattr(lp, "_tcp", lambda *a, **k: b"kryon-echo-probe")
    assert lp._check_echo(_svc(7)).rule_id == "echo-service-open"


def test_echo_no_reflection_none(monkeypatch):
    monkeypatch.setattr(lp, "_tcp", lambda *a, **k: b"different response")
    assert lp._check_echo(_svc(7)) is None
