"""Batch P — ICS/SCADA/OT probes. The wired tools.ot functions are mocked with
fake result objects; the new protocol probes (EtherNet/IP, OPC-UA, ATG, Fox)
mock _tcp. Graceful behavior + read-only signature precision checked."""

from __future__ import annotations

from dataclasses import dataclass, field

import kryon.cli.ot_probes as ot
from kryon.cli.engage import DiscoveredService
from kryon.cli.ot_probes import _OT_PROBES, run_ot_probes

_DEAD = "127.0.0.1"


def _svc(port: int) -> DiscoveredService:
    return DiscoveredService(host=_DEAD, port=port, state="open", service="")


@dataclass
class _FakeResult:
    reachable: bool = True
    exposure: bool = True
    device_identification: dict = field(default_factory=dict)
    plc_firmware_version: str = ""
    module_identification: dict = field(default_factory=dict)

    @property
    def has_unauth_exposure(self) -> bool:
        return self.exposure


def test_run_ot_probes_graceful_on_dead_ports():
    for port in (502, 102, 2404, 20000, 44818, 4840, 10001, 1911):
        assert isinstance(run_ot_probes(_svc(port)), list)


def test_dispatch_well_formed():
    assert len(_OT_PROBES) == 8
    for matches, probe in _OT_PROBES:
        assert callable(matches) and callable(probe)


def test_modbus_unauth(monkeypatch):
    monkeypatch.setattr("kryon.tools.ot.modbus_scan.modbus_scan",
                        lambda host, port=502, **k: _FakeResult(device_identification={"VendorName": "Schneider"}))
    f = ot._check_modbus(_svc(502))
    assert f is not None and f.rule_id == "modbus-unauth" and "Schneider" in f.evidence


def test_modbus_not_exposed_returns_none(monkeypatch):
    monkeypatch.setattr("kryon.tools.ot.modbus_scan.modbus_scan",
                        lambda host, port=502, **k: _FakeResult(exposure=False))
    assert ot._check_modbus(_svc(502)) is None


def test_s7comm_unauth(monkeypatch):
    monkeypatch.setattr("kryon.tools.ot.s7_enum.s7_enum",
                        lambda host, port=102, **k: _FakeResult(plc_firmware_version="V4.2"))
    assert ot._check_s7comm(_svc(102)).rule_id == "s7comm-unauth"


def test_iec104_unauth(monkeypatch):
    monkeypatch.setattr("kryon.tools.ot.iec104_probe.iec104_probe",
                        lambda host, port=2404, **k: _FakeResult())
    assert ot._check_iec104(_svc(2404)).rule_id == "iec104-unauth"


def test_dnp3_unauth(monkeypatch):
    monkeypatch.setattr("kryon.tools.ot.dnp3_probe.dnp3_probe",
                        lambda host, port=20000, **k: _FakeResult())
    assert ot._check_dnp3(_svc(20000)).rule_id == "dnp3-unauth"


def test_enip_list_identity(monkeypatch):
    monkeypatch.setattr(ot, "_tcp", lambda *a, **k: b"\x63\x00\x20\x00" + b"\x00" * 30)
    f = ot._check_enip(_svc(44818))
    assert f is not None and f.rule_id == "enip-exposed"


def test_enip_no_reply_returns_none(monkeypatch):
    monkeypatch.setattr(ot, "_tcp", lambda *a, **k: None)
    assert ot._check_enip(_svc(44818)) is None


def test_opcua_hello_ack(monkeypatch):
    monkeypatch.setattr(ot, "_tcp", lambda *a, **k: b"ACKF\x1c\x00\x00\x00" + b"\x00" * 20)
    assert ot._check_opcua(_svc(4840)).rule_id == "opcua-exposed"


def test_atg_inventory(monkeypatch):
    monkeypatch.setattr(ot, "_tcp", lambda *a, **k: b"\x01I20100\r\nIN-TANK INVENTORY\r\nT 1:UNLEADED\x03")
    assert ot._check_atg(_svc(10001)).rule_id == "atg-exposed"


def test_niagara_fox(monkeypatch):
    monkeypatch.setattr(ot, "_tcp", lambda *a, **k: b"fox a:1 -1 fox hello\n{\nfox.version=s:1.0.1\nstation.name=s:JACE\n};;\n")
    assert ot._check_niagara_fox(_svc(1911)).rule_id == "niagara-fox-exposed"


def test_no_false_positive_on_garbage(monkeypatch):
    monkeypatch.setattr(ot, "_tcp", lambda *a, **k: b"\xde\xad\xbe\xef garbage")
    for port in (44818, 4840, 10001, 1911):
        assert run_ot_probes(_svc(port)) == []
