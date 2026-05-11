"""F84 — OT/ICS protocol audit tools.

Industry protocol family. Each module is one protocol:
  modbus_scan    — Modbus/TCP (port 502)         — IEC 62443 baseline
  dnp3_probe     — DNP3 over TCP/UDP 20000       — Sprint 2
  s7_enum        — Siemens S7Comm                 — Sprint 3
  iec104_probe   — IEC 60870-5-104 (power grid)   — Sprint 4
  mqtt_industrial_audit — SCADA broker checks    — Sprint 5

Stdlib-only by design: socket, struct, hashlib. Adding pymodbus / pydnp3
later is fine but the baseline must run inside an air-gapped banking
container without `pip install` reaching the internet.

Callers should import from the submodule explicitly
(`from kryon.tools.ot.modbus_scan import modbus_scan`) so the package
namespace doesn't shadow the submodule with a same-named function — that
broke `import kryon.tools.ot.modbus_scan as src` in test fixtures.
"""
