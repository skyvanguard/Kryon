"""Run Kryon PCI-DSS checks against localhost from inside bench-target.

Bootstraps minimal `kryon` package paths since bench-target doesn't have
Kryon installed as a package. Outputs /tmp/kryon_bench.json.
"""
import importlib.util
import json
import sys
import types
from pathlib import Path

ROOT = Path("/opt/kryon_compliance")


def bootstrap() -> None:
    # Fake kryon.* package hierarchy backed by /opt/kryon_compliance
    for name, path in [
        ("kryon", []),
        ("kryon.compliance", [str(ROOT)]),
        ("kryon.compliance.checks", [str(ROOT / "checks")]),
        ("kryon.compliance.checks.section_2", [str(ROOT / "checks/section_2")]),
        ("kryon.compliance.checks.section_6", [str(ROOT / "checks/section_6")]),
        ("kryon.compliance.checks.section_8", [str(ROOT / "checks/section_8")]),
        ("kryon.compliance.checks.section_10", [str(ROOT / "checks/section_10")]),
    ]:
        mod = types.ModuleType(name)
        mod.__path__ = path
        sys.modules[name] = mod


def load(name: str, path: str) -> None:
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)


def main() -> None:
    bootstrap()
    load("kryon.compliance.checks.base", str(ROOT / "checks/base.py"))
    load("kryon.compliance.runner", str(ROOT / "runner.py"))
    for sec, fname in [
        ("section_2", "c_2_2_2_default_accounts"),
        ("section_2", "c_2_2_7_ssh_hardening"),
        ("section_6", "c_6_3_3_patch_currency"),
        ("section_6", "c_6_4_1_web_headers"),
        ("section_8", "c_8_3_6_password_policy"),
        ("section_10", "c_10_2_1_audit_trails"),
    ]:
        load(f"kryon.compliance.checks.{sec}.{fname}",
             str(ROOT / f"checks/{sec}/{fname}.py"))

    from kryon.compliance.checks.base import CheckContext
    from kryon.compliance.runner import reproducibility_hash, run_all

    ctx = CheckContext(host="localhost")
    results = run_all(ctx)
    payload = [
        {
            "control_id": r.control_id,
            "control_title": r.control_title,
            "section": r.section,
            "verdict": r.verdict,
            "evidence_command": r.evidence_command,
            "evidence_parsed": r.evidence_parsed,
            "evidence_stdout": r.evidence_stdout[:2000],
        }
        for r in results
    ]
    Path("/tmp/kryon_bench.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print("hash:", reproducibility_hash(results))
    for r in results:
        print(f"  [{r.control_id}] {r.verdict}")


if __name__ == "__main__":
    main()
