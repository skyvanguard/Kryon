"""Declarative CIS-style compliance framework loader (F33).

Public API:

    from kryon.compliance.cis import load_framework, register_framework
    register_framework("src/kryon/compliance/cis/frameworks/cis-ubuntu-22.04-l1.yaml")

The YAML schema is documented in :mod:`~kryon.compliance.cis.schema`.
"""

from pathlib import Path

from kryon.compliance.cis.importer import (
    FrameworkSchemaError,
    _CISCheck,
    build_check,
    load_framework,
    register_framework,
)
from kryon.compliance.cis.schema import (
    CheckSpec,
    Framework,
    FrameworkMetadata,
    PassWhen,
    Severity,
)

_FRAMEWORKS_DIR = Path(__file__).resolve().parent / "frameworks"


def register_all_frameworks(
    include_samples: bool = False,
) -> dict[str, list[_CISCheck]]:
    """Register every framework YAML under ``cis/frameworks/``.

    Returns a dict keyed by framework id with the list of registered
    checks. Files whose basename starts with ``_`` (e.g. ``_sample.yaml``)
    are skipped unless ``include_samples=True``.
    """
    results: dict[str, list[_CISCheck]] = {}
    for path in sorted(_FRAMEWORKS_DIR.glob("*.yaml")):
        if path.name.startswith("_") and not include_samples:
            continue
        checks = register_framework(path)
        fw_id = path.stem
        results[fw_id] = checks
    return results


def available_frameworks(include_samples: bool = False) -> list[Path]:
    """Return the list of framework YAML paths shipped with Kryon."""
    return [p for p in sorted(_FRAMEWORKS_DIR.glob("*.yaml")) if include_samples or not p.name.startswith("_")]


__all__ = [
    "CheckSpec",
    "Framework",
    "FrameworkMetadata",
    "FrameworkSchemaError",
    "PassWhen",
    "Severity",
    "available_frameworks",
    "build_check",
    "load_framework",
    "register_all_frameworks",
    "register_framework",
]
