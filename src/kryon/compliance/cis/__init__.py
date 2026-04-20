"""Declarative CIS-style compliance framework loader (F33).

Public API:

    from kryon.compliance.cis import load_framework, register_framework
    register_framework("src/kryon/compliance/cis/frameworks/cis-ubuntu-22.04-l1.yaml")

The YAML schema is documented in :mod:`~kryon.compliance.cis.schema`.
"""

from kryon.compliance.cis.importer import (
    FrameworkSchemaError,
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

__all__ = [
    "CheckSpec",
    "Framework",
    "FrameworkMetadata",
    "FrameworkSchemaError",
    "PassWhen",
    "Severity",
    "build_check",
    "load_framework",
    "register_framework",
]
