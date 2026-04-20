"""CWE → regulatory framework mapping loader (F59).

Reads ``cwe_to_framework.yaml`` (shipped alongside) and exposes a tiny
lookup API for probes and report generators.

Example:

    from kryon.compliance.cwe_mapping import frameworks_for_cwe
    tags = frameworks_for_cwe("CWE-89")
    # → FrameworkTags(
    #       title="SQL Injection", severity="CRITICAL",
    #       pci_dss=["6.2.4", "6.5.1"], swift=["2.7", "6.2"],
    #       bcp_py=["VII"], owasp="A03:2021")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

_MAPPING_PATH = Path(__file__).resolve().parent / "cwe_to_framework.yaml"


@dataclass(frozen=True)
class FrameworkTags:
    """Regulatory citations for a single CWE."""

    cwe_id: str
    title: str
    severity: str
    pci_dss: tuple[str, ...] = ()
    swift: tuple[str, ...] = ()
    bcp_py: tuple[str, ...] = ()
    owasp: str = ""

    def to_dict(self) -> dict:
        return {
            "cwe_id": self.cwe_id,
            "title": self.title,
            "severity": self.severity,
            "pci_dss": list(self.pci_dss),
            "swift": list(self.swift),
            "bcp_py": list(self.bcp_py),
            "owasp": self.owasp,
        }

    def citations(self) -> list[str]:
        """Flatten into a single ordered list of human-readable cites."""
        out: list[str] = []
        for c in self.pci_dss:
            out.append(f"PCI-DSS {c}")
        for c in self.swift:
            out.append(f"SWIFT CSCF {c}")
        for c in self.bcp_py:
            out.append(f"BCP Res. 12/2021 Sección {c}")
        if self.owasp:
            out.append(f"OWASP {self.owasp}")
        return out


class CWEMappingError(RuntimeError):
    """Raised when the YAML file is malformed."""


@lru_cache(maxsize=1)
def _load_mapping() -> dict[str, FrameworkTags]:
    try:
        import yaml  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover
        raise CWEMappingError("PyYAML required for cwe_mapping") from exc

    if not _MAPPING_PATH.is_file():
        raise CWEMappingError(f"mapping file not found: {_MAPPING_PATH}")

    with _MAPPING_PATH.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    if not isinstance(raw, dict):
        raise CWEMappingError("top-level YAML must be a mapping")

    out: dict[str, FrameworkTags] = {}
    for cwe_id, entry in raw.items():
        if not isinstance(entry, dict):
            raise CWEMappingError(f"{cwe_id}: entry must be a mapping")
        out[cwe_id] = FrameworkTags(
            cwe_id=cwe_id,
            title=str(entry.get("title", "")),
            severity=str(entry.get("severity", "MEDIUM")).upper(),
            pci_dss=tuple(str(x) for x in entry.get("pci_dss", []) or []),
            swift=tuple(str(x) for x in entry.get("swift", []) or []),
            bcp_py=tuple(str(x) for x in entry.get("bcp_py", []) or []),
            owasp=str(entry.get("owasp", "")),
        )
    return out


def frameworks_for_cwe(cwe_id: str) -> Optional[FrameworkTags]:
    """Return the regulatory tags for ``cwe_id`` (e.g. "CWE-89"), or
    ``None`` if the CWE is not mapped."""
    return _load_mapping().get(cwe_id.upper())


def all_mapped_cwes() -> list[str]:
    """Return the list of CWE ids with a mapping entry."""
    return sorted(_load_mapping().keys())


def mapping_size() -> int:
    return len(_load_mapping())
