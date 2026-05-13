"""F110 — Nuclei wrapper. Delegates breadth-of-coverage scanning to
ProjectDiscovery's nuclei, parses its JSONL output, normalizes
results to the same UnifiedFinding shape as F97-F109."""

from kryon.tools.nuclei.runner import (
    NuclieConfig,
    NucleiResult,
    NucleiFinding,
    is_nuclei_available,
    run_nuclei,
)

__all__ = [
    "NuclieConfig",
    "NucleiResult",
    "NucleiFinding",
    "is_nuclei_available",
    "run_nuclei",
]
