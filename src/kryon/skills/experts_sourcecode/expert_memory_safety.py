"""MemorySafetyExpert — CWE-787 / 121 / 122 / 125 / 416.

Heap-buffer-overflow, stack-buffer-overflow, out-of-bounds read,
use-after-free. The bread-and-butter of a zero-day hunt on C/C++
codebases: most ASAN-catchable crashes land in this family.

All the work is in the base class — this expert just declares the
family. The YAML library (`patterns/cwe/cwe-787.yaml`, etc.) already
ships the detection regexes and PoC skeletons.
"""

from __future__ import annotations

from kryon.skills.experts_sourcecode.base import SourceExpert


class MemorySafetyExpert(SourceExpert):
    expert_id = "memory_safety"
    cwe_family = ("CWE-787", "CWE-121", "CWE-122", "CWE-125", "CWE-416")
    # Memory-safety is the highest-signal family, give it a bigger cap.
    max_budget = 60
    confidence_floor = "medium"


__all__ = ["MemorySafetyExpert"]
