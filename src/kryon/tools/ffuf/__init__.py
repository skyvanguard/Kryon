"""F112 — ffuf wrapper. Delegates content-discovery fuzzing to
ffuf, parses its JSON output, exposes hits as UnifiedFinding-
compatible records. When ffuf is absent the module soft-fails."""

from kryon.tools.ffuf.runner import (
    FfufConfig,
    FfufHit,
    FfufResult,
    embedded_wordlist,
    is_ffuf_available,
    run_ffuf,
)

__all__ = [
    "FfufConfig",
    "FfufHit",
    "FfufResult",
    "embedded_wordlist",
    "is_ffuf_available",
    "run_ffuf",
]
