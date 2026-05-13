"""F113 — Replay Engine. Re-verifies that a previously-reported
UnifiedFinding is still present on the target. Used before delivering
audit reports (cuts false positives) and in CI for regression."""

from kryon.tools.replay.engine import (
    ReplayConfig,
    ReplayEngine,
    ReplayedFinding,
    ReplayResult,
    REPLAY_STATUS_STILL_PRESENT,
    REPLAY_STATUS_DISAPPEARED,
    REPLAY_STATUS_CHANGED,
    REPLAY_STATUS_INCONCLUSIVE,
    run_replay,
)

__all__ = [
    "ReplayConfig",
    "ReplayEngine",
    "ReplayedFinding",
    "ReplayResult",
    "REPLAY_STATUS_STILL_PRESENT",
    "REPLAY_STATUS_DISAPPEARED",
    "REPLAY_STATUS_CHANGED",
    "REPLAY_STATUS_INCONCLUSIVE",
    "run_replay",
]
