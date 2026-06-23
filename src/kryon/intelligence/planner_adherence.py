"""Planner-adherence telemetry — measures whether the model actually FOLLOWS the
deterministic ``NextActionRecommendation`` the chain-planner injects, or ignores it.

Motivation: the reflective runner injects an OPERATOR DIRECTIVE (often at confidence
0.92) and then *hopes* the model issues the recommended tool. Empirically it ignores
the directive a large fraction of the time (Pyrat/THM benches), but that fraction was
never measured — so it couldn't be driven down. This module turns "the model ignores
the scaffolding ~X%" from a vibe into a tracked metric.

Design: pure + side-effect-light. ``record_injection`` notes that a high-confidence
recommendation was injected at turn N; ``record_action`` notes the model's actual next
tool call; ``adheres`` decides whether they match. The reflective runner calls these at
its existing injection + tool-loop points. Emission to JSONL is gated behind
``KRYON_PLANNER_TELEMETRY`` (off by default — zero overhead in banking runs).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kryon.util.env import env_bool


def telemetry_enabled() -> bool:
    """Adherence telemetry is opt-in (banking runs leave it off)."""
    return env_bool("KRYON_PLANNER_TELEMETRY")


def _log_path() -> Path:
    raw = os.environ.get("KRYON_PLANNER_TELEMETRY_PATH")
    if raw:
        return Path(raw)
    return Path.home() / ".kryon" / "planner_adherence.jsonl"


# Canonicalise a tool name so "run_command" vs "run_command_async" vs
# "execute_planner_directive(run_command ...)" compare equal.
def _canon_tool(name: str) -> str:
    n = (name or "").strip().lower()
    n = n.removesuffix("_async")
    # The directive executor IS the recommended tool when the model delegates to it.
    if n == "execute_planner_directive":
        return "execute_planner_directive"
    return n


def adheres(recommended_tool: str, actual_tool: str) -> bool:
    """True when the model's actual next tool call matches the recommendation —
    either by issuing the same tool, or by delegating to execute_planner_directive
    (which runs the recommendation verbatim)."""
    a = _canon_tool(actual_tool)
    if a == "execute_planner_directive":
        return True
    return a == _canon_tool(recommended_tool)


@dataclass
class AdherenceTracker:
    """Per-run accumulator. The reflective runner holds one of these and feeds it the
    injected recommendation each chunk + the model's actual next tool call."""

    total_injected: int = 0
    total_followed: int = 0
    _pending_tool: str | None = None
    _pending_conf: float = 0.0
    _pending_turn: int = 0
    records: list[dict[str, Any]] = field(default_factory=list)

    def record_injection(self, *, turn: int, tool: str, confidence: float) -> None:
        """A recommendation was injected this chunk. Resolves the PREVIOUS pending
        injection as 'not followed' if the model never acted on it before the next
        recommendation landed."""
        if self._pending_tool is not None:
            self._resolve(actual_tool="(none)")
        self._pending_tool = tool
        self._pending_conf = confidence
        self._pending_turn = turn
        self.total_injected += 1

    def record_action(self, *, tool: str) -> None:
        """The model's actual next tool call. Resolves the pending injection."""
        if self._pending_tool is None:
            return
        self._resolve(actual_tool=tool)

    def _resolve(self, *, actual_tool: str) -> None:
        followed = adheres(self._pending_tool or "", actual_tool)
        if followed:
            self.total_followed += 1
        self.records.append(
            {
                "turn": self._pending_turn,
                "recommended": self._pending_tool,
                "confidence": round(self._pending_conf, 3),
                "actual": actual_tool,
                "followed": followed,
            }
        )
        self._pending_tool = None

    def adherence_rate(self) -> float:
        return (self.total_followed / self.total_injected) if self.total_injected else 0.0

    def flush(self, *, run_id: str = "", target: str = "") -> None:
        """Append this run's records to the JSONL log (best-effort, gated)."""
        # Resolve any still-pending injection as unfollowed.
        if self._pending_tool is not None:
            self._resolve(actual_tool="(none)")
        if not telemetry_enabled() or not self.records:
            return
        path = _log_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                for rec in self.records:
                    fh.write(json.dumps({"run_id": run_id, "target": target, **rec}, ensure_ascii=False) + "\n")
        except OSError:
            pass  # telemetry must never break a run
