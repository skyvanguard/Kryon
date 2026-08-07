"""Wazuh forwarder — local JSON file-drop.

The integration path that fits Kryon's deployment (appliance running
unattended via cron inside the client datacenter) is NOT the Wazuh
manager API but a local append-only JSON log that the Wazuh agent —
already installed on the host, Kryon even audits for it — tails via:

    <localfile>
      <log_format>json</log_format>
      <location>/var/ossec/logs/kryon/findings.json</location>
    </localfile>

Rationale over the manager API:
  - Kryon already writes append-only JSONL per engagement (action_log,
    partial_findings) — the pattern is proven and offline-robust.
  - No manager credentials, no extra network egress to open.
  - Survives network cuts: the agent forwards on reconnect.

``endpoint`` (from SIEMConfig) is interpreted as the local file path.
One JSON object per line. ``format_event`` flattens ``metadata`` to the
top level so Wazuh decoders see ``cwe``/``mitre``/``host``/``delta``
without nesting. Severity filtering reuses ``should_forward``.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from kryon.integrations.models import SIEMEvent
from kryon.integrations.siem.base import BaseSIEMForwarder

logger = logging.getLogger(__name__)

_DEFAULT_PATH = "/var/ossec/logs/kryon/findings.json"


class WazuhFileForwarder(BaseSIEMForwarder):
    """Append normalized events as JSON lines to a local file the Wazuh
    agent tails. Best-effort: a write failure logs and returns False
    rather than raising (the engagement must never break on telemetry)."""

    def _path(self) -> str:
        return self.endpoint or _DEFAULT_PATH

    def format_event(self, event: SIEMEvent) -> dict:
        """Flatten metadata to top-level for Wazuh decoders."""
        base = event.model_dump()
        meta = base.pop("metadata", {}) or {}
        # metadata keys win only when not already a core field.
        for k, v in meta.items():
            base.setdefault(k, v)
        return base

    def _append(self, event: SIEMEvent) -> bool:
        path = self._path()
        try:
            parent = os.path.dirname(path)
            if parent:
                Path(parent).mkdir(parents=True, exist_ok=True)
            line = json.dumps(self.format_event(event), ensure_ascii=False, default=str)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            return True
        except OSError as exc:
            logger.warning("Wazuh file-drop write failed (%s): %s", path, exc)
            return False

    async def send_event(self, event: SIEMEvent) -> bool:
        return self._append(event)

    async def send_batch(self, events: list[SIEMEvent]) -> int:
        return sum(1 for e in events if self._append(e))
