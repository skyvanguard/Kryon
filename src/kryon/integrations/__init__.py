"""SIEM/SOAR integration framework for forwarding security events."""

from __future__ import annotations

import logging
import os
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kryon.integrations.models import SIEMEvent
    from kryon.integrations.siem.base import BaseSIEMForwarder

logger = logging.getLogger(__name__)

_FORWARDER_REGISTRY: dict[str, type] = {}


def register_forwarder(siem_type: str, cls: type) -> None:
    _FORWARDER_REGISTRY[siem_type] = cls


def get_forwarder_class(siem_type: str) -> type | None:
    return _FORWARDER_REGISTRY.get(siem_type)


# Register built-in forwarders
def _register_builtins() -> None:
    from kryon.integrations.siem.elastic import ElasticSIEMForwarder
    from kryon.integrations.siem.qradar import QRadarLEEFForwarder
    from kryon.integrations.siem.splunk import SplunkHECForwarder
    from kryon.integrations.siem.wazuh import WazuhFileForwarder

    register_forwarder("splunk", SplunkHECForwarder)
    register_forwarder("qradar", QRadarLEEFForwarder)
    register_forwarder("elastic", ElasticSIEMForwarder)
    register_forwarder("wazuh", WazuhFileForwarder)


_register_builtins()


class IntegrationManager:
    """Manages SIEM forwarder instances and dispatches events."""

    def __init__(self):
        self._forwarders: list[BaseSIEMForwarder] = []
        self._loaded = False

    def load_from_store(self) -> None:
        """Load SIEM configs from DB and instantiate forwarders."""
        from kryon.server.deps import get_store

        self._forwarders = []
        try:
            configs = get_store().list_siem_configs()
            for cfg in configs:
                if not cfg.get("enabled", True):
                    continue
                cls = get_forwarder_class(cfg["siem_type"])
                if cls:
                    self._forwarders.append(cls(cfg))
                    logger.info("Loaded SIEM forwarder: %s (%s)", cfg["name"], cfg["siem_type"])
        except Exception:
            logger.debug("Failed to load SIEM configs", exc_info=True)
        self._loaded = True

    def load_from_env(self) -> None:
        """Load ONE SIEM forwarder from env vars — for the unattended
        cron/CLI path, which never boots the FastAPI server (so
        ``load_from_store`` has no DB to read).

        Env contract::

            KRYON_SIEM_TYPE=wazuh|splunk|elastic|qradar
            KRYON_SIEM_ENDPOINT=...   # HEC/ECS URL, or local path (wazuh)
            KRYON_SIEM_TOKEN=...      # HEC/auth token (ignored by wazuh)
            KRYON_SIEM_INDEX=...      # index/sourcetype
            KRYON_SIEM_MIN_SEVERITY=critical|high|medium|low|info

        Idempotent: appends to whatever ``load_from_store`` already
        loaded (the server path and the cron path can coexist). No-op
        when ``KRYON_SIEM_TYPE`` is unset — banca-safe default OFF."""
        siem_type = os.environ.get("KRYON_SIEM_TYPE", "").strip().lower()
        if not siem_type:
            self._loaded = True
            return
        cls = get_forwarder_class(siem_type)
        if cls is None:
            logger.warning("KRYON_SIEM_TYPE=%r has no registered forwarder", siem_type)
            self._loaded = True
            return
        min_sev = os.environ.get("KRYON_SIEM_MIN_SEVERITY", "").strip().lower()
        cfg = {
            "name": f"env:{siem_type}",
            "siem_type": siem_type,
            "endpoint": os.environ.get("KRYON_SIEM_ENDPOINT", "").strip(),
            "token": os.environ.get("KRYON_SIEM_TOKEN", "").strip(),
            "index_name": os.environ.get("KRYON_SIEM_INDEX", "").strip(),
            "config_json": {"min_severity": min_sev} if min_sev else {},
        }
        try:
            self._forwarders.append(cls(cfg))
            logger.info("Loaded SIEM forwarder from env: %s", siem_type)
        except Exception:
            logger.debug("Failed to build env SIEM forwarder", exc_info=True)
        self._loaded = True

    async def forward_event(self, event: SIEMEvent) -> None:
        """Forward an event to all registered SIEM forwarders."""
        if not self._loaded:
            self.load_from_store()

        for forwarder in self._forwarders:
            try:
                if forwarder.should_forward(event):
                    await forwarder.send_event(event)
            except Exception:
                logger.debug("SIEM forward failed for %s", forwarder.name, exc_info=True)

    async def forward_batch(self, events: list[SIEMEvent]) -> None:
        """Forward a batch of events."""
        for forwarder in self._forwarders:
            try:
                batch = [e for e in events if forwarder.should_forward(e)]
                if batch:
                    await forwarder.send_batch(batch)
            except Exception:
                logger.debug("SIEM batch forward failed for %s", forwarder.name, exc_info=True)

    def reload(self) -> None:
        """Reload forwarder configs from DB."""
        self._loaded = False
        self.load_from_store()


# Singleton
_manager: IntegrationManager | None = None
_manager_lock = threading.Lock()


def get_integration_manager() -> IntegrationManager:
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = IntegrationManager()
    return _manager
