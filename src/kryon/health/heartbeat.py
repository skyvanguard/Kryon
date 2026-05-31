"""F142 — Heartbeat + health check.

Writes ``.kryon/heartbeat.json`` periodically so an external watchdog
(or ``kryon doctor``) can detect that the agent isn't crashed silently.
``run_doctor()`` inspects the broader environment: heartbeat freshness,
Ollama reachable, audit/state/checkpoint dirs writable, key envs sane.

Pure stdlib — no requests. Watchdog scripts can ``cron @reboot
kryon doctor --fail-on-stale`` and feed the result into Nagios /
Prometheus / Slack.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class HeartbeatRecord:
    timestamp: str
    pid: int
    hostname: str
    kryon_version: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HealthCheckResult:
    """Outcome of a single health probe."""

    name: str
    ok: bool
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _default_heartbeat_path() -> Path:
    root = os.environ.get("KRYON_HEARTBEAT_PATH", "").strip()
    if root:
        return Path(root)
    return Path(".kryon") / "heartbeat.json"


def write_heartbeat(*, path: Path | None = None, extra: dict | None = None) -> Path | None:
    """Update the heartbeat file. Never raises."""
    p = path or _default_heartbeat_path()
    record = HeartbeatRecord(
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        pid=os.getpid(),
        hostname=socket.gethostname(),
        kryon_version=os.environ.get("KRYON_VERSION", ""),
        extra=dict(extra or {}),
    )
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(record.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return p
    except OSError as exc:
        logger.warning("heartbeat write failed: %s", exc)
        return None


def read_heartbeat(*, path: Path | None = None) -> HeartbeatRecord | None:
    p = path or _default_heartbeat_path()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return HeartbeatRecord(
            timestamp=str(data.get("timestamp", "")),
            pid=int(data.get("pid", 0)),
            hostname=str(data.get("hostname", "")),
            kryon_version=str(data.get("kryon_version", "")),
            extra=dict(data.get("extra", {}) or {}),
        )
    except (json.JSONDecodeError, OSError, ValueError, TypeError):
        return None


def is_stale(record: HeartbeatRecord | None, *, threshold_minutes: int = 10) -> bool:
    """True when the record is missing or older than ``threshold_minutes``."""
    if record is None or not record.timestamp:
        return True
    try:
        ts = record.timestamp.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return True
    age = datetime.now(timezone.utc) - dt
    return age > timedelta(minutes=threshold_minutes)


# ---------------------------------------------------------------------------
# Doctor — broader environment probes
# ---------------------------------------------------------------------------


def _check_dir_writable(path: Path, name: str) -> HealthCheckResult:
    try:
        path.mkdir(parents=True, exist_ok=True)
        test = path / ".kryon-doctor-probe"
        test.write_text("ok", encoding="utf-8")
        test.unlink()
        return HealthCheckResult(name=name, ok=True, detail=str(path))
    except OSError as exc:
        return HealthCheckResult(name=name, ok=False, detail=f"{path}: {exc}")


def _check_heartbeat(threshold_minutes: int) -> HealthCheckResult:
    record = read_heartbeat()
    if record is None:
        return HealthCheckResult(name="heartbeat", ok=False, detail="missing")
    if is_stale(record, threshold_minutes=threshold_minutes):
        return HealthCheckResult(name="heartbeat", ok=False, detail=f"stale (last: {record.timestamp})")
    return HealthCheckResult(name="heartbeat", ok=True, detail=record.timestamp)


def _check_ollama_reachable() -> HealthCheckResult:
    """Probe the *embeddings* endpoint (``KRYON_EMBEDDING_BASE_URL`` →
    Ollama ``/api/tags``). The main LLM moved to llama-server (see
    ``_check_llm_reachable``); Ollama now only serves embeddings.
    Best-effort — degraded reachability shouldn't crash doctor."""
    host = os.environ.get("KRYON_EMBEDDING_BASE_URL", "").strip()
    if not host:
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").strip()
    if not host.startswith("http"):
        host = f"http://{host}"
    url = host.rstrip("/") + "/api/tags"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            ok = 200 <= resp.status < 300
            return HealthCheckResult(name="ollama(embeddings)", ok=ok, detail=f"{url} → {resp.status}")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        return HealthCheckResult(name="ollama(embeddings)", ok=False, detail=f"{url}: {exc}")


def _check_llm_reachable() -> HealthCheckResult:
    """Probe the main LLM endpoint (``OPENAI_BASE_URL`` → ``/v1/models``).
    Works for llama-server, Ollama's ``/v1`` shim and any OpenAI-compatible
    provider. Best-effort — degraded reachability shouldn't crash doctor."""
    base = os.environ.get("OPENAI_BASE_URL", "").strip()
    if not base:
        return HealthCheckResult(name="llm", ok=False, detail="OPENAI_BASE_URL unset")
    if not base.startswith("http"):
        base = f"http://{base}"
    # OPENAI_BASE_URL conventionally ends in /v1 → append /models.
    url = base.rstrip("/") + "/models"
    try:
        req = urllib.request.Request(url, method="GET")
        api_key = os.environ.get("OPENAI_API_KEY", "").strip()
        if api_key:
            req.add_header("Authorization", f"Bearer {api_key}")
        with urllib.request.urlopen(req, timeout=3) as resp:
            ok = 200 <= resp.status < 300
            return HealthCheckResult(name="llm", ok=ok, detail=f"{url} → {resp.status}")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        return HealthCheckResult(name="llm", ok=False, detail=f"{url}: {exc}")


def _check_env(env_var: str, *, expected: str = "") -> HealthCheckResult:
    val = os.environ.get(env_var, "")
    if not val:
        return HealthCheckResult(name=f"env:{env_var}", ok=False, detail="unset")
    if expected and expected.lower() not in val.lower():
        return HealthCheckResult(name=f"env:{env_var}", ok=False, detail=f"set but != '{expected}' (={val[:40]})")
    return HealthCheckResult(name=f"env:{env_var}", ok=True, detail=val[:40])


def run_doctor(
    *,
    heartbeat_threshold_minutes: int = 10,
    check_ollama: bool = True,
) -> list[HealthCheckResult]:
    """Run every diagnostic. Returns ordered list of results. Caller
    decides exit code based on ``ok=False`` count."""
    checks: list[HealthCheckResult] = []

    # Filesystem probes — must work before anything else.
    checks.append(_check_dir_writable(Path(".kryon") / "audit", "dir:audit"))
    checks.append(_check_dir_writable(Path(".kryon") / "state", "dir:state"))
    checks.append(_check_dir_writable(Path(".kryon") / "checkpoints", "dir:checkpoints"))

    # Heartbeat freshness.
    checks.append(_check_heartbeat(heartbeat_threshold_minutes))

    # Env sanity.
    checks.append(_check_env("KRYON_MODEL"))

    # Main LLM (llama-server / OpenAI-compatible) reachability.
    checks.append(_check_llm_reachable())

    # F177 — CVE cache health.
    checks.append(_check_cve_cache())

    # External dependencies (optional).
    if check_ollama:
        checks.append(_check_ollama_reachable())

    return checks


def _check_cve_cache() -> HealthCheckResult:
    """F177 — surface CVE cache state for the operator.

    The cache lives at ``KRYON_CVE_CACHE_PATH`` (default
    ``.kryon/nvd_cache/cves.txt``). When the operator sets
    ``KRYON_CVE_CACHE_REQUIRED=true`` (F151 strict mode), an empty
    cache silently rejects every CVE-shaped finding. This check
    catches that misconfiguration up front.

    Status:
      * ok=True with line count when the file exists and has >100 IDs
      * ok=True with "soft mode" note when cache is empty AND strict
        mode is off (the operator chose not to enforce — that's fine)
      * ok=False when cache is empty AND strict mode is on (the
        operator is about to silently drop every CVE finding)
    """
    cache_path_str = os.environ.get(
        "KRYON_CVE_CACHE_PATH",
        ".kryon/nvd_cache/cves.txt",
    ).strip() or ".kryon/nvd_cache/cves.txt"
    strict = os.environ.get("KRYON_CVE_CACHE_REQUIRED", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    path = Path(cache_path_str)
    if not path.exists():
        detail = f"missing ({cache_path_str}). Run: kryon update-cve-cache --years 2020-2026"
        return HealthCheckResult(name="cve_cache", ok=not strict, detail=detail)

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return HealthCheckResult(name="cve_cache", ok=False, detail=f"read error: {exc}")

    count = 0
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            count += 1

    if count == 0:
        detail = f"empty ({cache_path_str}). Run: kryon update-cve-cache --years 2020-2026"
        return HealthCheckResult(name="cve_cache", ok=not strict, detail=detail)
    if count < 100:
        return HealthCheckResult(
            name="cve_cache",
            ok=True,
            detail=f"{count} entries (sparse — consider --all)",
        )
    return HealthCheckResult(name="cve_cache", ok=True, detail=f"{count} entries")
