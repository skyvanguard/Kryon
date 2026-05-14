"""F115.B — interactsh-client subprocess wrapper.

Runs `interactsh-client` in BATCH mode:

  1. start session  → spawn `interactsh-client -json`
  2. capture the assigned callback domain (first stdout output)
  3. operator (or another module) sends probes that target the
     callback domain
  4. wait `collect_seconds` for interactions to accumulate
  5. read all collected JSON events from stdout
  6. terminate the subprocess + return InteractshResult

**Banca-safety**:

  * Default `server_url=""` → REJECTED unless `allow_public_server=True`
    is set. Public oast.* servers transmit callback data to
    ProjectDiscovery; banks should NEVER do this.
  * Reasonable timeouts; subprocess always killed on exit.
  * No retries.
  * Soft-fail if binary not on PATH.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field

__all__ = [
    "Interaction",
    "InteractshConfig",
    "InteractshResult",
    "is_interactsh_available",
    "run_interactsh_batch",
]


# Domains hosted by ProjectDiscovery — refused unless allow_public_server=True
_PUBLIC_OAST_HOSTS: frozenset[str] = frozenset(
    {
        "oast.live",
        "oast.online",
        "oast.pro",
        "oast.fun",
        "oast.me",
        "oast.site",
        "oast.us",
        "interactsh.com",
    }
)


@dataclass(frozen=True)
class InteractshConfig:
    """Banca-safe session profile."""

    interactsh_binary: str = "interactsh-client"
    # Required unless allow_public_server=True. Format:
    # "https://my-interactsh.example.lab"
    server_url: str = ""
    # Explicit opt-in to using ProjectDiscovery's public oast.* servers.
    # Banca: leave this False. Operator must self-host for confidential
    # engagements.
    allow_public_server: bool = False
    # Time to wait for interactions to accumulate AFTER the operator
    # finishes their probe round.
    collect_seconds: int = 30
    # Time to wait for the assigned domain to appear in stdout after
    # spawning the subprocess.
    startup_timeout_seconds: float = 10.0
    # Max bytes of stdout we'll buffer (DoS guard).
    max_stdout_bytes: int = 5_000_000
    # Authentication token (for self-hosted with auth).
    auth_token: str = ""
    extra_args: tuple[str, ...] = ()


@dataclass(frozen=True)
class Interaction:
    """One observed callback."""

    unique_id: str  # the subdomain segment from the hit
    protocol: str  # "http" / "dns" / "smtp" / "ldap"
    remote_address: str  # source IP of the callback
    timestamp: str
    raw_event: str  # full JSON line


@dataclass(frozen=True)
class InteractshResult:
    callback_domain: str = ""  # the registered domain (no protocol prefix)
    interactions: tuple[Interaction, ...] = field(default_factory=tuple)
    binary_missing: bool = False
    public_server_blocked: bool = False
    server_url_used: str = ""
    error: str = ""
    elapsed_seconds: float = 0.0
    exit_code: int = 0
    stderr_excerpt: str = ""


_DOMAIN_RE = re.compile(r"\[([a-z0-9-]+\.[a-z0-9.-]+)\]", re.IGNORECASE)


def is_interactsh_available(binary: str = "interactsh-client") -> bool:
    return shutil.which(binary) is not None


def _server_is_public(server_url: str) -> bool:
    """True if the server_url points at one of ProjectDiscovery's
    public oast servers."""
    if not server_url:
        return True  # empty server_url → defaults to public
    low = server_url.strip().lower()
    for host in _PUBLIC_OAST_HOSTS:
        if host in low:
            return True
    return False


def _extract_domain_from_line(line: str) -> str:
    """Pull the assigned callback domain from interactsh-client's
    startup output. The CLI prints something like:

        [INF] Listing 1 payload for OOB Testing
        [INF] abcd1234.oast.live

    We match the first thing that LOOKS like a fully-qualified
    domain (`.` present, no scheme). interactsh-client also prints
    the domain inside brackets in some flag combinations."""
    line = line.strip()
    if not line:
        return ""
    # Strip ANSI escapes
    line = re.sub(r"\x1b\[[0-9;]*m", "", line)
    # First try the bracketed format
    m = _DOMAIN_RE.search(line)
    if m:
        return m.group(1)
    # Lines like "[INF] abcd1234.oast.live" — split + check for a
    # bare token with a dot
    for token in line.split():
        if "." in token and "/" not in token and ":" not in token:
            if token.replace(".", "").replace("-", "").isalnum():
                return token
    return ""


def _parse_interaction_line(line: str) -> Interaction | None:
    """Parse one interactsh JSON event line."""
    line = line.strip()
    if not line:
        return None
    try:
        evt = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(evt, dict):
        return None
    # Different interactsh-client versions use slightly different keys
    unique_id = evt.get("unique-id") or evt.get("unique_id") or evt.get("full-id") or evt.get("uniqueID") or ""
    return Interaction(
        unique_id=str(unique_id),
        protocol=str(evt.get("protocol") or evt.get("kind") or "").lower(),
        remote_address=str(evt.get("remote-address") or evt.get("remoteAddress") or evt.get("remote_addr") or ""),
        timestamp=str(evt.get("timestamp") or evt.get("time") or ""),
        raw_event=line,
    )


class _StdoutReader(threading.Thread):
    """Reader thread that drains stdout into a list (capped)."""

    def __init__(self, stream, max_bytes: int) -> None:
        super().__init__(daemon=True)
        self.stream = stream
        self.max_bytes = max_bytes
        self.lines: list[str] = []
        self.bytes_read = 0
        self.stop_event = threading.Event()

    def run(self) -> None:
        try:
            for raw_line in self.stream:
                if self.stop_event.is_set():
                    break
                if isinstance(raw_line, bytes):
                    line = raw_line.decode("utf-8", errors="replace")
                else:
                    line = raw_line
                self.bytes_read += len(line)
                if self.bytes_read > self.max_bytes:
                    break
                self.lines.append(line)
        except (OSError, ValueError):
            # Stream closed mid-read; that's fine
            pass


def run_interactsh_batch(
    config: InteractshConfig,
    pre_collect_callback=None,
) -> InteractshResult:
    """Spawn interactsh-client, capture the assigned domain, call
    `pre_collect_callback(domain)` (so the caller can fire probes),
    wait `collect_seconds`, return all observed interactions.

    `pre_collect_callback` is a callable `(domain: str) -> None` —
    typically the operator's probe-firing logic. If None, the
    function just waits + collects (useful when probes are fired
    externally / manually).

    Always cleans up the subprocess on exit, even on exception."""
    t0 = time.monotonic()
    # Banca-safety gates
    if not is_interactsh_available(config.interactsh_binary):
        return InteractshResult(binary_missing=True, exit_code=-1)
    if _server_is_public(config.server_url) and not config.allow_public_server:
        return InteractshResult(
            public_server_blocked=True,
            error="server_url points at a PUBLIC oast.* server but allow_public_server=False",
            exit_code=-2,
            elapsed_seconds=time.monotonic() - t0,
        )

    args: list[str] = [config.interactsh_binary, "-json"]
    if config.server_url:
        args.extend(["-server", config.server_url])
    if config.auth_token:
        args.extend(["-token", config.auth_token])
    args.extend(config.extra_args)

    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except (FileNotFoundError, PermissionError) as e:
        return InteractshResult(
            binary_missing=True,
            exit_code=-3,
            error=str(e),
            elapsed_seconds=time.monotonic() - t0,
        )

    reader = _StdoutReader(proc.stdout, config.max_stdout_bytes)
    reader.start()

    try:
        # ---- Phase 1: wait for assigned domain ----
        domain = ""
        deadline = time.monotonic() + config.startup_timeout_seconds
        while time.monotonic() < deadline and not domain:
            # Look through accumulated lines for a domain
            for line in list(reader.lines):
                d = _extract_domain_from_line(line)
                if d:
                    domain = d
                    break
            if domain:
                break
            if proc.poll() is not None:
                # Process died during startup
                break
            time.sleep(0.2)

        if not domain:
            # Couldn't find domain; bail
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
            stderr_data = ""
            try:
                stderr_data = (proc.stderr.read() or "")[-1000:] if proc.stderr else ""
            except Exception:
                pass
            return InteractshResult(
                error="failed to extract callback domain from interactsh-client output",
                exit_code=proc.returncode or -4,
                stderr_excerpt=stderr_data,
                server_url_used=config.server_url,
                elapsed_seconds=time.monotonic() - t0,
            )

        # ---- Phase 2: pre_collect callback (operator fires probes) ----
        if pre_collect_callback is not None:
            try:
                pre_collect_callback(domain)
            except Exception:
                # Operator callback raised; we still want to collect
                # whatever may have arrived
                pass

        # ---- Phase 3: collect ----
        time.sleep(config.collect_seconds)

        # ---- Phase 4: parse interactions from accumulated stdout ----
        interactions: list[Interaction] = []
        # The domain line itself + headers come first, then JSON events.
        for line in list(reader.lines):
            evt = _parse_interaction_line(line)
            if evt is not None:
                interactions.append(evt)

        return InteractshResult(
            callback_domain=domain,
            interactions=tuple(interactions),
            server_url_used=config.server_url,
            exit_code=0,
            elapsed_seconds=time.monotonic() - t0,
        )
    finally:
        reader.stop_event.set()
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
