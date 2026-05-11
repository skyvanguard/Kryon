"""
Target profiler — extract a structured profile of the target from either
the conversation history or the raw text of a user message.

v1 is intentionally heuristic. Good enough to cluster similar targets
without needing an LLM call.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

_URL_RE = re.compile(r"(?:https?://)?(?P<host>[a-z0-9._-]+\.[a-z]{2,})(?::(?P<port>\d+))?", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_NMAP_HOST_LINE_RE = re.compile(r"Nmap scan report for\s+(?P<host>\S+)(?:\s+\((?P<ip>[0-9.]+)\))?")
_NMAP_PORT_LINE_RE = re.compile(r"^(?P<port>\d+)/tcp\s+(?P<state>\w+)\s+(?P<service>\S+)(?:\s+(?P<version>.*))?", re.MULTILINE)
_HTTP_TITLE_RE = re.compile(r"http-title:\s*(?P<title>.+)")
_HTTP_SERVER_RE = re.compile(r"http-server-header:\s*(?P<server>[^\n]+)", re.IGNORECASE)

# Simple tech detection from text patterns
_TECH_SIGNALS = {
    "wordpress": ["wp-content", "wp-login", "wordpress"],
    "joomla": ["joomla", "/administrator"],
    "drupal": ["drupal", "drupal.settings"],
    "apache": ["apache"],
    "nginx": ["nginx"],
    "iis": ["microsoft-iis"],
    "php": [" php/", "x-powered-by: php"],
    "laravel": ["laravel", "x-powered-by: laravel"],
    "node": ["x-powered-by: express", "node.js"],
    "openssh": ["openssh"],
}


def _extract_host(text: str) -> str | None:
    """Best-effort extraction of a hostname from arbitrary text."""
    m = _NMAP_HOST_LINE_RE.search(text)
    if m:
        return m.group("host")
    m = _URL_RE.search(text)
    if m:
        return m.group("host")
    m = _IPV4_RE.search(text)
    if m:
        return m.group(0)
    return None


def _extract_resolved_ip(text: str) -> str | None:
    m = _NMAP_HOST_LINE_RE.search(text)
    if m and m.group("ip"):
        return m.group("ip")
    ip = _IPV4_RE.search(text)
    return ip.group(0) if ip else None


def _extract_ports_and_services(text: str) -> tuple[list[int], dict[str, str]]:
    ports: list[int] = []
    services: dict[str, str] = {}
    for m in _NMAP_PORT_LINE_RE.finditer(text):
        state = m.group("state")
        if state and state.lower() != "open":
            continue
        try:
            port = int(m.group("port"))
        except Exception:
            continue
        ports.append(port)
        svc = m.group("service") or ""
        version = (m.group("version") or "").strip()
        services[str(port)] = f"{svc} {version}".strip()
    # de-dup preserve order
    seen = set()
    ports = [p for p in ports if not (p in seen or seen.add(p))]
    return ports, services


def _extract_tech(text: str) -> list[str]:
    lower = text.lower()
    found: list[str] = []
    for tech, signals in _TECH_SIGNALS.items():
        if any(sig in lower for sig in signals):
            found.append(tech)
    # Also look at http-title values for a hint at the stack
    for m in _HTTP_TITLE_RE.finditer(text):
        title = m.group("title").lower()
        if "wordpress" in title:
            found.append("wordpress")
        if "joomla" in title:
            found.append("joomla")
    return sorted(set(found))


def _guess_os(text: str) -> str | None:
    lower = text.lower()
    if any(sig in lower for sig in ("linux", "ubuntu", "debian", "centos", "apache/2", "openssh")):
        return "linux"
    if any(sig in lower for sig in ("windows", "microsoft-iis", "win32", "smb signing")):
        return "windows"
    return None


def _collect_text(sources: Iterable[Any]) -> str:
    """Flatten an iterable of strings / dicts / messages into plain text."""
    chunks: list[str] = []
    for src in sources:
        if not src:
            continue
        if isinstance(src, str):
            chunks.append(src)
        elif isinstance(src, dict):
            # Common shapes: {"role": ..., "content": ...} or tool outputs
            content = src.get("content")
            if isinstance(content, str):
                chunks.append(content)
            elif isinstance(content, list):
                for c in content:
                    if isinstance(c, dict) and c.get("text"):
                        chunks.append(c["text"])
                    elif isinstance(c, str):
                        chunks.append(c)
            if src.get("output"):
                chunks.append(str(src["output"]))
        else:
            chunks.append(str(src))
    return "\n".join(chunks)


def build_profile(
    *,
    user_message: str | None = None,
    history: list[Any] | None = None,
    tool_outputs: list[str] | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    """Build a target profile from whatever signals the caller has.

    Any of the inputs can be None. The function scans everything it was
    given and returns a best-effort profile dict with the fields defined
    in `docs/LEARNING_LOOP.md`.
    """
    buckets: list[Any] = []
    if user_message:
        buckets.append(user_message)
    if history:
        buckets.extend(history)
    if tool_outputs:
        buckets.extend(tool_outputs)

    text = _collect_text(buckets)

    host = _extract_host(text)
    resolved_ip = _extract_resolved_ip(text)
    ports, services = _extract_ports_and_services(text)
    tech = _extract_tech(text)
    os_hint = _guess_os(text)

    profile: dict[str, Any] = {
        "host": host,
        "resolved_ip": resolved_ip,
        "ports": ports,
        "services": services,
        "tech": tech,
        "os_hint": os_hint,
    }
    if notes:
        profile["notes"] = notes
    return profile
