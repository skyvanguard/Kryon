"""Probe the model actually served behind the ``KRYON_MODEL`` alias.

``KRYON_MODEL`` (e.g. ``kryon-local``) is a stable alias the whole stack routes
on; the llama-server behind it may load any GGUF. This asks the server which
file it loaded (llama.cpp ``/props`` → ``model_path``) and returns its
basename (``jan-nano-128k-Q8_0``).

Cached after the first success — the loaded model only changes on a
llama-server restart. Falls back to the alias when the endpoint exposes no
``/props`` (an external OpenAI-compatible provider such as DeepSeek, where
``KRYON_MODEL`` already IS the real name) or is unreachable. Never raises.
"""

from __future__ import annotations

import os

_cache: dict[str, str | None] = {"name": None}


def real_model_name() -> str:
    """Basename of the served GGUF, or the ``KRYON_MODEL`` alias on fallback."""
    if _cache["name"]:
        return _cache["name"]

    alias = os.getenv("KRYON_MODEL", "default")
    root = os.getenv("OPENAI_BASE_URL", "").rstrip("/")
    if not root:
        return alias
    host = root[:-3] if root.endswith("/v1") else root
    try:
        import json
        import urllib.request

        with urllib.request.urlopen(host.rstrip("/") + "/props", timeout=2) as resp:
            model_path = json.load(resp).get("model_path") or ""
        stem = os.path.basename(model_path)
        if stem.lower().endswith(".gguf"):
            stem = stem[:-5]
        if stem:
            _cache["name"] = stem
            return stem
    except Exception:  # pragma: no cover - network / parse best-effort
        pass
    return alias


def reset_cache() -> None:
    """Force the next call to re-probe (test helper / after a model swap)."""
    _cache["name"] = None
