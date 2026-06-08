"""F203.U — sqlmap pre_hook bridge for cwe-89-sqli playbook.

The pre_hook spec rejects path traversal (`../`) in declarations, so this
shim sits next to the cwe-89-sqli.md playbook and delegates to the F191
multi-endpoint sqlmap hook via importlib (not regular import — playbooks/
is not a Python package).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

_F191_HOOK_PATH = Path(__file__).resolve().parent.parent / "pre_hooks" / "endpoint_discovery_sqlmap_hook.py"


def run(ctx: dict[str, Any]) -> str:
    """Load + forward to the F191 sqlmap multi-endpoint hook."""
    if not _F191_HOOK_PATH.is_file():
        return "F203.U sqlmap bridge: F191 hook file missing — fallback skipped"

    spec = importlib.util.spec_from_file_location("_f191_sqlmap_hook_loaded_by_f203u", _F191_HOOK_PATH)
    if spec is None or spec.loader is None:
        return "F203.U sqlmap bridge: importlib spec creation failed"

    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fn = getattr(mod, "run", None)
    if fn is None:
        return "F203.U sqlmap bridge: F191 hook has no run() entry point"

    return fn(ctx)
