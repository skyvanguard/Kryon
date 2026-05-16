"""F187 — sqlmap pre_hook helper (Python escape hatch).

The declarative ``tool: run_command`` pre_hook form rejects argument
strings containing ``{...}`` literals because the SSTI-guarded
template substitution treats every brace as a potential
``{ctx.var}`` placeholder. Our sqlmap probe needs a JSON POST body
``{"email":"test","password":"test"}`` which trips the validator.

The Python escape hatch (F80 phase 5) lets us pass the JSON body
verbatim via subprocess.run, no template substitution involved.

The function ``run(ctx)`` returns the sqlmap stdout/stderr as a
str. The F186 output processor (``_summarize_sqlmap``) compresses
the output to the model-facing finding lines.

ctx is the standard pre_hook context dict — we only use ``ctx['target']``.
"""

from __future__ import annotations

import logging
import shlex
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

# F187 — common REST login endpoint path used across vulnerable
# training apps (Juice Shop, DVWA-API, bWAPP). Targets that don't
# expose this path return cleanly with "not injectable" in ~10s.
_LOGIN_PATH = "/rest/user/login"
_JSON_BODY = '{"email":"test","password":"test"}'

# Timeout slightly below the pre_hook ``timeout_s`` to give us a
# graceful exit before the runner kills the process.
_SQLMAP_TIMEOUT_SECONDS = 110


def run(ctx: dict[str, Any]) -> str:
    """Run sqlmap against ``<target>/rest/user/login`` with a JSON body.

    Returns the raw stdout (truncated). Empty target → "[sqlmap] no
    target provided".
    """
    target = (ctx.get("target") or "").strip().rstrip("/")
    if not target:
        return "[sqlmap] no target provided in ctx"

    url = f"{target}{_LOGIN_PATH}"
    cmd = [
        "sqlmap",
        "-u",
        url,
        "--data",
        _JSON_BODY,
        "--headers",
        "Content-Type: application/json",
        "--batch",
        "--level=2",
        "--risk=2",
        "--threads=5",
        "--timeout=8",
        "--ignore-code=401",
        "--technique=B",
        "--random-agent",
    ]
    logger.info("F187 sqlmap pre_hook: %s", shlex.join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_SQLMAP_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "[sqlmap] timed out after 110s (target may be slow or unreachable)"
    except FileNotFoundError:
        return "[sqlmap] binary not found — pre_hook skipped"
    except OSError as exc:
        return f"[sqlmap] OS error: {exc}"

    # sqlmap's verdict lives in stdout; stderr is mostly empty for
    # successful runs but may carry warnings.
    out = result.stdout or ""
    if not out and result.stderr:
        out = result.stderr
    # Hard cap so a misbehaving run doesn't blow up the context.
    return out[:12000]
