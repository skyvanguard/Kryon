"""Glue between the unified-agent run loop and the pre_hook runner.

The REPL/CLI code calls `maybe_run_pre_hooks(agent, user_input, console)` once
per turn. If the active skills declare any pre_hooks, this:
  1. Builds a `tool_callables` map from the agent's bound tools (using the
     `_raw_fn` accessor stored by `function_tool`).
  2. Builds a turn `ctx` from env vars + the user input (lightweight host
     heuristic so simple cases like "auditá 192.168.1.1" auto-bind).
  3. Runs the hooks via `pre_hook_runner.run_pre_hooks`.
  4. Formats the findings dict into a markdown block ready to append to the
     user input or the conversation_input list.
  5. Surfaces progress to the user via `console.print` (Claude-Code style).

If anything is missing (no skills, no hooks, no console), the function is a
no-op and returns "" — safe to call unconditionally from the REPL.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from kryon.skills.pre_hook_runner import (
    PreHookExecutionError,
    ToolCallable,
    run_pre_hooks,
)
from kryon.skills.pre_hook_spec import PreHookSpec

logger = logging.getLogger(__name__)


# Quick host detector for the user input — picks up an IPv4 / hostname so
# that prompts like "auditá el fortigate 192.168.1.1" automatically bind
# `ctx.host` without the operator having to set KRYON_TARGET_HOST.
_HOST_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9][\w\-.]*\.[a-zA-Z]{2,})\b")

# F203.AS — markers that indicate REAL evidence (a concrete finding) vs
# enumeration noise (a scan that ran but didn't find anything). Without
# this distinction, gpt-oss treats curl header dumps as authoritative
# findings and terminates with severity=INFO entries instead of
# exploring the real exploit chain manually.
#
# FASE 11.T.3 — added "KEY FINDING" + "Disallow:" markers so the
# FASE 11.T web_common_paths pre_hook output counts as evidence. Bench
# Robots showed the model reading the "Pre-hook devolvió output VACÍO"
# imperative suffix and verbalizing "web_common_paths didn't return
# anything" even when the block contained a /robots.txt finding with
# 3 disallow paths. Was a false-negative in evidence detection.
_EVIDENCE_MARKERS = re.compile(
    r"(?:"
    r"\bCWE-\d+\b|"  # CWE-89, CWE-639, etc.
    r"\b(?:VULNERABLE|exploitable|exploited)\b|"
    r"\binjection point\b|\binjection found\b|"
    r"sqlmap identified|"
    r"\[critical\]|\[high\]|\[medium\]|"  # nuclei severity tags (no word-boundary)
    r"\bmatched\b|"
    r"interesting \([a-z ]+\):\s*[1-9]|"  # idor_probe "Interesting (potential CWE-X): N"
    r"candidate \(200 OK on foreign|"  # idor candidate confirmed
    r"KEY FINDING|"  # FASE 11.T web_common_paths section
    r"^\s*Disallow:\s*/"  # /robots.txt body line (recon CTF marker)
    r")",
    re.IGNORECASE | re.MULTILINE,
)


def _looks_like_real_evidence(payload: str) -> bool:
    """F203.AS — distinguir evidence concreta de enumeration noise.

    Curl `Set-Cookie:` dumps, OPTIONS preflight headers, idor_probe
    tables sin candidates → noise. Sólo cuenta como evidence si
    contiene markers de finding REAL (CWE-N, VULNERABLE, [high], etc.).
    """
    if not payload:
        return False
    return _EVIDENCE_MARKERS.search(payload) is not None


def build_tool_callables_from_agent(agent: Any) -> dict[str, ToolCallable]:
    """Extract `{tool_name: raw_python_callable}` from agent.tools.

    Skips any tool that does not expose `._raw_fn` (e.g. MCP-bridged tools
    where the underlying callable lives in a remote process). Pre-hooks
    can only invoke local @function_tool tools — that's intentional, the
    deterministic-detector path should not depend on remote MCP.
    """
    callables: dict[str, ToolCallable] = {}
    tools = getattr(agent, "tools", None) or []
    for t in tools:
        name = getattr(t, "name", None)
        raw = getattr(t, "_raw_fn", None)
        if name and callable(raw):
            callables[name] = raw
    return callables


# Host/URL/path-safe charset. ctx values get substituted into pre_hook commands that
# may run under a shell, so a value with a shell metacharacter (; | & $ ` ( ) < > ' "
# space newline …) is rejected here at the source — closing the command-injection vector
# where KRYON_TARGET_HOST (or any env-sourced ctx var) carried an attacker payload.
_SAFE_CTX_RE = re.compile(r"\A[A-Za-z0-9._:/@\-]*\Z")


def _safe_ctx(value: str) -> str:
    """Return value if it's free of shell metacharacters, else "" (the hook then
    substitutes empty and degrades gracefully — never injects)."""
    return value if _SAFE_CTX_RE.match(value or "") else ""


def build_turn_ctx(user_input: str) -> dict[str, Any]:
    """Compose the per-turn ctx dict consumed by template substitution.

    Variables (all optional, missing → "" at substitution):
      host, ssh_user, ssh_key_path, ssh_port, target, session_id, client_name

    Every value is sanitized to a host/URL/path charset (no shell metacharacters)
    so a malicious KRYON_TARGET_HOST / user input can't inject into a hook command.
    """
    detected_host = ""
    if user_input:
        m = _HOST_RE.search(user_input)
        if m:
            detected_host = m.group(1)

    return {
        "host": _safe_ctx(os.environ.get("KRYON_TARGET_HOST", "") or detected_host),
        "ssh_user": _safe_ctx(os.environ.get("KRYON_SSH_USER", "")),
        "ssh_key_path": _safe_ctx(os.environ.get("KRYON_SSH_KEY", "")),
        "ssh_port": _safe_ctx(os.environ.get("KRYON_SSH_PORT", "22")),
        "target": _safe_ctx(detected_host or os.environ.get("KRYON_TARGET_HOST", "")),
        "session_id": _safe_ctx(os.environ.get("KRYON_SESSION_ID", "")),
        "client_name": _safe_ctx(os.environ.get("KRYON_CLIENT_NAME", "")),
    }


def collect_active_pre_hooks(agent: Any) -> list[PreHookSpec]:
    """Flatten pre_hooks from every active skill on the agent.

    Order is preserved per skill, and skills follow priority order
    (already sorted by the loader).
    """
    skills = getattr(agent, "_active_skills", None) or []
    # Offensive profile: skip compliance-audit pre_hooks. A compliance skill (e.g.
    # windows-server-audit) can match an offensive engagement by target tech, and its
    # run_compliance_audit pre_hook then floods the turn with dozens of WIN-x.x/PCI findings —
    # which derailed the model into regurgitating them as a giant malformed tool call (a 500
    # that killed the AttacktiveDirectory run before the offensive chain could start). Compliance
    # audits belong to compliance engagements, not red-team. The findings themselves stay
    # available via `kryon engage`; this only stops them from polluting an offensive turn.
    from kryon.util.env import is_red_team  # noqa: PLC0415

    skip_compliance = is_red_team()
    flat: list[PreHookSpec] = []
    for skill in skills:
        for hook in getattr(skill, "pre_hooks", None) or ():
            if skip_compliance and getattr(hook, "tool", "") == "run_compliance_audit":
                continue
            flat.append(hook)
    return flat


def format_findings_block(findings: dict[str, str]) -> str:
    """Format the pre-hook output dict as a markdown block.

    Designed to be appended to the user input (or the last user message
    in a conversation_input list) so the model sees authoritative context
    inline with the request.

    F186 — each payload is run through ``summarize_pre_hook_output``
    before rendering: nuclei/nikto-shaped output gets de-noised (banners,
    template-load metadata, scan progress stripped) and capped to the
    top-N findings sorted by severity. The block ends with the F186
    imperative suffix that forces the model to convert the evidence
    into findings JSON instead of re-invoking the tools.
    """
    if not findings:
        return ""

    from kryon.skills.pre_hook_output_processor import (
        imperative_findings_suffix,
        summarize_pre_hook_output,
    )

    parts = [
        "",
        "---",
        "## Pre-hook deterministic context (this turn)",
        "",
        "_The tools below were executed deterministically BEFORE you. "
        "Their output is authoritative — do NOT re-run these tools this "
        "turn, narrate the findings honestly._",
        "",
    ]
    # F203.AO.B — track whether any pre_hook returned actual evidence.
    # When all hooks returned empty/whitespace, we'll use the
    # "continue manually" variant of the imperative suffix (vs the
    # default "convert each line to JSON" variant). Prevents gpt-oss
    # from terminating with `[]` when catalog heuristics missed.
    any_evidence = False
    for inject_as, payload in findings.items():
        parts.append(f"### {inject_as}")
        parts.append("")
        parts.append("```")
        # Try to keep payload as raw JSON if it parses (e.g.
        # ``deterministic_compliance_findings`` from run_compliance_audit
        # is structured JSON we don't want to text-summarize).
        try:
            parsed = json.loads(payload)
            rendered = json.dumps(parsed, indent=2, ensure_ascii=False)
            parts.append(rendered)
            # Non-empty JSON array/object = evidence present.
            if isinstance(parsed, (list, dict)) and parsed:
                any_evidence = True
            elif isinstance(parsed, str) and parsed.strip():
                any_evidence = True
        except (json.JSONDecodeError, TypeError):
            # F186 — text output goes through the de-noiser + truncator.
            compact = summarize_pre_hook_output(inject_as, payload)
            parts.append(compact)
            # F203.AS — text payload solo cuenta como evidence si tiene
            # markers de finding REAL (no enumeration noise). curl
            # `Set-Cookie:` headers o `===path===` separators son
            # informational, NO findings concretos. Evidence markers
            # claros: "CWE-", "VULNERABLE", "Injection", "matched",
            # "exploited", "interesting". Sin esos markers, el text
            # se trata como informational → modelo continúa.
            if compact and _looks_like_real_evidence(compact):
                any_evidence = True
        parts.append("```")
        parts.append("")
    parts.append(imperative_findings_suffix(evidence_present=any_evidence))
    return "\n".join(parts)


async def maybe_run_pre_hooks(
    agent: Any,
    user_input: str,
    console: Any = None,
) -> str:
    """Run all active pre_hooks for this turn, return formatted suffix.

    Returns:
        Empty string if nothing ran (no hooks declared, or no agent skills).
        Otherwise a markdown block ready to concat to the user input.

    Behaviour on errors:
        - Required hook failure → suffix contains a clearly-marked error
          block and the rest of the turn proceeds (we do NOT abort the
          conversation; surfacing the error inline lets the user retry).
        - Optional hook failure → handled inside `run_pre_hooks`, output
          is a `[pre_hook X failed: ...]` placeholder.
    """
    hooks = collect_active_pre_hooks(agent)
    if not hooks:
        return ""

    callables = build_tool_callables_from_agent(agent)
    ctx = build_turn_ctx(user_input)

    # Surface intent up-front so the user sees what's about to happen.
    if console is not None:
        for hook in hooks:
            label = hook.tool or hook.python or "(unknown)"
            try:
                console.print(
                    f"[dim cyan]▸[/dim cyan] [yellow]pre-hook:[/yellow] "
                    f"[cyan]{label}[/cyan] [dim](timeout {hook.timeout_s}s)[/dim]"
                )
            except Exception:
                pass

    try:
        findings = await run_pre_hooks(tuple(hooks), ctx=ctx, tool_callables=callables)
    except PreHookExecutionError as e:
        logger.warning("pre-hook required failure: %s", e)
        if console is not None:
            try:
                console.print(f"[red]✗ pre-hook required failure:[/red] {e}")
            except Exception:
                pass
        # Surface the failure to the LLM as authoritative context so it
        # tells the user instead of silently proceeding without findings.
        return format_findings_block(
            {
                "_pre_hook_error": f"Required pre-hook failed: {e}. "
                "Tell the user what failed and stop — do NOT re-run the tool."
            }
        )

    # Per-finding success line for the user.
    if console is not None:
        for inject_as, payload in findings.items():
            size = len(payload) if isinstance(payload, str) else 0
            try:
                console.print(f"  [green]✓[/green] [dim]{inject_as}[/dim] [dim]({size} chars)[/dim]")
            except Exception:
                pass

    return format_findings_block(findings)
