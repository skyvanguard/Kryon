"""WinRM / PowerShell Remoting runner for Windows hosts (F36).

This module provides ``run_winrm_cmd`` matching the contract of
:func:`kryon.compliance.runner.run_cmd` so Windows-targeted CIS checks
can plug in without modifying the check YAML layer.

Authentication
--------------

Supports NTLM, Kerberos, CredSSP, and basic (test environments only).
Credentials are read from the ``CheckContext`` and never persisted.
HTTPS (5986) is strongly preferred for production; HTTP (5985) is
acceptable only inside a dedicated admin VLAN.

Dependency note
---------------

Requires the ``pywinrm`` package (and ``requests-kerberos`` for
Kerberos auth). Both are optional extras — the module degrades
gracefully with a clear error if absent.

Command semantics
-----------------

Accepts the same ``cmd: list[str] | str`` interface as ``run_cmd``.
A ``list[str]`` is joined with single-space separation for cmd.exe
execution. For PowerShell-native invocations, pass a string that
starts with ``powershell -nop -c ...`` or use ``Get-*`` cmdlets
directly inside ``reg query`` / ``auditpol`` / ``secedit`` wrappers
that match how most CIS Windows benchmarks ship.

Output is truncated to 4 KB stdout / 1 KB stderr for reproducibility
and evidence hygiene — identical to the SSH path.
"""

from __future__ import annotations

from typing import Any

from kryon.compliance.checks.base import CheckContext

_STDOUT_CAP = 4096
_STDERR_CAP = 1024


def _format_cmd(cmd: list[str] | str) -> str:
    if isinstance(cmd, list):
        # Windows cmd.exe doesn't have POSIX shell quoting rules; if a
        # caller truly needs spaces inside an argument they must pass
        # a pre-built string. Joining by space matches the behaviour of
        # ``subprocess.list2cmdline`` for most CIS audit commands which
        # don't use literal spaces inside args.
        return " ".join(cmd)
    return cmd


def _classify_auth(auth: str) -> str:
    """Map our short auth names to pywinrm's transport identifiers."""
    a = (auth or "").lower()
    if a in ("kerberos", "krb5"):
        return "kerberos"
    if a in ("basic",):
        return "basic"
    if a in ("credssp",):
        return "credssp"
    return "ntlm"  # default


def run_winrm_cmd(
    ctx: CheckContext,
    cmd: list[str] | str,
    *,
    timeout_s: int = 15,
) -> tuple[str, str, int]:
    """Execute ``cmd`` on ``ctx.host`` via WinRM and return (stdout, stderr, rc).

    Never raises — all transport, auth, and protocol errors become
    ``("", <error message>, <non-zero rc>)`` so the CIS evaluator can
    mark the check as ERROR rather than crashing the run.
    """
    # Validate args before attempting any network or import work so
    # misconfiguration is caught without side effects.
    if not ctx.host or ctx.host in ("localhost", "127.0.0.1"):
        return (
            "",
            "winrm transport requires a remote host; got localhost",
            2,
        )

    if not ctx.winrm_user or not ctx.winrm_password:
        return (
            "",
            "winrm transport requires ctx.winrm_user and ctx.winrm_password",
            2,
        )

    try:
        import winrm  # type: ignore
    except ImportError:
        return (
            "",
            "pywinrm is not installed; install with: pip install pywinrm",
            127,
        )

    scheme = "https" if (ctx.winrm_scheme or "").lower() == "https" else "http"
    endpoint = f"{scheme}://{ctx.host}:{ctx.winrm_port}/wsman"
    transport = _classify_auth(ctx.winrm_auth)

    session_kwargs: dict[str, Any] = {
        "auth": (ctx.winrm_user, ctx.winrm_password),
        "transport": transport,
        "operation_timeout_sec": max(5, timeout_s),
        "read_timeout_sec": max(10, timeout_s + 5),
        "server_cert_validation": (
            "validate" if scheme == "https" else "ignore"
        ),
    }

    cmd_str = _format_cmd(cmd)

    try:
        session = winrm.Session(endpoint, **session_kwargs)

        # Route PowerShell scripts vs. cmd.exe invocations.
        lstripped = cmd_str.lstrip()
        lower = lstripped.lower()
        if lower.startswith(("powershell", "pwsh")):
            # Let the caller's explicit "powershell -nop -c ..." flow through
            # unchanged via run_cmd rather than run_ps for exact parity with
            # the intent of the author.
            result = session.run_cmd(cmd_str)
        elif lower.startswith(("get-", "set-", "test-", "where-object", "$")):
            result = session.run_ps(cmd_str)
        else:
            result = session.run_cmd(cmd_str)

        stdout = result.std_out.decode("utf-8", errors="replace")[:_STDOUT_CAP]
        stderr = result.std_err.decode("utf-8", errors="replace")[:_STDERR_CAP]
        return stdout, stderr, int(result.status_code)

    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        if "BasicAuth" in msg or "401" in msg:
            return "", f"winrm auth failed ({transport}): {msg}"[:_STDERR_CAP], 1
        if "timed out" in msg.lower() or "timeout" in msg.lower():
            return "", f"winrm timeout after {timeout_s}s: {msg}"[:_STDERR_CAP], 124
        if "ConnectionError" in msg or "Failed to establish" in msg:
            return "", f"winrm connection failed: {msg}"[:_STDERR_CAP], 1
        return "", f"winrm error: {msg}"[:_STDERR_CAP], 1


__all__ = ["run_winrm_cmd"]
