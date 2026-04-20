"""Pluggable transports for compliance command execution (F36).

Each runner exposes a ``run_<name>_cmd(ctx, cmd, *, timeout_s) ->
(stdout, stderr, exit_code)`` function that mirrors
:func:`kryon.compliance.runner.run_cmd`.
"""
