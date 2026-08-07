"""Lazy import proxy for run_command to avoid circular imports."""

# Lazy import for run_command to avoid circular imports
# The actual implementation is in kryon.tools.reconnaissance.run_command
_run_command_cached = None


def _get_run_command():
    """Lazy loader for run_command to avoid circular imports."""
    global _run_command_cached
    if _run_command_cached is None:
        from kryon.tools.reconnaissance.run_command import (
            run_command as _rc,
        )

        _run_command_cached = _rc
    return _run_command_cached


# Create a wrapper that behaves like the original function
class _RunCommandProxy:
    """Proxy class to enable lazy loading of run_command."""

    def __getattr__(self, name):
        return getattr(_get_run_command(), name)

    async def __call__(self, *args, **kwargs):
        func = _get_run_command()
        return await func(*args, **kwargs)


run_command_tool = _RunCommandProxy()
