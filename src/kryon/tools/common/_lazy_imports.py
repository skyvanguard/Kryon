"""Lazy import proxy for generic_linux_command to avoid circular imports."""

# Lazy import for generic_linux_command to avoid circular imports
# The actual implementation is in kryon.tools.reconnaissance.generic_linux_command
_generic_linux_command_cached = None


def _get_generic_linux_command():
    """Lazy loader for generic_linux_command to avoid circular imports."""
    global _generic_linux_command_cached
    if _generic_linux_command_cached is None:
        from kryon.tools.reconnaissance.generic_linux_command import (
            generic_linux_command as _glc,
        )

        _generic_linux_command_cached = _glc
    return _generic_linux_command_cached


# Create a wrapper that behaves like the original function
class _GenericLinuxCommandProxy:
    """Proxy class to enable lazy loading of generic_linux_command."""

    def __getattr__(self, name):
        return getattr(_get_generic_linux_command(), name)

    async def __call__(self, *args, **kwargs):
        func = _get_generic_linux_command()
        return await func(*args, **kwargs)


generic_linux_command = _GenericLinuxCommandProxy()
