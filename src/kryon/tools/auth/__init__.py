"""F111 — Auth Flow Runner. Executes a single operator-supplied login
flow, captures the resulting session (cookies + bearer tokens), and
exposes it as plug-in input to the F108 crawler + F109 pipeline so
every downstream analyzer can run authenticated."""

from kryon.tools.auth.runner import (
    AuthFlowConfig,
    AuthFlowRunner,
    AuthSession,
    AuthSuccessSignal,
    LoginCredentials,
    execute_auth_flow,
)

__all__ = [
    "AuthFlowConfig",
    "AuthFlowRunner",
    "AuthSession",
    "AuthSuccessSignal",
    "LoginCredentials",
    "execute_auth_flow",
]
