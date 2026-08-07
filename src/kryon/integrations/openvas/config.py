"""Env-driven configuration for the OpenVAS integration.

Two concerns:

* **Fire gate** — OpenVAS runs *active, intrusive* scans, so it is double-gated
  like the other live-probe tools: it only runs when ``KRYON_OPENVAS_FIRE`` is
  truthy. Default OFF (banca-safe); without it the integration is inert.
* **Connection** — how to reach the stock Greenbone (socket path + GMP creds),
  used to build the arm's-length ``gvm-cli`` runner.
"""

from __future__ import annotations

import os

from kryon.integrations.openvas.client import GmpRunner, gmp_socket_runner, gvm_cli_runner

_TRUTHY = {"1", "true", "yes", "on"}


def is_openvas_enabled() -> bool:
    """True only when KRYON_OPENVAS_FIRE opts in. Default OFF."""
    return os.getenv("KRYON_OPENVAS_FIRE", "").strip().lower() in _TRUTHY


def runner_from_env() -> GmpRunner:
    """Build a GMP runner from KRYON_OPENVAS_* env.

    Default transport is **raw GMP** (``gmp_socket_runner``) — zero Greenbone
    code in the Kryon image, maximal license cleanliness. Set
    ``KRYON_OPENVAS_TRANSPORT=cli`` to fall back to ``gvm-cli`` (needs
    gvm-tools installed).
    """
    try:
        timeout = int(os.getenv("KRYON_OPENVAS_TIMEOUT", "900") or "900")
    except ValueError:
        timeout = 900
    socket_path = os.getenv("KRYON_OPENVAS_SOCKET", "/run/gvmd/gvmd.sock")
    username = os.getenv("KRYON_OPENVAS_USER", "admin")
    password = os.getenv("KRYON_OPENVAS_PASSWORD", "")

    if os.getenv("KRYON_OPENVAS_TRANSPORT", "gmp").strip().lower() == "cli":
        return gvm_cli_runner(socket_path=socket_path, username=username, password=password, timeout_s=timeout)

    use_tls = os.getenv("KRYON_OPENVAS_TLS", "").strip().lower() in _TRUTHY
    return gmp_socket_runner(
        username=username,
        password=password,
        socket_path=socket_path,
        use_tls=use_tls,
        host=os.getenv("KRYON_OPENVAS_HOST", "127.0.0.1"),
        port=int(os.getenv("KRYON_OPENVAS_PORT", "9390") or "9390"),
        cafile=os.getenv("KRYON_OPENVAS_CAFILE", ""),
        insecure_tls=os.getenv("KRYON_OPENVAS_TLS_INSECURE", "").strip().lower() in _TRUTHY,
        timeout_s=timeout,
    )
