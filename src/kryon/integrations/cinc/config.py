"""Env-driven config for the Cinc Auditor integration.

* Fire gate — ``KRYON_CINC_FIRE`` (default OFF). Cinc reads config over SSH; it
  is read-only, but gating it keeps every external-scan integration uniform and
  opt-in.
* Profiles — which profiles to run. Defaults to the dev-sec.io (Apache-2.0)
  SSH + Linux baselines, referenceable directly by git URL.
* Target/auth — build the Cinc transport target + auth extra-args from the
  engagement's SSH parameters.
"""

from __future__ import annotations

import os

_TRUTHY = {"1", "true", "yes", "on"}

_DEFAULT_PROFILES = (
    "https://github.com/dev-sec/ssh-baseline",
    "https://github.com/dev-sec/linux-baseline",
)


def is_cinc_enabled() -> bool:
    """True only when KRYON_CINC_FIRE opts in. Default OFF."""
    return os.getenv("KRYON_CINC_FIRE", "").strip().lower() in _TRUTHY


def profiles_from_env() -> list[str]:
    """Profiles to run — KRYON_CINC_PROFILES (comma-separated) or the dev-sec defaults."""
    raw = os.getenv("KRYON_CINC_PROFILES", "")
    picked = [p.strip() for p in raw.split(",") if p.strip()]
    return picked or list(_DEFAULT_PROFILES)


def build_target(host: str, *, ssh_user: str = "") -> str:
    """Cinc transport target. Local when there's no host/user, else ssh://."""
    if not host or host in ("localhost", "127.0.0.1"):
        return "local://"
    return f"ssh://{ssh_user}@{host}" if ssh_user else f"ssh://{host}"


def build_ssh_extra_args(*, ssh_key: str = "", ssh_password: str = "", ssh_port: int = 22) -> list[str]:
    """Cinc auth/transport flags derived from the engagement's SSH params."""
    args: list[str] = []
    if ssh_port and ssh_port != 22:
        args += ["--port", str(ssh_port)]
    if ssh_key:
        args += ["-i", ssh_key]
    if ssh_password:
        args += ["--password", ssh_password]
    return args
