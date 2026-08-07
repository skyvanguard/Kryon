"""Probe registry — the scaffolding that lets the deterministic detectors scale.

Instead of hand-wiring every ``run_*`` probe runner into engage AND investigate
(import block + gated call, ~30 edits across two load-bearing files), each module
is declared ONCE here with a gate (when to run) and whether it takes a scheme.
``run_all_probes(svc)`` iterates the registry; adding a detector becomes a single
line here.

Lazy module resolution (cached) keeps the engage ↔ probe-module import order intact
(engage imports this lazily; this imports the probe modules, which import a
fully-loaded engage). A missing/broken module is skipped, never fatal.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.probe_base import TLS_PORTS as _TLS_PORTS, TLS_SERVICES as _TLS_SERVICES

# Gate predicates over a DiscoveredService (duck-typed: .host, .port, .service).
_HTTP_SERVICES = ("http", "http-proxy", "https")
_HTTP_PORTS = (80, 443, 8080, 8443)
_VPN_PORTS = (443, 4443, 8443, 10443)
# https when the service is TLS-ish or the port is one a scheme-taking runner
# reaches over TLS — chosen so a single function reproduces the per-runner schemes
# the old hand-wiring computed (web/app/webapp/default-creds used {443,8443};
# infra added 5001; vpn forced https on {443,4443,8443,10443}).
_HTTPS_PORTS = (443, 8443, 5001, 4443, 10443)


def _always(s) -> bool:  # noqa: ANN001
    return True


def _is_http(s) -> bool:  # noqa: ANN001
    return s.service in _HTTP_SERVICES or s.port in _HTTP_PORTS


def _is_tls(s) -> bool:  # noqa: ANN001
    return s.service in _TLS_SERVICES or s.port in _TLS_PORTS


def _is_vpn(s) -> bool:  # noqa: ANN001
    return s.service in ("https", "ssl") or s.port in _VPN_PORTS


def _is_ssh(s) -> bool:  # noqa: ANN001
    return s.service == "ssh" or s.port in (22, 2222)


def scheme_for(s) -> str:  # noqa: ANN001
    return "https" if (s.service in ("https", "ssl") or s.port in _HTTPS_PORTS) else "http"


@dataclass(frozen=True)
class _Entry:
    module: str
    func: str
    gate: Callable
    pass_scheme: bool


# Declarative wiring — the ONE place a probe module is registered.
_REGISTRY: tuple[_Entry, ...] = (
    _Entry("service_probes", "run_service_probes", _always, False),
    _Entry("ad_probes", "run_ad_probes", _always, False),
    _Entry("legacy_probes", "run_legacy_probes", _always, False),
    _Entry("amp_probes", "run_amp_probes", _always, False),
    _Entry("ot_probes", "run_ot_probes", _always, False),
    _Entry("mail_probes", "run_mail_probes", _always, False),
    _Entry("infra_probes", "run_infra_probes", _always, True),
    _Entry("ssh_probes", "run_ssh_probes", _is_ssh, False),
    _Entry("tls_probes", "run_tls_probes", _is_tls, False),
    _Entry("web_probes", "run_web_probes", _is_http, True),
    _Entry("app_probes", "run_app_probes", _is_http, True),
    _Entry("webapp_probes", "run_webapp_probes", _is_http, True),
    _Entry("default_creds", "run_default_cred_checks", _is_http, True),
    _Entry("vpn_probes", "run_vpn_probes", _is_vpn, True),
)

_RESOLVED: list[tuple[_Entry, Callable]] | None = None


def _resolve() -> list[tuple[_Entry, Callable]]:
    global _RESOLVED
    if _RESOLVED is not None:
        return _RESOLVED
    out: list[tuple[_Entry, Callable]] = []
    for e in _REGISTRY:
        try:
            mod = importlib.import_module(f"kryon.cli.{e.module}")
            out.append((e, getattr(mod, e.func)))
        except (ImportError, AttributeError):
            continue  # a missing/broken probe module must never break the sweep
    _RESOLVED = out
    return out


def run_all_probes(svc: DiscoveredService) -> list[Finding]:
    """Run every registered probe whose gate matches the service. Never raises.

    The runners are independent, network-I/O-bound, and mostly hit *different*
    services/ports — so against a single host the sequential loop spent ~70s
    waiting on closed-port timeouts (measured on a web host). They run
    concurrently by default (I/O releases the GIL); set ``KRYON_PROBE_SERIAL=1``
    to force the old sequential order for ultra-conservative/banca-safe runs.
    """
    import os
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FTimeout, as_completed

    sch = scheme_for(svc)
    tasks = [(e, fn) for e, fn in _resolve() if _safe_gate(e, svc)]
    if not tasks:
        return []

    def _run(pair) -> list:  # noqa: ANN001
        e, fn = pair
        try:
            return fn(svc, sch) if e.pass_scheme else (fn(svc) or [])
        except Exception:  # noqa: BLE001 — one probe must never break the rest
            return []

    serial = os.environ.get("KRYON_PROBE_SERIAL", "").strip().lower() in ("1", "true", "yes", "on")
    out: list = []
    if serial:
        for pair in tasks:
            out.extend(_run(pair) or [])
        return out

    # R1 — wall-clock deadline for the whole sweep. Without it, ThreadPoolExecutor's
    # context-manager __exit__ waits on EVERY worker, so a single hung probe (e.g. a
    # slowloris peer dribbling one byte before each socket timeout) blocks all of
    # run_all_probes — the same failure class as the 180s compliance hang. We collect
    # whatever finishes before the deadline and abandon the rest (their threads die on
    # their own socket timeout; we do NOT wait on shutdown). Tune with KRYON_PROBE_DEADLINE_S.
    try:
        _deadline = float(os.environ.get("KRYON_PROBE_DEADLINE_S", "60"))
    except ValueError:
        _deadline = 60.0
    ex = ThreadPoolExecutor(max_workers=min(12, len(tasks)))
    try:
        futures = [ex.submit(_run, pair) for pair in tasks]
        try:
            for fut in as_completed(futures, timeout=_deadline):
                try:
                    res = fut.result()
                except Exception:  # noqa: BLE001
                    res = []
                if res:
                    out.extend(res)
        except _FTimeout:
            # Deadline hit — keep the findings we already have, drop the stragglers.
            pass
    finally:
        # Don't block on hung workers; cancel the ones that never started.
        ex.shutdown(wait=False, cancel_futures=True)
    return out


def _safe_gate(e, svc) -> bool:  # noqa: ANN001
    try:
        return bool(e.gate(svc))
    except Exception:  # noqa: BLE001
        return False
