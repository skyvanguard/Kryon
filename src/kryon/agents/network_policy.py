"""Network egress policy — blocks access to internal/unauthorized networks."""

from __future__ import annotations

import ipaddress
import logging
import socket

from pydantic import BaseModel

logger = logging.getLogger(__name__)

# RFC1918 private ranges + loopback — always blocked by default
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]


class NetworkEgressPolicy(BaseModel):
    """Network egress control policy."""

    allow_private: bool = False
    allowed_cidrs: list[str] = []
    denied_cidrs: list[str] = []

    def _parse_networks(self, cidrs: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        nets = []
        for cidr in cidrs:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning("Invalid CIDR in network policy: %s", cidr)
        return nets

    def is_allowed(self, target: str) -> tuple[bool, str | None]:
        """Check if a target IP or hostname is allowed by the policy."""
        # Resolve hostname to IP
        ip = self._resolve(target)
        if ip is None:
            return False, f"Cannot resolve hostname: {target}"

        # Check explicit deny list first
        denied_nets = self._parse_networks(self.denied_cidrs)
        for net in denied_nets:
            if ip in net:
                return False, f"Target {target} ({ip}) is in denied CIDR {net}"

        # Check explicit allow list
        allowed_nets = self._parse_networks(self.allowed_cidrs)
        if allowed_nets:
            for net in allowed_nets:
                if ip in net:
                    return True, None

        # Block private/internal by default
        if not self.allow_private:
            for net in _BLOCKED_NETWORKS:
                if ip in net:
                    return False, f"Target {target} ({ip}) is in private/internal range {net}"

        return True, None

    def _resolve(self, target: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        """Resolve a target to an IP address."""
        target = target.strip()
        try:
            return ipaddress.ip_address(target)
        except ValueError:
            pass
        try:
            info = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if info:
                addr = info[0][4][0]
                return ipaddress.ip_address(addr)
        except (socket.gaierror, OSError, ValueError):
            pass
        return None


def enforce_network_policy(policy: NetworkEgressPolicy | None = None):
    """Decorator that enforces network policy on tool functions.

    The decorated function must accept a `target` keyword argument (str).
    """
    if policy is None:
        policy = NetworkEgressPolicy()

    def decorator(func):
        async def wrapper(*args, **kwargs):
            target = kwargs.get("target") or (args[0] if args else None)
            if target and isinstance(target, str):
                allowed, reason = policy.is_allowed(target)
                if not allowed:
                    raise PermissionError(f"Network policy violation: {reason}")
            return await func(*args, **kwargs)
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    return decorator
