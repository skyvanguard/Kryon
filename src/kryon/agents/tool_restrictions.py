"""Role-based tool filtering for agents — restricts tool access by user role."""

from __future__ import annotations

import fnmatch
import logging
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class ToolPolicy(BaseModel):
    """Defines which tools a role can access."""

    role: str
    allowed_tools: list[str] = ["*"]
    denied_tools: list[str] = []


DEFAULT_TOOL_POLICIES: dict[str, ToolPolicy] = {
    "admin": ToolPolicy(
        role="admin",
        allowed_tools=["*"],
        denied_tools=[],
    ),
    "analyst": ToolPolicy(
        role="analyst",
        allowed_tools=[
            "nmap_scan",
            "nikto_scan",
            "web_search",
            "dns_query",
            "whois_lookup",
            "ssl_check",
            "port_scan",
            "subdomain_enum",
            "dir_brute",
            "vuln_scan",
            "http_request",
            "shodan_search",
            "nuclei_scan",
            "wpscan",
            "sqlmap_scan",
            "xss_scan",
            "web_crawl",
            "screenshot",
            "tech_detect",
        ],
        denied_tools=["rm_rf", "dd_wipe", "format_disk", "drop_database"],
    ),
    "viewer": ToolPolicy(
        role="viewer",
        allowed_tools=["web_search", "dns_query", "whois_lookup", "ssl_check"],
        denied_tools=[],
    ),
}


class RoleBasedToolFilter:
    """Filters tools based on user role policy."""

    def __init__(self, policy: ToolPolicy | None = None, role: str = "analyst"):
        self._policy = policy or DEFAULT_TOOL_POLICIES.get(role, DEFAULT_TOOL_POLICIES["viewer"])

    @property
    def policy(self) -> ToolPolicy:
        return self._policy

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check if a specific tool is allowed by the policy."""
        # Check denied list first (takes priority)
        for pattern in self._policy.denied_tools:
            if fnmatch.fnmatch(tool_name, pattern):
                return False

        # Check allowed list
        for pattern in self._policy.allowed_tools:
            if pattern == "*" or fnmatch.fnmatch(tool_name, pattern):
                return True

        return False

    def filter_tools(self, tools: list[Any]) -> list[Any]:
        """Filter a list of tools, keeping only those allowed by the policy."""
        filtered = []
        for tool in tools:
            name = getattr(tool, "name", str(tool))
            if self.is_tool_allowed(name):
                filtered.append(tool)
            else:
                logger.debug("Tool %s denied by role %s policy", name, self._policy.role)
        return filtered
