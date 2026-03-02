"""Scope enforcement for agent operations — ensures agents only target whitelisted assets."""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

from pydantic import BaseModel

from kryon.sdk.agents import (
    GuardrailFunctionOutput,
    RunContextWrapper,
    TResponseInputItem,
    input_guardrail,
)

logger = logging.getLogger(__name__)

# Regex patterns for extracting IPs and domains from text
_IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_DOMAIN_PATTERN = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)\b")


class ScopeRule(BaseModel):
    """A single scope whitelist rule."""

    id: str = ""
    client_id: str = ""
    rule_type: str  # 'cidr' | 'domain' | 'ip' | 'url_prefix'
    value: str
    description: str = ""
    created_at: str = ""
    created_by: str | None = None


class ScopeEnforcer:
    """Validates targets against a set of scope rules."""

    def __init__(self, rules: list[ScopeRule]):
        self._rules = rules
        self._cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._domains: list[str] = []
        self._ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        self._url_prefixes: list[str] = []
        self._parse_rules()

    def _parse_rules(self) -> None:
        for rule in self._rules:
            try:
                if rule.rule_type == "cidr":
                    self._cidrs.append(ipaddress.ip_network(rule.value, strict=False))
                elif rule.rule_type == "domain":
                    self._domains.append(rule.value.lower())
                elif rule.rule_type == "ip":
                    self._ips.append(ipaddress.ip_address(rule.value))
                elif rule.rule_type == "url_prefix":
                    self._url_prefixes.append(rule.value.lower())
            except ValueError:
                logger.warning("Invalid scope rule: %s = %s", rule.rule_type, rule.value)

    def is_allowed(self, target: str) -> tuple[bool, str | None]:
        """Check if a target is within scope. Returns (allowed, reason_if_denied)."""
        if not self._rules:
            return True, None

        target_lower = target.lower().strip()

        # Check URL prefix rules
        for prefix in self._url_prefixes:
            if target_lower.startswith(prefix):
                return True, None

        # Try to parse as IP
        try:
            ip = ipaddress.ip_address(target.strip())
            # Check exact IP rules
            if ip in self._ips:
                return True, None
            # Check CIDR rules
            for cidr in self._cidrs:
                if ip in cidr:
                    return True, None
            return False, f"IP {target} is not in scope whitelist"
        except ValueError:
            pass

        # Try as domain
        for domain in self._domains:
            if target_lower == domain or target_lower.endswith("." + domain):
                return True, None

        return False, f"Target {target} is not in scope whitelist"

    def validate_targets(self, targets: list[str]) -> list[str]:
        """Validate a list of targets. Returns list of violation messages."""
        violations = []
        for target in targets:
            allowed, reason = self.is_allowed(target)
            if not allowed:
                violations.append(reason or f"{target} out of scope")
        return violations

    def extract_and_validate(self, text: str) -> list[str]:
        """Extract IPs and domains from text and validate against scope."""
        violations = []
        # Extract IPs
        for match in _IP_PATTERN.finditer(text):
            ip_str = match.group(1)
            try:
                ipaddress.ip_address(ip_str)
                allowed, reason = self.is_allowed(ip_str)
                if not allowed:
                    violations.append(reason or f"{ip_str} out of scope")
            except ValueError:
                pass

        # Extract domains
        for match in _DOMAIN_PATTERN.finditer(text):
            domain = match.group(1)
            # Skip common false positives
            if domain.endswith((".example.com", ".test", ".localhost")):
                continue
            allowed, reason = self.is_allowed(domain)
            if not allowed:
                violations.append(reason or f"{domain} out of scope")

        return violations


@input_guardrail(name="scope_enforcement_guard")
async def scope_enforcement_guardrail(
    ctx: RunContextWrapper[Any], agent: Any, input: str | list[TResponseInputItem]
) -> GuardrailFunctionOutput:
    """Input guardrail that validates targets against scope whitelist."""
    # Get scope rules from agent context if available
    scope_rules = getattr(ctx.context, "scope_rules", None) if ctx.context else None
    if not scope_rules:
        return GuardrailFunctionOutput(
            output_info={"action": "allowed", "reason": "No scope rules configured"},
            tripwire_triggered=False,
        )

    enforcer = ScopeEnforcer(scope_rules)

    # Convert input to text
    if isinstance(input, list):
        input_text = " ".join(str(item) for item in input)
    else:
        input_text = str(input)

    violations = enforcer.extract_and_validate(input_text)
    if violations:
        return GuardrailFunctionOutput(
            output_info={
                "action": "blocked",
                "reason": "Targets outside engagement scope detected",
                "violations": violations,
            },
            tripwire_triggered=True,
        )

    return GuardrailFunctionOutput(
        output_info={"action": "allowed"},
        tripwire_triggered=False,
    )
