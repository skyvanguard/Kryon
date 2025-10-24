"""
SKYNET Adaptive Strategy Engine - Intelligent Fallback System
=============================================================

Auto-adaptation system that detects failures, identifies causes,
and automatically selects alternative strategies for success.

Clearance Level: Omega-Strategic (Adaptive Operations Authority)
Classification: RESTRICTED
Mission: Convert failures into successes through intelligent adaptation

Features:
- Automatic failure detection and classification
- Intelligent fallback strategy selection
- Defense bypass technique application
- Payload adaptation and evasion
- Retry logic with exponential backoff
- Learning from failures
"""

import random
import time
from enum import Enum
from typing import Any, Dict, Optional


class FailureReason(Enum):
    """Classification of failure reasons."""

    WAF_BLOCKED = "waf_blocked"
    IPS_BLOCKED = "ips_blocked"
    RATE_LIMITED = "rate_limited"
    AUTH_REQUIRED = "auth_required"
    SERVICE_CRASHED = "service_crashed"
    TIMEOUT = "timeout"
    PAYLOAD_DETECTED = "payload_detected"
    NETWORK_ERROR = "network_error"
    INVALID_RESPONSE = "invalid_response"
    PERMISSION_DENIED = "permission_denied"
    UNKNOWN = "unknown"


class AdaptiveStrategy:
    """
    Adaptive execution engine with intelligent fallback.

    Converts failures into successes by:
    1. Detecting why an exploit failed
    2. Selecting appropriate fallback strategy
    3. Applying evasion techniques
    4. Retrying with adapted approach
    """

    def __init__(self, max_attempts: int = 5, enable_learning: bool = True):
        """
        Initialize adaptive strategy engine.

        Args:
            max_attempts: Maximum retry attempts per exploit
            enable_learning: Enable learning from failures
        """
        self.max_attempts = max_attempts
        self.enable_learning = enable_learning
        self.attempt_history = []
        self.defenses_detected = set()

    def adaptive_exploit_execution(
        self,
        target_ip: str,
        exploit: Dict[str, Any],
        service: Dict[str, Any],
        initial_strategy: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Execute exploit with adaptive retry logic.

        Args:
            target_ip: Target IP address
            exploit: Exploit details
            service: Target service details
            initial_strategy: Initial execution strategy

        Returns:
            Dictionary with execution results
        """
        results = {
            "success": False,
            "attempts": 0,
            "adaptations_applied": [],
            "defenses_encountered": [],
            "final_strategy": None,
            "error": None,
            "shell_obtained": False,
            "privilege_level": "none",
        }

        strategy = initial_strategy or self._create_initial_strategy(exploit, service)

        for attempt in range(1, self.max_attempts + 1):
            results["attempts"] = attempt

            print(f"[*] Attempt {attempt}/{self.max_attempts}: {exploit['name']}")
            print(f"    Strategy: {strategy.get('description', 'Standard')}")

            # Execute exploit with current strategy
            attempt_result = self._execute_exploit_attempt(target_ip, exploit, service, strategy)

            # Record attempt
            self.attempt_history.append(
                {
                    "attempt": attempt,
                    "strategy": strategy,
                    "result": attempt_result,
                    "timestamp": time.time(),
                }
            )

            # Check if successful
            if attempt_result.get("success"):
                results["success"] = True
                results["shell_obtained"] = attempt_result.get("shell_obtained", False)
                results["privilege_level"] = attempt_result.get("privilege_level", "user")
                results["final_strategy"] = strategy
                print(f"[+] Success on attempt {attempt}!")
                break

            # Detect failure reason
            failure_reason = self._detect_failure_reason(attempt_result)
            results["defenses_encountered"].append(failure_reason.value)
            self.defenses_detected.add(failure_reason)

            print(f"[-] Failed: {failure_reason.value}")

            # Last attempt? Don't adapt further
            if attempt >= self.max_attempts:
                results["error"] = f"Max attempts reached. Last failure: {failure_reason.value}"
                break

            # Adapt strategy based on failure
            adapted_strategy = self._adapt_strategy(
                strategy, failure_reason, attempt_result, attempt
            )

            if adapted_strategy:
                results["adaptations_applied"].append(
                    {
                        "attempt": attempt,
                        "reason": failure_reason.value,
                        "adaptation": adapted_strategy.get("description", "Unknown"),
                    }
                )
                strategy = adapted_strategy
                print(f"[*] Adapting: {adapted_strategy.get('description', 'Fallback strategy')}")
            else:
                print(f"[-] No adaptation available for {failure_reason.value}")
                results["error"] = f"No adaptation available for {failure_reason.value}"
                break

        return results

    def _detect_failure_reason(self, attempt_result: Dict[str, Any]) -> FailureReason:
        """
        Detect why an exploit attempt failed.

        Args:
            attempt_result: Result of exploit attempt

        Returns:
            FailureReason enum
        """
        error_msg = str(attempt_result.get("error", "")).lower()
        response = str(attempt_result.get("response", "")).lower()
        status_code = attempt_result.get("status_code", 0)

        # WAF detection
        if any(
            indicator in error_msg or indicator in response
            for indicator in [
                "waf",
                "firewall",
                "cloudflare",
                "blocked",
                "forbidden",
                "akamai",
                "incapsula",
                "sucuri",
                "modsecurity",
            ]
        ):
            return FailureReason.WAF_BLOCKED

        # IPS detection
        if any(
            indicator in error_msg for indicator in ["intrusion", "ips", "ids", "snort", "suricata"]
        ):
            return FailureReason.IPS_BLOCKED

        # Rate limiting
        if status_code == 429 or any(
            indicator in error_msg or indicator in response
            for indicator in ["rate limit", "too many requests", "429", "throttle", "slow down"]
        ):
            return FailureReason.RATE_LIMITED

        # Authentication required
        if (
            status_code == 401
            or status_code == 403
            or any(
                indicator in response
                for indicator in [
                    "unauthorized",
                    "authentication required",
                    "login required",
                    "401",
                    "403",
                ]
            )
        ):
            return FailureReason.AUTH_REQUIRED

        # Service crashed
        if any(
            indicator in error_msg
            for indicator in [
                "connection refused",
                "service unavailable",
                "connection reset",
                "no route to host",
                "502",
                "503",
            ]
        ):
            return FailureReason.SERVICE_CRASHED

        # Timeout
        if "timeout" in error_msg or "timed out" in error_msg:
            return FailureReason.TIMEOUT

        # Payload detected
        if any(
            indicator in response
            for indicator in ["malicious", "attack detected", "suspicious", "security violation"]
        ):
            return FailureReason.PAYLOAD_DETECTED

        # Permission denied
        if "permission denied" in error_msg or "access denied" in error_msg:
            return FailureReason.PERMISSION_DENIED

        # Network errors
        if any(
            indicator in error_msg for indicator in ["network", "dns", "unreachable", "connection"]
        ):
            return FailureReason.NETWORK_ERROR

        return FailureReason.UNKNOWN

    def _adapt_strategy(
        self,
        current_strategy: Dict,
        failure_reason: FailureReason,
        attempt_result: Dict,
        attempt_number: int,
    ) -> Optional[Dict[str, Any]]:
        """
        Adapt strategy based on failure reason.

        Args:
            current_strategy: Current execution strategy
            failure_reason: Why the attempt failed
            attempt_result: Details of failed attempt
            attempt_number: Current attempt number

        Returns:
            Adapted strategy or None if no adaptation available
        """
        adaptations = {
            FailureReason.WAF_BLOCKED: self._adapt_for_waf,
            FailureReason.IPS_BLOCKED: self._adapt_for_ips,
            FailureReason.RATE_LIMITED: self._adapt_for_rate_limit,
            FailureReason.AUTH_REQUIRED: self._adapt_for_auth,
            FailureReason.SERVICE_CRASHED: self._adapt_for_crash,
            FailureReason.TIMEOUT: self._adapt_for_timeout,
            FailureReason.PAYLOAD_DETECTED: self._adapt_for_payload_detection,
            FailureReason.PERMISSION_DENIED: self._adapt_for_permission_denied,
        }

        adaptation_func = adaptations.get(failure_reason)
        if adaptation_func:
            return adaptation_func(current_strategy, attempt_result, attempt_number)

        return None

    def _adapt_for_waf(self, strategy: Dict, result: Dict, attempt: int) -> Dict[str, Any]:
        """Adapt strategy to bypass WAF using Evasion Autonomy v3.1."""
        adapted = strategy.copy()
        adapted["description"] = "WAF bypass attempt (Evasion Autonomy v3.1)"

        # Get evasion recommendations from new evasion module
        try:
            from skynet.tools.autonomous.evasion_autonomy import get_evasion_recommendations
            evasion_recs = get_evasion_recommendations("waf")
            adapted["evasion_techniques"] = evasion_recs.get("recommended_techniques", [])
        except ImportError:
            # Fallback to legacy techniques if evasion module unavailable
            pass

        # Progressive evasion techniques
        if attempt == 1:
            # First retry: Case manipulation
            adapted["payload_encoding"] = "case_mix"
            adapted["headers"] = {
                "User-Agent": self._get_legitimate_user_agent(),
                "Referer": result.get("target_url", ""),
            }
        elif attempt == 2:
            # Second retry: URL encoding
            adapted["payload_encoding"] = "url_double"
            adapted["add_junk_params"] = True
        elif attempt == 3:
            # Third retry: Unicode encoding
            adapted["payload_encoding"] = "unicode"
            adapted["request_fragmentation"] = True
        else:
            # Last resort: Heavy obfuscation
            adapted["payload_encoding"] = "multi_layer"
            adapted["use_alternate_syntax"] = True

        return adapted

    def _adapt_for_ips(self, strategy: Dict, result: Dict, attempt: int) -> Dict[str, Any]:
        """Adapt strategy to evade IPS."""
        adapted = strategy.copy()
        adapted["description"] = "IPS evasion attempt"

        # IPS evasion techniques
        adapted["packet_fragmentation"] = True
        adapted["timing_delays"] = random.uniform(2, 5)  # Random delay 2-5 seconds
        adapted["randomize_order"] = True

        if attempt > 1:
            # Increase delay for subsequent attempts
            adapted["timing_delays"] *= attempt

        return adapted

    def _adapt_for_rate_limit(self, strategy: Dict, result: Dict, attempt: int) -> Dict[str, Any]:
        """Adapt strategy for rate limiting."""
        adapted = strategy.copy()
        adapted["description"] = "Rate limit evasion"

        # Exponential backoff
        delay = min(60, 5 * (2 ** (attempt - 1)))  # Max 60 seconds
        print(f"    [*] Waiting {delay}s to avoid rate limit...")
        time.sleep(delay)

        # Rotate identifiers
        adapted["headers"] = {
            "User-Agent": self._get_legitimate_user_agent(),
            "X-Forwarded-For": self._generate_random_ip(),
            "X-Real-IP": self._generate_random_ip(),
        }

        adapted["use_proxy"] = True  # Suggest using proxy rotation

        return adapted

    def _adapt_for_auth(self, strategy: Dict, result: Dict, attempt: int) -> Dict[str, Any]:
        """Adapt strategy for authentication requirements."""
        adapted = strategy.copy()
        adapted["description"] = "Authentication bypass attempt"

        if attempt == 1:
            # Try default credentials
            adapted["try_default_credentials"] = True
            adapted["default_creds_list"] = [
                ("admin", "admin"),
                ("admin", "password"),
                ("root", "root"),
                ("administrator", "administrator"),
            ]
        elif attempt == 2:
            # Try SQL injection auth bypass
            adapted["auth_bypass_method"] = "sql_injection"
            adapted["sql_payloads"] = ["' OR '1'='1", "admin'--", "' OR 1=1--"]
        else:
            # Try alternative endpoints
            adapted["auth_bypass_method"] = "endpoint_discovery"
            adapted["try_alternate_endpoints"] = True

        return adapted

    def _adapt_for_crash(self, strategy: Dict, result: Dict, attempt: int) -> Dict[str, Any]:
        """Adapt strategy when service crashes."""
        adapted = strategy.copy()
        adapted["description"] = "Service recovery wait"

        # Wait for service to recover
        wait_time = min(30, 10 * attempt)  # Max 30 seconds
        print(f"    [*] Service crashed. Waiting {wait_time}s for recovery...")
        time.sleep(wait_time)

        # Use lighter payload
        adapted["payload_complexity"] = "minimal"
        adapted["reduce_payload_size"] = True

        return adapted

    def _adapt_for_timeout(self, strategy: Dict, result: Dict, attempt: int) -> Dict[str, Any]:
        """Adapt strategy for timeouts."""
        adapted = strategy.copy()
        adapted["description"] = "Timeout mitigation"

        # Increase timeout
        current_timeout = strategy.get("timeout", 30)
        adapted["timeout"] = min(120, current_timeout * 2)

        # Simplify payload
        adapted["payload_complexity"] = "simple"
        adapted["reduce_operations"] = True

        return adapted

    def _adapt_for_payload_detection(
        self, strategy: Dict, result: Dict, attempt: int
    ) -> Dict[str, Any]:
        """Adapt strategy when payload is detected."""
        adapted = strategy.copy()
        adapted["description"] = "Payload obfuscation"

        # Progressive obfuscation
        obfuscation_levels = ["base64", "hex", "unicode", "custom"]
        if attempt <= len(obfuscation_levels):
            adapted["payload_obfuscation"] = obfuscation_levels[attempt - 1]
        else:
            adapted["payload_obfuscation"] = "multi_layer"

        # Add decoy payloads
        adapted["add_decoy_requests"] = True

        return adapted

    def _adapt_for_permission_denied(
        self, strategy: Dict, result: Dict, attempt: int
    ) -> Dict[str, Any]:
        """Adapt strategy for permission denied errors."""
        adapted = strategy.copy()
        adapted["description"] = "Permission escalation attempt"

        if attempt == 1:
            # Try with different user context
            adapted["try_different_user"] = True
        elif attempt == 2:
            # Try privilege escalation technique
            adapted["try_privilege_escalation"] = True
        else:
            # Try alternative access method
            adapted["try_alternate_method"] = True

        return adapted

    def _create_initial_strategy(self, exploit: Dict, service: Dict) -> Dict[str, Any]:
        """Create initial execution strategy."""
        return {
            "description": "Standard execution",
            "exploit_name": exploit.get("name", "unknown"),
            "target_service": service.get("name", "unknown"),
            "payload_encoding": "none",
            "timeout": 30,
            "retries": 0,
            "headers": {},
            "evasion_enabled": False,
        }

    def _execute_exploit_attempt(
        self, target_ip: str, exploit: Dict, service: Dict, strategy: Dict
    ) -> Dict[str, Any]:
        """
        Execute single exploit attempt (mock implementation).

        In real implementation, this would call actual exploit execution.
        """
        # This is a placeholder - actual implementation would execute the exploit
        # For now, simulate success/failure randomly for demonstration

        result = {
            "success": False,
            "error": "",
            "response": "",
            "status_code": 0,
            "shell_obtained": False,
            "privilege_level": "none",
        }

        # Simulate execution (replace with real exploit execution)
        # In real implementation, this would use:
        # - Metasploit wrapper
        # - Custom exploit execution
        # - Service-specific exploits

        return result

    def _get_legitimate_user_agent(self) -> str:
        """Get a legitimate user agent string."""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ]
        return random.choice(user_agents)

    def _generate_random_ip(self) -> str:
        """Generate random IP address."""
        return (
            f"{random.randint(1, 254)}.{random.randint(1, 254)}."
            f"{random.randint(1, 254)}.{random.randint(1, 254)}"
        )


# Convenience function
def execute_with_adaptation(
    target_ip: str, exploit: Dict[str, Any], service: Dict[str, Any], max_attempts: int = 5
) -> Dict[str, Any]:
    """
    Execute exploit with automatic adaptation.

    Args:
        target_ip: Target IP address
        exploit: Exploit configuration
        service: Service details
        max_attempts: Maximum retry attempts

    Returns:
        Execution results with adaptations applied
    """
    engine = AdaptiveStrategy(max_attempts=max_attempts)
    return engine.adaptive_exploit_execution(target_ip, exploit, service)
