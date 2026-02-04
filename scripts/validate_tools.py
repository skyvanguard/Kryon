"""
KRYON Tool Validation Script
==============================

Validates that all required tools and dependencies are available.

Clearance Level: Omega-Command (System Validation)
"""

import importlib
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def check_module(module_name, optional=False):
    """Check if a module can be imported."""
    try:
        importlib.import_module(module_name)
        status = "OK" if not optional else "OK (optional)"
        print(f"[+] {module_name:60s} {status}")
        return True
    except Exception as e:
        status = "MISSING (optional)" if optional else "MISSING"
        print(f"[-] {module_name:60s} {status}: {str(e)[:50]}")
        return not optional  # Return True if optional, False if required


def main():
    print("=" * 80)
    print("KRYON Tool Validation")
    print("=" * 80)
    print()

    # Core autonomous modules (REQUIRED)
    print("[CRITICAL] Core Autonomous Modules:")
    all_ok = True
    all_ok &= check_module("skynet.tools.autonomous")
    all_ok &= check_module("skynet.tools.autonomous.auto_recon")
    all_ok &= check_module("skynet.tools.autonomous.decision_engine")
    all_ok &= check_module("skynet.tools.autonomous.orchestrator")
    all_ok &= check_module("skynet.tools.autonomous.strategic_planner")
    all_ok &= check_module("skynet.tools.autonomous.context_analyzer")
    all_ok &= check_module("skynet.tools.autonomous.learning_engine")
    all_ok &= check_module("skynet.tools.autonomous.adaptive_strategy")
    print()

    # Tool modules (OPTIONAL - will be imported dynamically)
    print("[OPTIONAL] Tool Modules (imported dynamically as needed):")
    check_module("skynet.tools.web.nuclei", optional=True)
    check_module("skynet.tools.web.sqlmap", optional=True)
    check_module("skynet.tools.api_attacks.hydra", optional=True)
    check_module("skynet.tools.exploitation.metasploit_wrapper", optional=True)
    check_module("skynet.tools.exploitation.exploit_db", optional=True)
    check_module("skynet.tools.reconnaissance.gobuster", optional=True)
    check_module("skynet.tools.reconnaissance.netstat", optional=True)
    check_module("skynet.tools.reconnaissance.filesystem", optional=True)
    check_module("skynet.tools.reconnaissance.netcat", optional=True)
    check_module("skynet.tools.privilege_escalation.linux_privesc", optional=True)
    check_module("skynet.tools.privilege_escalation.windows_privesc", optional=True)
    check_module("skynet.tools.ctf.ctf_automation", optional=True)
    check_module("skynet.tools.network.capture_traffic", optional=True)
    check_module("skynet.tools.lateral_movement.remote_execution", optional=True)
    check_module("skynet.tools.lateral_movement.pth_attacks", optional=True)
    check_module("skynet.tools.container.docker_bench", optional=True)
    check_module("skynet.tools.container.kube_hunter", optional=True)
    print()

    # Python standard library dependencies (REQUIRED)
    print("[REQUIRED] Standard Library:")
    all_ok &= check_module("subprocess")
    all_ok &= check_module("json")
    all_ok &= check_module("re")
    all_ok &= check_module("time")
    all_ok &= check_module("socket")
    all_ok &= check_module("ftplib")
    print()

    # Third-party dependencies (OPTIONAL)
    print("[OPTIONAL] Third-Party Libraries:")
    check_module("requests", optional=True)
    check_module("mysql.connector", optional=True)
    print()

    # Test core functions
    print("[TEST] Core Functions:")
    try:
        from skynet.tools.autonomous import (
            select_best_exploit,
        )

        print("[+] All core functions importable")
    except Exception as e:
        print(f"[-] Core function import failed: {e}")
        all_ok = False
    print()

    # Test exploit database
    print("[TEST] Exploit Database:")
    try:
        from skynet.tools.autonomous.decision_engine import EXPLOIT_DATABASE

        services = list(EXPLOIT_DATABASE.keys())
        total_exploits = sum(len(exploits) for exploits in EXPLOIT_DATABASE.values())
        print(f"[+] Exploit database loaded: {len(services)} services, {total_exploits} exploits")
        print(f"    Services: {', '.join(services)}")
    except Exception as e:
        print(f"[-] Exploit database load failed: {e}")
        all_ok = False
    print()

    # Test decision engine
    print("[TEST] Decision Engine:")
    try:
        from skynet.tools.autonomous import select_best_exploit

        result = select_best_exploit("apache", "Apache 2.4.49", difficulty="medium")
        if result["exploit_recommended"]:
            print(f"[+] Decision engine functional: {result['exploit_name']}")
        else:
            print("[!] Decision engine returned no recommendation (unexpected)")
    except Exception as e:
        print(f"[-] Decision engine test failed: {e}")
        all_ok = False
    print()

    # Summary
    print("=" * 80)
    if all_ok:
        print("[SUCCESS] All REQUIRED modules are available")
        print()
        print("Note: Some OPTIONAL tools are missing but will be handled gracefully")
        print("      when needed. The autonomous system will work with fallbacks.")
        return 0
    else:
        print("[FAILURE] Some REQUIRED modules are missing")
        print()
        print("Please ensure KRYON is properly installed:")
        print("  pip install -e .")
        return 1


if __name__ == "__main__":
    sys.exit(main())
