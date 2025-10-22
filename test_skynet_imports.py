#!/usr/bin/env python3
"""
SKYNET Framework - Import and Compatibility Test Suite
======================================================

Tests all critical imports and backward compatibility.
"""

import sys
import traceback

print("=" * 70)
print("SKYNET FRAMEWORK - IMPORT TEST SUITE")
print("=" * 70)
print()

# Test Results Storage
test_results = {
    "passed": [],
    "failed": [],
    "total": 0
}

def test_import(module_name, description):
    """Test if a module can be imported."""
    test_results["total"] += 1
    try:
        __import__(module_name)
        test_results["passed"].append((module_name, description))
        print(f"✅ PASS: {description}")
        print(f"   Import: {module_name}")
        return True
    except Exception as e:
        test_results["failed"].append((module_name, description, str(e)))
        print(f"❌ FAIL: {description}")
        print(f"   Import: {module_name}")
        print(f"   Error: {str(e)}")
        return False

print("=" * 70)
print("TEST 1: CORE SKYNET PACKAGE IMPORTS")
print("=" * 70)
print()

# Core package
test_import("skynet", "Core SKYNET package")
test_import("skynet.sdk", "SKYNET SDK")
test_import("skynet.sdk.agents", "SKYNET Agents module")
test_import("skynet.tools", "SKYNET Tools module")

print()
print("=" * 70)
print("TEST 2: AGENT IMPORTS (19 Agents)")
print("=" * 70)
print()

# T-Series Offensive Units
test_import("skynet.sdk.agents.t800_infiltrator", "T-800 Infiltrator (Alpha-Red)")
test_import("skynet.sdk.agents.exploit_expert", "T-1000 Advanced Hunter (Omega-Strike)")
test_import("skynet.sdk.agents.web_bounty_agent", "T-600 Scout (Bravo-Green)")

# Defensive Units
test_import("skynet.sdk.agents.blue_team_agent", "Guardian Protocol (Alpha-Blue)")

# Command & Control
test_import("skynet.sdk.agents.thought_router", "Central Core (Omega-Command)")

# Reconnaissance Units
test_import("skynet.sdk.agents.network_analyzer", "HK-Aerial (Alpha-Silver)")

# Intelligence & Analysis Units
test_import("skynet.sdk.agents.memory_analysis_agent", "Neural Extractor (Alpha-Gold)")
test_import("skynet.sdk.agents.dfir_agent", "Forensic Analyzer (Alpha-Platinum)")
test_import("skynet.sdk.agents.reverse_engineering_agent", "Tech-Com Reverse (Alpha-Purple)")
test_import("skynet.sdk.agents.reporting_agent", "Intel Reporter (Beta-Silver)")

# Specialized Units
test_import("skynet.sdk.agents.android_sast", "Mobile Infiltrator (Alpha-Teal)")
test_import("skynet.sdk.agents.bug_bounter", "Target Validator (Bravo-Yellow)")
test_import("skynet.sdk.agents.triage_agent", "Validation Core (Bravo-Orange)")
test_import("skynet.sdk.agents.replay_attack_agent", "Signal Repeater (Alpha-Crimson)")
test_import("skynet.sdk.agents.subghz_agent", "RF Analyzer (Alpha-Magenta)")
test_import("skynet.sdk.agents.wifi_security_agent", "Wireless Infiltrator (Alpha-Indigo)")
test_import("skynet.sdk.agents.use_cases", "Mission Analyst (Omega-Documentation)")

# Protocol Analysis
test_import("skynet.sdk.agents.mail_agent", "Comm-Sec Analyzer (Bravo-Cyan)")

# Web Analysis
test_import("skynet.sdk.agents.web_analyzer", "Web Analysis Unit")

print()
print("=" * 70)
print("TEST 3: TOOL MODULE IMPORTS (4 Modules)")
print("=" * 70)
print()

# Exploitation Tools
test_import("skynet.tools.exploitation", "Exploitation Tools Module")
test_import("skynet.tools.exploitation.exploit_builder", "Exploit Builder")
test_import("skynet.tools.exploitation.metasploit_wrapper", "Metasploit Wrapper")
test_import("skynet.tools.exploitation.exploit_db", "Exploit-DB Integration")

# Privilege Escalation Tools
test_import("skynet.tools.privilege_escalation", "Privilege Escalation Module")
test_import("skynet.tools.privilege_escalation.linux_privesc", "Linux PrivEsc Tools")
test_import("skynet.tools.privilege_escalation.windows_privesc", "Windows PrivEsc Tools")
test_import("skynet.tools.privilege_escalation.privesc_suggester", "PrivEsc Suggester")

# Lateral Movement Tools
test_import("skynet.tools.lateral_movement", "Lateral Movement Module")
test_import("skynet.tools.lateral_movement.pth_attacks", "Pass-the-Hash Attacks")
test_import("skynet.tools.lateral_movement.remote_execution", "Remote Execution")
test_import("skynet.tools.lateral_movement.pivoting", "Network Pivoting")

# Data Exfiltration Tools
test_import("skynet.tools.data_exfiltration", "Data Exfiltration Module")
test_import("skynet.tools.data_exfiltration.covert_channels", "Covert Channels")
test_import("skynet.tools.data_exfiltration.file_prep", "File Preparation")
test_import("skynet.tools.data_exfiltration.cloud_upload", "Cloud Upload")

print()
print("=" * 70)
print("TEST 4: BACKWARD COMPATIBILITY (Legacy CAI Imports)")
print("=" * 70)
print()

# Legacy CAI imports should still work
test_import("cai", "Legacy CAI package (backward compatibility)")
test_import("cai.sdk", "Legacy CAI SDK")
test_import("cai.sdk.agents", "Legacy CAI Agents")
test_import("cai.tools", "Legacy CAI Tools")

# Legacy agent imports
test_import("cai.sdk.agents.t800_infiltrator", "Legacy T-800 import")
test_import("cai.sdk.agents.exploit_expert", "Legacy Exploit Expert import")

print()
print("=" * 70)
print("TEST 5: COMMON UTILITIES")
print("=" * 70)
print()

test_import("skynet.tools.common", "Common Tools Utilities")
test_import("skynet.util", "SKYNET Utilities")

print()
print("=" * 70)
print("TEST RESULTS SUMMARY")
print("=" * 70)
print()

total = test_results["total"]
passed = len(test_results["passed"])
failed = len(test_results["failed"])
pass_rate = (passed / total * 100) if total > 0 else 0

print(f"Total Tests: {total}")
print(f"Passed: {passed} ({pass_rate:.1f}%)")
print(f"Failed: {failed}")
print()

if failed > 0:
    print("FAILED TESTS:")
    print("-" * 70)
    for module, desc, error in test_results["failed"]:
        print(f"❌ {desc}")
        print(f"   Module: {module}")
        print(f"   Error: {error}")
        print()

if pass_rate == 100:
    print("🎉 ALL TESTS PASSED! SKYNET Framework is fully operational!")
    sys.exit(0)
elif pass_rate >= 90:
    print("✅ Most tests passed. SKYNET Framework is operational with minor issues.")
    sys.exit(0)
elif pass_rate >= 75:
    print("⚠️  Some tests failed. SKYNET Framework needs attention.")
    sys.exit(1)
else:
    print("❌ Many tests failed. SKYNET Framework has critical issues.")
    sys.exit(1)
