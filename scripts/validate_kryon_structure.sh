#!/bin/bash
#
# KRYON Framework - Structure Validation Script
# ===============================================
# Validates all critical files and directories exist

echo "======================================================================"
echo "KRYON FRAMEWORK - STRUCTURE VALIDATION"
echo "======================================================================"
echo ""

PASSED=0
FAILED=0

# Function to check if file/directory exists
check_exists() {
    local path="$1"
    local description="$2"

    if [ -e "$path" ]; then
        echo "✓ PASS: $description"
        ((PASSED++))
        return 0
    else
        echo "✗ FAIL: $description"
        echo "   Path: $path (NOT FOUND)"
        ((FAILED++))
        return 1
    fi
}

echo "======================================================================"
echo "TEST 1: CORE INFRASTRUCTURE"
echo "======================================================================"
echo ""

check_exists "src/kryon/__init__.py" "Core KRYON package"
check_exists "src/kryon/sdk" "KRYON SDK directory"
check_exists "src/kryon/tools" "KRYON Tools directory"
check_exists "src/kryon/prompts" "KRYON Prompts directory"
check_exists "src/kryon/agents" "KRYON Agents directory"
check_exists "pyproject.toml" "Package configuration"

echo ""
echo "======================================================================"
echo "TEST 2: SYSTEM PROMPTS"
echo "======================================================================"
echo ""

check_exists "src/kryon/prompts/system_pentest_agent.md" "Pentest Agent prompt"
check_exists "src/kryon/prompts/system_recon_scout.md" "Recon Scout prompt"
check_exists "src/kryon/prompts/system_vuln_hunter.md" "Vuln Hunter prompt"
check_exists "src/kryon/prompts/system_ctf_master.md" "CTF Master prompt"
check_exists "src/kryon/prompts/system_central_core.md" "Central Core prompt"
check_exists "src/kryon/prompts/system_guardian_protocol.md" "Guardian Protocol prompt"
check_exists "src/kryon/prompts/system_forensic_analyzer.md" "Forensic Analyzer prompt"
check_exists "src/kryon/prompts/system_strategic_core.md" "Strategic Core prompt"
check_exists "src/kryon/prompts/system_network_analyzer.md" "Network Analyst prompt"
check_exists "src/kryon/prompts/system_mobile_infiltrator.md" "Mobile Infiltrator prompt"
check_exists "src/kryon/prompts/system_chrome_infiltrator.md" "Chrome Infiltrator prompt"
check_exists "src/kryon/prompts/system_wireless_infiltrator.md" "Wireless Infiltrator prompt"
check_exists "src/kryon/prompts/system_rf_analyzer.md" "RF Analyzer prompt"
check_exists "src/kryon/prompts/system_reporting_agent.md" "Intel Reporter prompt"
check_exists "src/kryon/prompts/system_memory_analyst.md" "Memory Analyst prompt"
check_exists "src/kryon/prompts/system_mission_analyst.md" "Mission Analyst prompt"

echo ""
echo "======================================================================"
echo "TEST 3: KEY TOOL CATEGORIES"
echo "======================================================================"
echo ""

check_exists "src/kryon/tools/exploitation" "Exploitation tools"
check_exists "src/kryon/tools/privilege_escalation" "Privilege escalation tools"
check_exists "src/kryon/tools/lateral_movement" "Lateral movement tools"
check_exists "src/kryon/tools/data_exfiltration" "Data exfiltration tools"
check_exists "src/kryon/tools/ctf" "CTF tools"
check_exists "src/kryon/tools/recon" "Reconnaissance tools"

echo ""
echo "======================================================================"
echo "TEST 4: DOCUMENTATION"
echo "======================================================================"
echo ""

check_exists "README.md" "README"
check_exists "CONTRIBUTING.md" "Contributing guide"
check_exists "LICENSE" "License file"
check_exists "DISCLAIMER" "Legal disclaimer"

echo ""
echo "======================================================================"
echo "TEST RESULTS SUMMARY"
echo "======================================================================"
echo ""

TOTAL=$((PASSED + FAILED))
if [ $TOTAL -gt 0 ]; then
    PASS_RATE=$(echo "scale=1; $PASSED * 100 / $TOTAL" | bc)
else
    PASS_RATE="0"
fi

echo "Total Tests: $TOTAL"
echo "Passed: $PASSED ($PASS_RATE%)"
echo "Failed: $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "ALL TESTS PASSED!"
    exit 0
else
    echo "Some tests failed. Review missing files above."
    exit 1
fi
