#!/bin/bash
#
# SKYNET Framework - Structure Validation Script
# ===============================================
# Validates all critical files and directories exist

echo "======================================================================"
echo "SKYNET FRAMEWORK - STRUCTURE VALIDATION"
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
        echo "   Path: $path"
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

check_exists "src/skynet/__init__.py" "Core SKYNET package"
check_exists "src/skynet/sdk" "SKYNET SDK directory"
check_exists "src/skynet/tools" "SKYNET Tools directory"
check_exists "src/skynet/prompts" "SKYNET Prompts directory"
check_exists "pyproject.toml" "Package configuration"

echo ""
echo "======================================================================"
echo "TEST 2: SYSTEM PROMPTS (17 Prompts)"
echo "======================================================================"
echo ""

check_exists "src/skynet/prompts/system_t800_infiltrator.md" "T-800 Infiltrator prompt"
check_exists "src/skynet/prompts/system_exploit_expert.md" "T-1000 Advanced Hunter prompt"
check_exists "src/skynet/prompts/system_web_bounty_agent.md" "T-600 Scout prompt"
check_exists "src/skynet/prompts/system_blue_team_agent.md" "Guardian Protocol prompt"
check_exists "src/skynet/prompts/system_thought_router.md" "Central Core prompt"
check_exists "src/skynet/prompts/system_network_analyzer.md" "HK-Aerial prompt"
check_exists "src/skynet/prompts/memory_analysis_agent.md" "Neural Extractor prompt"
check_exists "src/skynet/prompts/system_dfir_agent.md" "Forensic Analyzer prompt"
check_exists "src/skynet/prompts/reverse_engineering_agent.md" "Tech-Com Reverse prompt"
check_exists "src/skynet/prompts/system_reporting_agent.md" "Intel Reporter prompt"
check_exists "src/skynet/prompts/system_android_sast.md" "Mobile Infiltrator prompt"
check_exists "src/skynet/prompts/system_bug_bounter.md" "Target Validator prompt"
check_exists "src/skynet/prompts/system_triage_agent.md" "Validation Core prompt"
check_exists "src/skynet/prompts/system_replay_attack_agent.md" "Signal Repeater prompt"
check_exists "src/skynet/prompts/subghz_agent.md" "RF Analyzer prompt"
check_exists "src/skynet/prompts/wifi_security_agent.md" "Wireless Infiltrator prompt"
check_exists "src/skynet/prompts/system_use_cases.md" "Mission Analyst prompt"

echo ""
echo "======================================================================"
echo "TEST 3: EXPLOITATION TOOLS"
echo "======================================================================"
echo ""

check_exists "src/skynet/tools/exploitation" "Exploitation tools directory"
check_exists "src/skynet/tools/exploitation/__init__.py" "Exploitation module init"
check_exists "src/skynet/tools/exploitation/exploit_builder.py" "Exploit Builder"
check_exists "src/skynet/tools/exploitation/metasploit_wrapper.py" "Metasploit Wrapper"
check_exists "src/skynet/tools/exploitation/exploit_db.py" "Exploit-DB Integration"

echo ""
echo "======================================================================"
echo "TEST 4: PRIVILEGE ESCALATION TOOLS"
echo "======================================================================"
echo ""

check_exists "src/skynet/tools/privilege_escalation" "Privilege escalation directory"
check_exists "src/skynet/tools/privilege_escalation/__init__.py" "PrivEsc module init"
check_exists "src/skynet/tools/privilege_escalation/linux_privesc.py" "Linux PrivEsc"
check_exists "src/skynet/tools/privilege_escalation/windows_privesc.py" "Windows PrivEsc"
check_exists "src/skynet/tools/privilege_escalation/privesc_suggester.py" "PrivEsc Suggester"

echo ""
echo "======================================================================"
echo "TEST 5: LATERAL MOVEMENT TOOLS"
echo "======================================================================"
echo ""

check_exists "src/skynet/tools/lateral_movement" "Lateral movement directory"
check_exists "src/skynet/tools/lateral_movement/__init__.py" "Lateral movement init"
check_exists "src/skynet/tools/lateral_movement/pth_attacks.py" "Pass-the-Hash attacks"
check_exists "src/skynet/tools/lateral_movement/remote_execution.py" "Remote execution"
check_exists "src/skynet/tools/lateral_movement/pivoting.py" "Network pivoting"

echo ""
echo "======================================================================"
echo "TEST 6: DATA EXFILTRATION TOOLS"
echo "======================================================================"
echo ""

check_exists "src/skynet/tools/data_exfiltration" "Data exfiltration directory"
check_exists "src/skynet/tools/data_exfiltration/__init__.py" "Exfiltration module init"
check_exists "src/skynet/tools/data_exfiltration/covert_channels.py" "Covert channels"
check_exists "src/skynet/tools/data_exfiltration/file_prep.py" "File preparation"
check_exists "src/skynet/tools/data_exfiltration/cloud_upload.py" "Cloud upload"

echo ""
echo "======================================================================"
echo "TEST 7: DOCUMENTATION"
echo "======================================================================"
echo ""

check_exists "README.md" "Primary README (SKYNET)"
check_exists "README-CAI-LEGACY.md" "Legacy README (archived)"
check_exists "docs/skynet" "SKYNET documentation directory"
check_exists "docs/skynet_installation.md" "SKYNET installation guide"
check_exists "docs/skynet_quickstart.md" "SKYNET quickstart guide"
check_exists "docs/skynet_architecture.md" "SKYNET architecture docs"

echo ""
echo "======================================================================"
echo "TEST 8: SESSION REPORTS"
echo "======================================================================"
echo ""

check_exists "POST_TRANSFORMATION_ANALYSIS.md" "Post-transformation analysis"
check_exists "SESSION_6_COMPLETION_REPORT.md" "Session 6 report"
check_exists "SESSION_7_COMPLETION_REPORT.md" "Session 7 report"
check_exists "SESSION_8_COMPLETION_REPORT.md" "Session 8 report"

echo ""
echo "======================================================================"
echo "TEST RESULTS SUMMARY"
echo "======================================================================"
echo ""

TOTAL=$((PASSED + FAILED))
PASS_RATE=$(echo "scale=1; $PASSED * 100 / $TOTAL" | bc)

echo "Total Tests: $TOTAL"
echo "Passed: $PASSED ($PASS_RATE%)"
echo "Failed: $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "🎉 ALL TESTS PASSED! SKYNET Framework structure is complete!"
    exit 0
elif [ $(echo "$PASS_RATE >= 90" | bc) -eq 1 ]; then
    echo "✓ Most tests passed. SKYNET Framework structure is solid."
    exit 0
else
    echo "✗ Some tests failed. SKYNET Framework has structural issues."
    exit 1
fi
