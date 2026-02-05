#!/usr/bin/env python3
"""
KRYON Pre-Commit Validation Script

Quick validation script to run before committing changes.
Checks imports, runs fast tests, and validates code quality.
"""

import importlib
import subprocess
import sys
import time
from pathlib import Path


def print_header(text):
    """Print formatted header"""
    print(f"\n{'=' * 60}")
    print(f"  {text}")
    print("=" * 60)


def print_status(status, message):
    """Print status message with emoji"""
    emoji = "✅" if status else "❌"
    print(f"{emoji} {message}")


def check_imports():
    """Verify all critical modules can be imported"""
    print_header("CHECKING IMPORTS")

    critical_modules = [
        "kryon.agents.t800_infiltrator",
        "kryon.agents.ctf_master",
        "kryon.agents.central_core",
        "kryon.tools.ctf.ctf_automation",
        "kryon.tools.ctf.tryhackme_helpers",
        "kryon.tools.privilege_escalation.linux_privesc",
    ]

    failed = []
    for module in critical_modules:
        try:
            importlib.import_module(module)
            print_status(True, f"Imported {module}")
        except Exception as e:
            print_status(False, f"Failed to import {module}: {e}")
            failed.append(module)

    return len(failed) == 0


def run_quick_tests():
    """Run quick unit tests (no integration tests)"""
    print_header("RUNNING QUICK TESTS")

    try:
        result = subprocess.run(
            [
                "pytest",
                "tests/",
                "-v",
                "-m",
                "not integration and not slow",
                "--tb=short",
                "-x",  # Stop on first failure
                "--maxfail=5",  # Stop after 5 failures
            ],
            capture_output=True,
            text=True,
            timeout=120,  # 2 minute timeout
        )

        print(result.stdout)

        if result.returncode == 0:
            print_status(True, "All quick tests passed")
            return True
        else:
            print_status(False, "Some tests failed")
            print(result.stderr)
            return False

    except subprocess.TimeoutExpired:
        print_status(False, "Tests timed out")
        return False
    except FileNotFoundError:
        print_status(False, "pytest not found - install with: pip install pytest")
        return False


def check_code_quality():
    """Run basic code quality checks"""
    print_header("CHECKING CODE QUALITY")

    all_passed = True

    # Check for common issues with flake8
    try:
        result = subprocess.run(
            ["flake8", "src/kryon", "--select=E9,F63,F7,F82", "--count"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode == 0:
            print_status(True, "Flake8 critical checks passed")
        else:
            print_status(False, "Flake8 found critical issues")
            print(result.stdout)
            all_passed = False

    except FileNotFoundError:
        print_status(False, "flake8 not found (optional)")

    # Check for security issues with bandit
    try:
        result = subprocess.run(["bandit", "-r", "src/kryon", "-ll", "-q"], capture_output=True, text=True, timeout=60)

        if result.returncode == 0:
            print_status(True, "Bandit security scan passed")
        else:
            print_status(False, "Bandit found security issues")
            print(result.stdout)
            all_passed = False

    except FileNotFoundError:
        print_status(False, "bandit not found (optional)")

    return all_passed


def check_documentation():
    """Verify critical documentation exists"""
    print_header("CHECKING DOCUMENTATION")

    required_docs = [
        "README.md",
        "docs/CLEARANCE_LEVELS.md",
        "docs/sessions/SESSION_TRYHACKME_CTF_OPTIMIZATION.md",
        "docs/sessions/PROJECT_GAP_ANALYSIS.md",
    ]

    all_exist = True
    for doc in required_docs:
        path = Path(doc)
        if path.exists():
            print_status(True, f"Found {doc}")
        else:
            print_status(False, f"Missing {doc}")
            all_exist = False

    return all_exist


def check_agent_prompts():
    """Verify agent prompt files exist"""
    print_header("CHECKING AGENT PROMPTS")

    critical_prompts = [
        "src/kryon/prompts/system_t800_infiltrator.md",
        "src/kryon/prompts/system_ctf_master.md",
        "src/kryon/prompts/system_central_core.md",
        "src/kryon/prompts/system_guardian_protocol.md",
    ]

    all_exist = True
    for prompt in critical_prompts:
        path = Path(prompt)
        if path.exists():
            # Check file has content
            if path.stat().st_size > 100:
                print_status(True, f"Found {path.name}")
            else:
                print_status(False, f"{path.name} is too small")
                all_exist = False
        else:
            print_status(False, f"Missing {path.name}")
            all_exist = False

    return all_exist


def main():
    """Run all validation checks"""
    print("""
    ██╗  ██╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗
    ██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║
    █████╔╝ ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║
    ██╔═██╗ ██╔══██╗  ╚██╔╝  ██║   ██║██║╚██╗██║
    ██║  ██╗██║  ██║   ██║   ╚██████╔╝██║ ╚████║
    ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝

            PRE-COMMIT VALIDATION SUITE
    """)

    start_time = time.time()

    # Run all checks
    results = {
        "Imports": check_imports(),
        "Quick Tests": run_quick_tests(),
        "Code Quality": check_code_quality(),
        "Documentation": check_documentation(),
        "Agent Prompts": check_agent_prompts(),
    }

    # Summary
    print_header("VALIDATION SUMMARY")

    all_passed = True
    for check, passed in results.items():
        print_status(passed, check)
        if not passed:
            all_passed = False

    elapsed = time.time() - start_time
    print(f"\nCompleted in {elapsed:.2f} seconds")

    if all_passed:
        print("\n🎉 ALL CHECKS PASSED - Ready to commit!")
        return 0
    else:
        print("\n⚠️  SOME CHECKS FAILED - Fix issues before committing")
        return 1


if __name__ == "__main__":
    sys.exit(main())
