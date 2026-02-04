#!/usr/bin/env python3
"""
KRYON Import Update Script
============================

This script automatically updates all imports from 'skynet' to 'skynet' across
the entire codebase. It also updates environment variables and other references.

Usage:
    python scripts/update_imports.py [--dry-run] [--verbose]

Options:
    --dry-run: Show what would be changed without making changes
    --verbose: Show detailed output
"""

import re
import sys
from pathlib import Path

# Color codes for terminal output
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"

# Import mapping for agent renames
AGENT_RENAMES = {
    "red_teamer": "t800_infiltrator",
    "redteam_agent": "t800_infiltrator",
    "bug_bounter": "t1000_hunter",
    "one_tool": "t600_scout",
    "one_tool_agent": "t600_scout",
    "blue_teamer": "guardian_protocol",
    "blueteam_agent": "guardian_protocol",
    "dfir": "forensic_analyzer",
    "dfir_agent": "forensic_analyzer",
    "network_traffic_analyzer": "hk_aerial",
    "memory_analysis_agent": "neural_extractor",
    "reverse_engineering_agent": "tech_com_reverse",
    "android_sast_agent": "mobile_infiltrator",
    "thought": "central_core",
    "thought_agent": "central_core",
    "flag_discriminator": "target_validator",
    "replay_attack_agent": "signal_repeater",
    "subghz_sdr_agent": "rf_analyzer",
    "wifi_security_tester": "wireless_infiltrator",
    "usecase": "mission_analyst",
}


def update_file(file_path: Path, dry_run: bool = False, verbose: bool = False) -> tuple[int, list[str]]:
    """
    Update imports and references in a single file.

    Returns:
        Tuple of (number of changes, list of change descriptions)
    """
    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        if verbose:
            print(f"{RED}Error reading {file_path}: {e}{RESET}")
        return 0, []

    original_content = content
    changes = []

    # 1. Update imports: from skynet. -> from skynet.
    pattern1 = r"from skynet\."
    if re.search(pattern1, content):
        content = re.sub(pattern1, "from skynet.", content)
        changes.append("Updated: 'from skynet.' → 'from skynet.'")

    # 2. Update imports: import skynet. -> import skynet.
    pattern2 = r"import skynet\."
    if re.search(pattern2, content):
        content = re.sub(pattern2, "import skynet.", content)
        changes.append("Updated: 'import skynet.' → 'import skynet.'")

    # 3. Update environment variables: SKYNET_ -> SKYNET_
    pattern3 = r"\bSKYNET_([A-Z_]+)\b"
    skynet_vars = re.findall(pattern3, content)
    if skynet_vars:
        # Keep SKYNET_MODEL as a fallback option, so add SKYNET_MODEL check first
        content = re.sub(
            r'os\.getenv\(["\']SKYNET_MODEL["\']\)',
            'os.getenv("SKYNET_MODEL", os.getenv("SKYNET_MODEL", "gpt-4o"))',
            content,
        )
        # Update other SKYNET_ variables
        content = re.sub(pattern3, r"SKYNET_\1", content)
        changes.append(f"Updated {len(set(skynet_vars))} environment variable(s)")

    # 4. Update agent variable names
    for old_name, new_name in AGENT_RENAMES.items():
        # Update variable assignments and references
        pattern = rf"\b{old_name}\b"
        if re.search(pattern, content):
            content = re.sub(pattern, new_name, content)
            changes.append(f"Updated agent reference: '{old_name}' → '{new_name}'")

    # 5. Update transfer functions
    pattern5 = r"transfer_to_redteam_agent"
    if re.search(pattern5, content):
        content = re.sub(pattern5, "transfer_to_t800", content)
        changes.append("Updated: 'transfer_to_redteam_agent' → 'transfer_to_t800'")

    # 6. Update prompt file references
    pattern6 = r"prompts/system_red_team_agent\.md"
    if re.search(pattern6, content):
        content = re.sub(pattern6, "prompts/system_t800_infiltrator.md", content)
        changes.append("Updated prompt path for T-800")

    # Write changes if not dry run
    if content != original_content:
        if not dry_run:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
            except Exception as e:
                if verbose:
                    print(f"{RED}Error writing {file_path}: {e}{RESET}")
                return 0, []

        return len(changes), changes

    return 0, []


def process_directory(directory: Path, dry_run: bool = False, verbose: bool = False):
    """Process all Python files in a directory recursively."""

    python_files = list(directory.rglob("*.py"))
    md_files = list(directory.rglob("*.md"))
    yaml_files = list(directory.rglob("*.yml")) + list(directory.rglob("*.yaml"))

    all_files = python_files + md_files + yaml_files

    total_files = len(all_files)
    total_changes = 0
    files_modified = 0

    print(f"\n{BLUE}{'=' * 60}{RESET}")
    print(f"{BLUE}KRYON Import Update Script{RESET}")
    print(f"{BLUE}{'=' * 60}{RESET}\n")

    if dry_run:
        print(f"{YELLOW}[DRY RUN MODE - No files will be modified]{RESET}\n")

    print(f"Found {total_files} files to process\n")

    for i, file_path in enumerate(all_files, 1):
        relative_path = file_path.relative_to(directory)

        if verbose:
            print(f"[{i}/{total_files}] Processing: {relative_path}")

        num_changes, changes = update_file(file_path, dry_run, verbose)

        if num_changes > 0:
            files_modified += 1
            total_changes += num_changes
            print(f"{GREEN}OK{RESET} {relative_path} ({num_changes} change(s))")
            if verbose:
                for change in changes:
                    print(f"  - {change}")
        elif verbose:
            print("  No changes needed")

    # Print summary
    print(f"\n{BLUE}{'=' * 60}{RESET}")
    print(f"{BLUE}Summary{RESET}")
    print(f"{BLUE}{'=' * 60}{RESET}")
    print(f"Total files processed: {total_files}")
    print(f"Files modified: {GREEN}{files_modified}{RESET}")
    print(f"Total changes: {GREEN}{total_changes}{RESET}")

    if dry_run:
        print(f"\n{YELLOW}This was a dry run. Re-run without --dry-run to apply changes.{RESET}")
    else:
        print(f"\n{GREEN}SUCCESS: All changes applied successfully!{RESET}")

    print(f"{BLUE}{'=' * 60}{RESET}\n")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Update imports from SKYNET to KRYON across the codebase")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be changed without making changes")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")
    parser.add_argument(
        "--directory",
        "-d",
        type=Path,
        default=Path.cwd(),
        help="Directory to process (default: current directory)",
    )

    args = parser.parse_args()

    if not args.directory.exists():
        print(f"{RED}Error: Directory {args.directory} does not exist{RESET}")
        sys.exit(1)

    process_directory(args.directory, args.dry_run, args.verbose)


if __name__ == "__main__":
    main()
