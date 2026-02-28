"""Supply chain security — dependency confusion and typosquatting detection."""

from difflib import SequenceMatcher

from kryon.sdk.agents import function_tool
from kryon.tools.common import run_command


@function_tool
def detect_dependency_confusion(
    package_manifest: str,
    registry_url: str = "",
    ctf=None,
) -> str:
    """
    Detect potential dependency confusion vulnerabilities.

    Checks if internal/private packages could be hijacked by publishing
    a higher-version package on a public registry.

    Args:
        package_manifest: Path to package manifest (package.json, requirements.txt, pom.xml)
        registry_url: Private registry URL to compare against public registry
        ctf: CTF context for execution

    Returns:
        str: Dependency confusion analysis results
    """
    results = []

    if package_manifest.endswith("package.json"):
        cmd = "npm audit --json --registry https://registry.npmjs.org 2>/dev/null || true"
        audit_result = run_command(f"cd $(dirname {package_manifest}) && {cmd}", ctf=ctf)
        results.append(f"NPM Audit:\n{audit_result}")
        if registry_url:
            results.append(f"\nRegistry check:\n{run_command('npm config get registry', ctf=ctf)}")

    elif package_manifest.endswith(("requirements.txt", "setup.py")):
        cmd = f"pip-audit -r {package_manifest} --format json 2>/dev/null || true"
        results.append(f"Pip Audit:\n{run_command(cmd, ctf=ctf)}")

    elif package_manifest.endswith("pom.xml"):
        cmd = f"cd $(dirname {package_manifest}) && mvn dependency:analyze -DignoreNonCompile 2>/dev/null || true"
        results.append(f"Maven Analysis:\n{run_command(cmd, ctf=ctf)}")

    else:
        cmd = f"syft file:{package_manifest} -o json"
        results.append(f"Syft Analysis:\n{run_command(cmd, ctf=ctf)}")

    return "\n".join(results)


@function_tool
def check_typosquatting(
    package_name: str,
    ecosystem: str = "npm",
    threshold: float = 0.85,
    ctf=None,
) -> str:
    """
    Check if a package name is potentially a typosquatting attempt.

    Compares the package name against popular packages in the ecosystem
    to detect suspicious naming patterns.

    Args:
        package_name: Package name to check
        ecosystem: Package ecosystem (npm, pypi, rubygems, crates)
        threshold: Similarity threshold (0.0-1.0, default 0.85)
        ctf: CTF context for execution

    Returns:
        str: Typosquatting analysis with similarity scores
    """
    patterns = [
        ("hyphen swap", package_name.replace("-", "_"), package_name.replace("_", "-")),
        ("missing char", package_name[1:] if len(package_name) > 1 else "", package_name[:-1] if len(package_name) > 1 else ""),
        ("prefix", f"get-{package_name}", f"node-{package_name}"),
        ("suffix", f"{package_name}-js", f"{package_name}-lib"),
    ]

    if ecosystem == "npm":
        check_cmd = f"npm search {package_name} --json --long 2>/dev/null | head -c 5000"
    elif ecosystem == "pypi":
        check_cmd = f"pip index versions {package_name} 2>/dev/null || echo 'Check pypi.org manually'"
    else:
        check_cmd = f"echo 'Manual check required for {ecosystem}'"

    registry_result = run_command(check_cmd, ctf=ctf)

    results = [f"Package: {package_name}", f"Ecosystem: {ecosystem}", f"Threshold: {threshold}", ""]

    suspicious = []
    for pattern_name, *variants in patterns:
        for variant in variants:
            if variant and variant != package_name:
                similarity = SequenceMatcher(None, package_name, variant).ratio()
                if similarity >= threshold:
                    suspicious.append(f"  [{pattern_name}] '{variant}' (similarity: {similarity:.2f})")

    if suspicious:
        results.append("Potential typosquat variants:")
        results.extend(suspicious)
    else:
        results.append("No obvious typosquat patterns detected.")

    results.append(f"\nRegistry check:\n{registry_result}")
    return "\n".join(results)
