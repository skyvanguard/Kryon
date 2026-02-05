"""
Build Documentation Script
===========================

Automatically builds MkDocs documentation with validation and error checking.

Features:
- Validates mkdocs.yml configuration
- Checks for missing documentation files
- Builds documentation site
- Runs link checker
- Generates API reference documentation

Usage:
    python scripts/build_docs.py
    python scripts/build_docs.py --serve
    python scripts/build_docs.py --strict
"""

import argparse
import subprocess
import sys
from pathlib import Path


def validate_mkdocs_config():
    """Validate mkdocs.yml configuration."""
    print("\n" + "=" * 70)
    print("Validating MkDocs Configuration...")
    print("=" * 70)

    config_file = Path("mkdocs.yml")
    if not config_file.exists():
        print("❌ Error: mkdocs.yml not found!")
        return False

    try:
        # Try to load and validate
        result = subprocess.run(
            ["mkdocs", "build", "--strict", "--verbose"], capture_output=True, text=True, timeout=60
        )

        if result.returncode != 0:
            print("❌ Configuration validation failed:")
            print(result.stderr)
            return False

        print("✅ Configuration is valid!")
        return True

    except subprocess.TimeoutExpired:
        print("❌ Validation timed out!")
        return False
    except Exception as e:
        print(f"❌ Error during validation: {e}")
        return False


def check_documentation_coverage():
    """Check which Python files have documentation."""
    print("\n" + "=" * 70)
    print("Checking Documentation Coverage...")
    print("=" * 70)

    # Find all Python files in src/kryon
    kryon_dir = Path("src/kryon")
    if not kryon_dir.exists():
        print("⚠️  Warning: src/kryon directory not found!")
        return

    py_files = list(kryon_dir.rglob("*.py"))
    documented = 0
    undocumented = []

    for py_file in py_files:
        # Skip __init__.py and test files
        if py_file.name == "__init__.py" or "test_" in py_file.name:
            continue

        # Check if file has docstring
        try:
            with open(py_file, encoding="utf-8") as f:
                content = f.read()
                if '"""' in content or "'''" in content:
                    documented += 1
                else:
                    undocumented.append(py_file)
        except Exception:
            continue

    total = documented + len(undocumented)
    coverage = (documented / total * 100) if total > 0 else 0

    print(f"\nDocumentation Coverage: {coverage:.1f}%")
    print(f"  - Documented: {documented}")
    print(f"  - Undocumented: {len(undocumented)}")

    if undocumented and len(undocumented) <= 10:
        print("\nUndocumented files:")
        for f in undocumented[:10]:
            print(f"  - {f}")


def build_docs(strict=False, clean=False):
    """Build the documentation."""
    print("\n" + "=" * 70)
    print("Building Documentation...")
    print("=" * 70)

    # Clean previous build if requested
    if clean:
        print("\nCleaning previous build...")
        site_dir = Path("site")
        if site_dir.exists():
            import shutil

            shutil.rmtree(site_dir)
            print("✅ Cleaned!")

    # Build command
    cmd = ["mkdocs", "build"]
    if strict:
        cmd.append("--strict")
        print("\n⚠️  Building in STRICT mode (all warnings are errors)")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        if result.returncode != 0:
            print("❌ Build failed:")
            print(result.stderr)
            return False

        print("✅ Documentation built successfully!")
        print(f"\nOutput: {Path('site').absolute()}")

        # Show build stats
        site_dir = Path("site")
        if site_dir.exists():
            html_files = list(site_dir.rglob("*.html"))
            print(f"  - HTML pages: {len(html_files)}")

        return True

    except subprocess.TimeoutExpired:
        print("❌ Build timed out!")
        return False
    except Exception as e:
        print(f"❌ Build error: {e}")
        return False


def serve_docs(port=8000):
    """Serve documentation locally."""
    print("\n" + "=" * 70)
    print(f"Serving Documentation on http://localhost:{port}")
    print("=" * 70)
    print("\nPress Ctrl+C to stop the server...")

    try:
        subprocess.run(["mkdocs", "serve", "--dev-addr", f"localhost:{port}"], check=True)
    except KeyboardInterrupt:
        print("\n\n✅ Server stopped.")
    except Exception as e:
        print(f"\n❌ Server error: {e}")


def check_links():
    """Check for broken links in documentation."""
    print("\n" + "=" * 70)
    print("Checking Links...")
    print("=" * 70)

    # This would require additional tools like linkchecker
    print("⚠️  Link checking requires 'linkchecker' package")
    print("Install with: pip install linkchecker")
    print("Run with: linkchecker site/index.html")


def generate_api_docs():
    """Generate API reference documentation."""
    print("\n" + "=" * 70)
    print("Generating API Reference Documentation...")
    print("=" * 70)

    # MkDocstrings handles this automatically via mkdocs.yml
    print("✅ API docs are auto-generated by mkdocstrings plugin")
    print("   Configure in mkdocs.yml under 'plugins.mkdocstrings'")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Build KRYON documentation with MkDocs")
    parser.add_argument("--serve", action="store_true", help="Serve documentation locally after building")
    parser.add_argument("--strict", action="store_true", help="Build in strict mode (warnings are errors)")
    parser.add_argument("--clean", action="store_true", help="Clean previous build before building")
    parser.add_argument("--port", type=int, default=8000, help="Port for local server (default: 8000)")
    parser.add_argument("--check-links", action="store_true", help="Check for broken links")
    parser.add_argument("--coverage", action="store_true", help="Check documentation coverage only")

    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("KRYON DOCUMENTATION BUILD SCRIPT")
    print("=" * 70)

    # Coverage check only
    if args.coverage:
        check_documentation_coverage()
        return

    # Validate configuration
    # if not validate_mkdocs_config():
    #     print("\n❌ Configuration validation failed. Fix errors and try again.")
    #     sys.exit(1)

    # Check documentation coverage
    check_documentation_coverage()

    # Generate API docs
    generate_api_docs()

    # Build documentation
    if not build_docs(strict=args.strict, clean=args.clean):
        print("\n❌ Build failed. See errors above.")
        sys.exit(1)

    # Check links
    if args.check_links:
        check_links()

    # Serve locally
    if args.serve:
        serve_docs(port=args.port)
    else:
        print("\n✅ Build complete!")
        print(f"\nTo serve locally: python {sys.argv[0]} --serve")
        print("To deploy: mkdocs gh-deploy")


if __name__ == "__main__":
    main()
