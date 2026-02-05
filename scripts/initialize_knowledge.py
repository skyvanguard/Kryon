"""
KRYON Knowledge Base Initialization
====================================

Initialize knowledge base with real data from multiple sources.
"""

import sys
import time

# Fix encoding for Windows
if sys.platform == "win32":
    import codecs

    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "strict")
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, "strict")


def print_header(text):
    """Print section header."""
    print(f"\n{'=' * 70}")
    print(f"  {text}")
    print(f"{'=' * 70}\n")


def print_progress(current, total, prefix="", suffix="", length=50):
    """Print progress bar."""
    filled = int(length * current // total)
    bar = "█" * filled + "─" * (length - filled)
    percent = f"{100 * current / total:.1f}%"
    print(f"\r{prefix} |{bar}| {current}/{total} {percent} {suffix}", end="", flush=True)
    if current == total:
        print()


def scrape_exploitdb(max_results=500) -> list[dict]:
    """Scrape Exploit-DB."""
    print_header("Scraping Exploit-DB")

    try:
        from kryon.knowledge.scrapers import ExploitDBScraper

        scraper = ExploitDBScraper()

        # Common keywords for initial seeding
        keywords = [
            "apache",
            "nginx",
            "wordpress",
            "joomla",
            "drupal",
            "mysql",
            "postgresql",
            "mssql",
            "php",
            "python",
            "ruby",
            "nodejs",
            "windows",
            "linux",
            "privilege escalation",
            "sql injection",
            "xss",
            "rce",
            "lfi",
            "rfi",
        ]

        print(f"Scraping with {len(keywords)} keyword sets...")
        print(f"Target: ~{max_results} exploits\n")

        all_exploits = []
        per_keyword = max_results // len(keywords)

        for i, keyword in enumerate(keywords, 1):
            print_progress(i - 1, len(keywords), prefix="Progress", suffix=f"({keyword})")

            try:
                exploits = scraper.scrape(keywords=[keyword], max_results=per_keyword)
                all_exploits.extend(exploits)
                time.sleep(0.5)  # Be gentle
            except Exception as e:
                print(f"\n⚠️  Error with keyword '{keyword}': {e}")

        print_progress(len(keywords), len(keywords), prefix="Progress", suffix="Complete")

        # Deduplicate
        seen = set()
        unique_exploits = []
        for exploit in all_exploits:
            exploit_id = scraper.generate_id(exploit["content"])
            if exploit_id not in seen:
                seen.add(exploit_id)
                unique_exploits.append(exploit)

        print(f"\n✅ Scraped {len(unique_exploits)} unique exploits from Exploit-DB")
        return unique_exploits

    except Exception as e:
        print(f"\n❌ Exploit-DB scraping failed: {e}")
        return []


def scrape_nvd(days_back=7, max_results=200) -> list[dict]:
    """Scrape NVD CVEs."""
    print_header("Scraping NVD (National Vulnerability Database)")

    try:
        from kryon.knowledge.scrapers import NVDScraper

        scraper = NVDScraper()

        print(f"Fetching CVEs from last {days_back} days...")
        print(f"Target: ~{max_results} CVEs\n")

        cves = scraper.scrape(days_back=days_back, severity_min="MEDIUM", max_results=max_results)

        print(f"✅ Scraped {len(cves)} CVEs from NVD")
        return cves

    except Exception as e:
        print(f"\n❌ NVD scraping failed: {e}")
        return []


def scrape_github(max_results=50) -> list[dict]:
    """Scrape GitHub repositories."""
    print_header("Scraping GitHub Security Repositories")

    try:
        from kryon.knowledge.scrapers import GitHubScraper

        scraper = GitHubScraper()

        keywords = [
            "CVE exploit",
            "pentesting tool",
            "security scanner",
            "privilege escalation",
            "web exploitation",
        ]

        print(f"Searching with {len(keywords)} queries...")
        print(f"Target: ~{max_results} repositories\n")

        all_repos = []
        per_keyword = max_results // len(keywords)

        for i, keyword in enumerate(keywords, 1):
            print_progress(i - 1, len(keywords), prefix="Progress", suffix=f"({keyword})")

            try:
                repos = scraper.scrape(keywords=[keyword], min_stars=10, max_results=per_keyword)
                all_repos.extend(repos)
                time.sleep(2)  # GitHub rate limiting
            except Exception as e:
                print(f"\n⚠️  Error with keyword '{keyword}': {e}")

        print_progress(len(keywords), len(keywords), prefix="Progress", suffix="Complete")

        # Deduplicate
        seen = set()
        unique_repos = []
        for repo in all_repos:
            repo_id = scraper.generate_id(repo["content"])
            if repo_id not in seen:
                seen.add(repo_id)
                unique_repos.append(repo)

        print(f"\n✅ Scraped {len(unique_repos)} repositories from GitHub")
        return unique_repos

    except Exception as e:
        print(f"\n❌ GitHub scraping failed: {e}")
        return []


def scrape_writeups() -> list[dict]:
    """Scrape CTF writeups."""
    print_header("Scraping CTF Writeups")

    try:
        from kryon.knowledge.scrapers import WriteupScraper

        scraper = WriteupScraper()

        print("Collecting CTF methodologies and writeups...\n")

        writeups = scraper.scrape()

        print(f"✅ Scraped {len(writeups)} writeups/methodologies")
        return writeups

    except Exception as e:
        print(f"\n❌ Writeup scraping failed: {e}")
        return []


def add_to_knowledge_base(items: list[dict], source: str):
    """Add items to knowledge base with progress."""
    if not items:
        return 0

    print(f"\nAdding {len(items)} items to knowledge base...")

    from kryon.knowledge import get_rag_engine

    rag = get_rag_engine()

    added = 0
    for i, item in enumerate(items, 1):
        try:
            rag.add_knowledge(content=item["content"], source=source, metadata=item.get("metadata", {}))
            added += 1

            if i % 10 == 0 or i == len(items):
                print_progress(i, len(items), prefix="Adding", suffix="documents")

        except Exception as e:
            print(f"\n⚠️  Error adding item {i}: {e}")

    return added


def initialize(
    sources: list[str] = None,
    exploit_db_count: int = 500,
    nvd_days: int = 7,
    nvd_count: int = 200,
    github_count: int = 50,
):
    """
    Initialize knowledge base with real data.

    Args:
        sources: List of sources to scrape (default: all)
        exploit_db_count: Number of exploits to scrape
        nvd_days: Days back for NVD
        nvd_count: Number of CVEs to scrape
        github_count: Number of GitHub repos
    """
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   KRYON Knowledge Base Initialization                         ║
║   ─────────────────────────────────                           ║
║   Populating knowledge base with real security data           ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """)

    if sources is None:
        sources = ["exploit-db", "nvd", "github", "writeups"]

    start_time = time.time()
    total_added = 0
    results = {}

    # Scrape each source
    if "exploit-db" in sources:
        exploits = scrape_exploitdb(max_results=exploit_db_count)
        if exploits:
            added = add_to_knowledge_base(exploits, "exploit-db")
            results["exploit-db"] = added
            total_added += added

    if "nvd" in sources:
        cves = scrape_nvd(days_back=nvd_days, max_results=nvd_count)
        if cves:
            added = add_to_knowledge_base(cves, "nvd")
            results["nvd"] = added
            total_added += added

    if "github" in sources:
        repos = scrape_github(max_results=github_count)
        if repos:
            added = add_to_knowledge_base(repos, "github")
            results["github"] = added
            total_added += added

    if "writeups" in sources:
        writeups = scrape_writeups()
        if writeups:
            added = add_to_knowledge_base(writeups, "writeups")
            results["writeups"] = added
            total_added += added

    # Summary
    elapsed = time.time() - start_time

    print_header("Initialization Complete")

    print(f"⏱️  Time elapsed: {elapsed:.1f} seconds")
    print(f"📊 Total items added: {total_added}\n")

    print("Sources breakdown:")
    for source, count in results.items():
        print(f"  - {source}: {count} items")

    print(f"\n{'─' * 70}\n")

    # Get stats
    from kryon.knowledge import get_knowledge_stats

    stats = get_knowledge_stats()

    print("📚 Knowledge Base Status:")
    print(f"  Total documents: {stats['total_knowledge_items']}")
    print(f"  LLM configured: {'Yes' if stats['llm_configured'] else 'No'}")
    print(f"  LLM model: {stats['llm_model']}")
    print(f"  Database: {stats['vector_db_path']}")

    print("\n✅ Knowledge base initialized successfully!")
    print("\nNext steps:")
    print("  1. Test queries: python -m kryon.knowledge.cli query 'your question'")
    print("  2. Start auto-updates: See docs/RAG_QUICKSTART.md")
    print("  3. Integrate with agents: Use query_knowledge() in your code")

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Initialize KRYON knowledge base")
    parser.add_argument(
        "--sources",
        nargs="+",
        choices=["exploit-db", "nvd", "github", "writeups", "all"],
        default=["all"],
        help="Sources to scrape",
    )
    parser.add_argument("--exploits", type=int, default=500, help="Number of exploits to scrape from Exploit-DB")
    parser.add_argument("--nvd-days", type=int, default=7, help="Days back for NVD CVEs")
    parser.add_argument("--nvd-count", type=int, default=200, help="Number of CVEs from NVD")
    parser.add_argument("--github-count", type=int, default=50, help="Number of GitHub repositories")

    args = parser.parse_args()

    sources = args.sources
    if "all" in sources:
        sources = ["exploit-db", "nvd", "github", "writeups"]

    try:
        initialize(
            sources=sources,
            exploit_db_count=args.exploits,
            nvd_days=args.nvd_days,
            nvd_count=args.nvd_count,
            github_count=args.github_count,
        )
        sys.exit(0)
    except KeyboardInterrupt:
        print("\n\n⚠️  Initialization interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Initialization failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
