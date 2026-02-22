"""
KRYON Knowledge Base Verification
==================================

Verify and generate report on knowledge base content.
"""

import json
import sys
from datetime import datetime

# Fix encoding for Windows
if sys.platform == "win32":
    import codecs

    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "strict")
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, "strict")


def verify():
    """Verify knowledge base and generate report."""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   KRYON Knowledge Base Verification                           ║
║   ────────────────────────────────                            ║
║   Generating comprehensive knowledge base report              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """)

    from kryon.knowledge import get_knowledge_stats, query_knowledge

    # Get basic stats
    print("\n📊 Fetching statistics...")
    stats = get_knowledge_stats()

    report = {"generated_at": datetime.now().isoformat(), "stats": stats, "sample_queries": []}

    # Print basic info
    print(f"\n✅ Total Knowledge Items: {stats['total_knowledge_items']}")
    print(f"✅ LLM Configured: {'Yes' if stats['llm_configured'] else 'No'}")
    print(f"✅ LLM Model: {stats['llm_model']}")
    print(f"✅ Database: {stats['vector_db_path']}")

    # Source breakdown
    if stats.get("sources"):
        print("\n📚 Source Breakdown:")
        for source, count in sorted(stats["sources"].items(), key=lambda x: x[1], reverse=True):
            print(f"  - {source}: {count} documents")

    # Test sample queries
    print("\n🔍 Testing Sample Queries...\n")

    test_queries = [
        "SQL injection techniques",
        "Apache vulnerability",
        "Linux privilege escalation",
        "XSS exploitation",
    ]

    for query in test_queries:
        try:
            result = query_knowledge(query, top_k=3, use_llm=False)
            found = len(result["sources"])
            status = "✅" if found > 0 else "❌"
            print(f"{status} '{query}': {found} results")

            report["sample_queries"].append({"query": query, "results_found": found, "success": found > 0})
        except Exception as e:
            print(f"❌ '{query}': Error - {e}")
            report["sample_queries"].append({"query": query, "error": str(e), "success": False})

    # Save report
    report_file = f"knowledge_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n📄 Report saved to: {report_file}")

    # Summary
    print(f"\n{'=' * 70}")
    print("  Verification Summary")
    print(f"{'=' * 70}\n")

    successful_queries = sum(1 for q in report["sample_queries"] if q.get("success"))
    total_queries = len(report["sample_queries"])

    print("✅ Knowledge base operational")
    print(f"✅ {successful_queries}/{total_queries} sample queries successful")

    if stats["total_knowledge_items"] > 0:
        print("✅ Ready for use!")
        return True
    else:
        print("⚠️  Knowledge base is empty. Run initialize_knowledge.py first.")
        return False


if __name__ == "__main__":
    try:
        success = verify()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Verification failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
