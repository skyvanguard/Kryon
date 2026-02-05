"""
KRYON Knowledge CLI
====================

Command-line interface for knowledge base management.
"""

import sys


def main():
    """Main CLI entry point."""
    if len(sys.argv) < 2:
        print_help()
        sys.exit(0)

    command = sys.argv[1]

    if command == "query":
        cmd_query()
    elif command == "add":
        cmd_add()
    elif command == "stats":
        cmd_stats()
    elif command == "update":
        cmd_update()
    elif command == "scrape":
        cmd_scrape()
    elif command == "help":
        print_help()
    else:
        print(f"Unknown command: {command}")
        print_help()
        sys.exit(1)


def cmd_query():
    """Query knowledge base."""
    if len(sys.argv) < 3:
        print("Usage: skynet-knowledge query <question>")
        sys.exit(1)

    question = " ".join(sys.argv[2:])

    from .rag_engine import query_knowledge

    print(f"\n🔍 Querying: {question}\n")
    result = query_knowledge(question, top_k=3)

    if result["answer"]:
        print(f"**Answer:**\n{result['answer']}\n")

    print(f"**Sources ({len(result['sources'])}):**")
    for i, source in enumerate(result["sources"], 1):
        print(f"\n{i}. [{source['metadata']['source']}] (score: {source['score']:.2f})")
        print(f"   {source['content'][:200]}...")


def cmd_add():
    """Add document to knowledge base."""
    if len(sys.argv) < 3:
        print("Usage: skynet-knowledge add <file_path>")
        sys.exit(1)

    file_path = sys.argv[2]

    from .processors import DocumentProcessor
    from .rag_engine import get_rag_engine

    print(f"📄 Processing: {file_path}")

    processor = DocumentProcessor()
    chunks = processor.process_file(file_path)

    rag = get_rag_engine()
    for chunk in chunks:
        rag.add_knowledge(content=chunk["content"], source="manual", metadata=chunk.get("metadata", {}))

    print(f"✅ Added {len(chunks)} chunks to knowledge base")


def cmd_stats():
    """Show knowledge base statistics."""
    from .rag_engine import get_knowledge_stats

    stats = get_knowledge_stats()

    print("\n📊 Knowledge Base Statistics\n")
    print(f"Total items: {stats['total_knowledge_items']}")
    print(f"LLM configured: {stats['llm_configured']}")
    print(f"LLM model: {stats['llm_model']}")
    print(f"Database path: {stats['vector_db_path']}\n")

    if stats.get("sources"):
        print("Sources breakdown:")
        for source, count in stats["sources"].items():
            print(f"  - {source}: {count}")


def cmd_update():
    """Trigger knowledge update."""
    from .auto_updater import auto_update_knowledge

    sources = sys.argv[2:] if len(sys.argv) > 2 else ["exploit-db", "nvd", "github"]

    print(f"🔄 Updating knowledge from: {', '.join(sources)}")
    auto_update_knowledge(sources)


def cmd_scrape():
    """Scrape specific source."""
    if len(sys.argv) < 3:
        print("Usage: skynet-knowledge scrape <source>")
        print("Sources: exploit-db, nvd, github, writeups")
        sys.exit(1)

    source = sys.argv[2]

    from .scrapers import ExploitDBScraper, GitHubScraper, NVDScraper, WriteupScraper

    if source == "exploit-db":
        scraper = ExploitDBScraper()
        items = scraper.scrape(max_results=10)
    elif source == "nvd":
        scraper = NVDScraper()
        items = scraper.scrape(days_back=7, max_results=10)
    elif source == "github":
        scraper = GitHubScraper()
        items = scraper.scrape(max_results=10)
    elif source == "writeups":
        scraper = WriteupScraper()
        items = scraper.scrape()
    else:
        print(f"Unknown source: {source}")
        sys.exit(1)

    print(f"\n📚 Scraped {len(items)} items from {source}\n")
    for i, item in enumerate(items[:3], 1):
        print(f"{i}. {item['content'][:150]}...")


def print_help():
    """Print help message."""
    help_text = """
KRYON Knowledge Base CLI

Usage:
  skynet-knowledge <command> [args]

Commands:
  query <question>    Query knowledge base
  add <file_path>     Add document to knowledge base
  stats               Show knowledge base statistics
  update [sources]    Update knowledge from sources
  scrape <source>     Scrape specific source
  help                Show this help message

Examples:
  skynet-knowledge query "How to exploit SQL injection?"
  skynet-knowledge add /path/to/document.pdf
  skynet-knowledge stats
  skynet-knowledge update exploit-db nvd
  skynet-knowledge scrape github

Sources:
  - exploit-db: Exploit Database
  - nvd: National Vulnerability Database
  - github: GitHub security repositories
  - writeups: CTF writeups
"""
    print(help_text)


if __name__ == "__main__":
    main()
