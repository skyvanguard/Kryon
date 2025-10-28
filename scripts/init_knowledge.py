#!/usr/bin/env python3
"""
Initialize Skynet knowledge base with CTF techniques.
Run this after installing dependencies to populate the RAG system.
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from skynet.rag.retriever import get_retriever
from skynet.core.logging import get_logger

def main():
    logger = get_logger()
    retriever = get_retriever()

    knowledge_dir = Path(__file__).parent.parent / "data" / "ctf_knowledge"

    if not knowledge_dir.exists():
        print(f"❌ Knowledge directory not found: {knowledge_dir}")
        return 1

    print("🚀 Initializing Skynet knowledge base...")
    print(f"📁 Reading from: {knowledge_dir}")

    # Knowledge files and their categories
    knowledge_files = {
        "web_techniques.txt": "web",
        "linux_privesc.txt": "privesc",
        "crypto_techniques.txt": "crypto",
        "pwn_techniques.txt": "pwn"
    }

    total_added = 0

    for filename, category in knowledge_files.items():
        file_path = knowledge_dir / filename

        if not file_path.exists():
            print(f"⚠️  Skipping {filename} (not found)")
            continue

        print(f"\n📖 Processing {filename} ({category})...")

        try:
            retriever.add_knowledge_from_file(
                file_path=file_path,
                category=category
            )

            # Count entries (rough estimate)
            content = file_path.read_text()
            sections = content.count('\n## ') + content.count('\n### ')
            total_added += sections

            print(f"   ✅ Added ~{sections} knowledge entries")

        except Exception as e:
            print(f"   ❌ Error processing {filename}: {e}")
            logger.error(f"Failed to import {filename}: {e}")

    # Get final count
    final_count = retriever.count_knowledge()

    print(f"\n{'='*60}")
    print(f"✨ Knowledge base initialized!")
    print(f"📊 Total entries in database: {final_count}")
    print(f"{'='*60}")
    print(f"\n💡 Try searching:")
    print(f"   python -m skynet.cli.quick search 'sql injection'")
    print(f"   python -m skynet.cli.quick search 'privilege escalation'")
    print(f"   python -m skynet.cli.quick search 'buffer overflow'")

    return 0

if __name__ == "__main__":
    sys.exit(main())
