#!/usr/bin/env python3
"""
RAG Query Script for Claude Code
Integrates SKYNET's RAG knowledge base with Claude Code
"""

import asyncio
import sys
from pathlib import Path

# Add SKYNET src to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / "src"))


async def query_rag(question: str, top_k: int = 5, use_llm: bool = False):
    """Query SKYNET RAG knowledge base."""
    try:
        from skynet.knowledge import query_knowledge_async

        print(f"🔍 Querying RAG for: {question}\n")

        result = await query_knowledge_async(
            question=question,
            top_k=top_k,
            use_llm=use_llm
        )

        if result.get('error'):
            print(f"❌ Error: {result['answer']}")
            return

        print("📚 RAG KNOWLEDGE BASE RESULTS")
        print("=" * 70)
        print(f"\n{result['answer']}\n")

        if result.get('sources'):
            print(f"\n📖 Sources ({len(result['sources'])}):")
            print("-" * 70)
            for i, source in enumerate(result['sources'][:3], 1):
                metadata = source.get('metadata', {})
                print(f"{i}. {metadata.get('source', 'Unknown')}")
                print(f"   {source.get('text', '')[:100]}...")
                print()

        print("=" * 70)

    except ImportError:
        print("❌ Error: SKYNET knowledge module not found")
        print("Make sure RAG is installed: pip install skynet-framework[rag]")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error querying RAG: {e}")
        sys.exit(1)


async def batch_query(questions: list[str], top_k: int = 3):
    """Query multiple questions in parallel."""
    try:
        from skynet.knowledge import query_knowledge_batch

        print(f"🔍 Batch querying {len(questions)} topics\n")

        results = await query_knowledge_batch(
            questions=questions,
            top_k=top_k,
            use_llm=True
        )

        print("📚 BATCH RAG RESULTS")
        print("=" * 70)

        for question, result in zip(questions, results):
            print(f"\n❓ {question}")
            print("-" * 70)

            if result.get('error'):
                print(f"❌ {result['answer']}")
            else:
                answer = result['answer']
                print(answer[:300] + "..." if len(answer) > 300 else answer)
            print()

        print("=" * 70)

    except Exception as e:
        print(f"❌ Error in batch query: {e}")
        sys.exit(1)


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Single query:  python rag-query.py 'your question'")
        print("  Detailed:      python rag-query.py 'question' --detailed")
        print("  Batch:         python rag-query.py --batch 'q1' 'q2' 'q3'")
        sys.exit(1)

    if sys.argv[1] == '--batch':
        questions = sys.argv[2:]
        asyncio.run(batch_query(questions))
    else:
        question = sys.argv[1]
        use_llm = '--detailed' in sys.argv
        top_k = 10 if use_llm else 5
        asyncio.run(query_rag(question, top_k=top_k, use_llm=use_llm))


if __name__ == "__main__":
    main()
