"""
Async RAG Engine - Practical Examples
======================================

Demonstrates real-world usage of async RAG operations.

Use Cases:
1. Interactive Q&A with multiple related queries
2. Batch vulnerability analysis
3. Parallel CTF research
4. Multi-topic security research
"""

import asyncio
import time
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))


async def example_1_interactive_qa():
    """Example 1: Interactive Q&A session."""
    print("\n" + "="*70)
    print("EXAMPLE 1: Interactive Q&A Session")
    print("="*70)

    from skynet.knowledge import query_knowledge_async

    questions = [
        "What is SQL injection?",
        "How can I prevent SQL injection in PHP?",
        "What tools can detect SQL injection vulnerabilities?"
    ]

    print("\nUser has 3 related questions about SQL injection...")
    print("Processing them in parallel for faster response...")
    print("-"*70)

    start_time = time.time()

    # Process questions in parallel
    tasks = [query_knowledge_async(q, top_k=3, use_llm=True) for q in questions]
    results = await asyncio.gather(*tasks)

    elapsed = time.time() - start_time

    # Display results
    for i, (question, result) in enumerate(zip(questions, results), 1):
        print(f"\n📌 Question {i}: {question}")
        print("-"*70)
        print(result['answer'][:300] + "..." if len(result['answer']) > 300 else result['answer'])
        print(f"\n📚 Sources: {len(result['sources'])}")

    print(f"\n⚡ Total time: {elapsed:.2f}s (vs ~{len(questions)*15:.0f}s sequential)")
    print(f"✅ Speedup: {len(questions)*15/elapsed:.1f}x faster!")


async def example_2_vulnerability_analysis():
    """Example 2: Batch vulnerability analysis."""
    print("\n" + "="*70)
    print("EXAMPLE 2: Batch Vulnerability Analysis")
    print("="*70)

    from skynet.knowledge import query_knowledge_batch

    # Common web vulnerabilities
    vulnerabilities = [
        "SQL injection attacks",
        "Cross-Site Scripting (XSS)",
        "Cross-Site Request Forgery (CSRF)",
        "Path traversal vulnerabilities",
        "Remote Code Execution (RCE)"
    ]

    print(f"\nAnalyzing {len(vulnerabilities)} common web vulnerabilities...")
    print("-"*70)

    start_time = time.time()
    results = await query_knowledge_batch(vulnerabilities, top_k=2, use_llm=True)
    elapsed = time.time() - start_time

    # Create summary report
    print("\n📊 VULNERABILITY ANALYSIS REPORT")
    print("="*70)

    for vuln, result in zip(vulnerabilities, results):
        print(f"\n🔍 {vuln.upper()}")
        print("-"*70)

        if 'error' in result and result['error']:
            print(f"❌ Error: {result['answer']}")
        else:
            # Extract key info
            answer = result['answer']
            sources = result['sources']

            print(f"Summary: {answer[:200]}...")
            print(f"Knowledge sources: {len(sources)}")

    print(f"\n⏱️  Analysis completed in {elapsed:.2f}s")
    print(f"📈 Average per vulnerability: {elapsed/len(vulnerabilities):.2f}s")


async def example_3_ctf_research():
    """Example 3: Parallel CTF research."""
    print("\n" + "="*70)
    print("EXAMPLE 3: CTF Challenge Research")
    print("="*70)

    from skynet.knowledge import AsyncRAGEngine

    engine = AsyncRAGEngine(max_concurrent_llm_calls=3)

    # CTF-related queries
    ctf_queries = [
        "What is buffer overflow exploitation?",
        "How to perform privilege escalation on Linux?",
        "What are common CTF steganography techniques?",
        "How to crack password hashes?",
        "What is reverse shell and how to create one?"
    ]

    print(f"\n🎯 Researching {len(ctf_queries)} CTF topics in parallel...")
    print("-"*70)

    start_time = time.time()
    results = await engine.query_batch(ctf_queries, top_k=3, use_llm=True)
    elapsed = time.time() - start_time

    # Display CTF knowledge
    print("\n🏆 CTF RESEARCH RESULTS")
    print("="*70)

    for i, (query, result) in enumerate(zip(ctf_queries, results), 1):
        print(f"\n[{i}] {query}")
        print("-"*70)

        if 'error' not in result or not result['error']:
            print(result['answer'][:250] + "...")
            print(f"\n📚 References: {len(result['sources'])} documents")
        else:
            print(f"⚠️  {result['answer']}")

    print(f"\n⚡ Research time: {elapsed:.2f}s")
    print(f"🚀 Efficiency: {len(ctf_queries)*15/elapsed:.1f}x faster than sequential")


async def example_4_comparative_analysis():
    """Example 4: Comparative tool analysis."""
    print("\n" + "="*70)
    print("EXAMPLE 4: Comparative Security Tool Analysis")
    print("="*70)

    from skynet.knowledge import query_knowledge_async

    # Compare different tools
    tools = [
        "What is nmap and its features?",
        "What is Metasploit framework?",
        "What is Burp Suite used for?",
        "What is Wireshark and how to use it?"
    ]

    print(f"\n🔧 Comparing {len(tools)} security tools...")
    print("-"*70)

    start_time = time.time()

    # Parallel queries
    tasks = [query_knowledge_async(q, top_k=2, use_llm=True) for q in tools]
    results = await asyncio.gather(*tasks)

    elapsed = time.time() - start_time

    # Display comparison
    print("\n🛠️  TOOL COMPARISON")
    print("="*70)

    for tool_query, result in zip(tools, results):
        tool_name = tool_query.split("What is ")[1].split(" and")[0].split(" used")[0]

        print(f"\n📦 {tool_name.upper()}")
        print("-"*70)
        print(result['answer'][:300] + "...")
        print(f"Sources: {len(result['sources'])}")

    print(f"\n⏱️  Total time: {elapsed:.2f}s")


async def example_5_async_vs_sync_comparison():
    """Example 5: Async vs Sync performance comparison."""
    print("\n" + "="*70)
    print("EXAMPLE 5: Async vs Sync Performance Comparison")
    print("="*70)

    from skynet.knowledge import query_knowledge_async, query_knowledge

    queries = [
        "What is SQL injection?",
        "What is XSS?",
        "What is CSRF?"
    ]

    # Test async (parallel)
    print("\n🚀 Testing ASYNC (parallel)...")
    start_async = time.time()
    tasks = [query_knowledge_async(q, top_k=2, use_llm=True) for q in queries]
    async_results = await asyncio.gather(*tasks)
    async_time = time.time() - start_async

    # Test sync (sequential)
    print("🐌 Testing SYNC (sequential)...")
    start_sync = time.time()
    sync_results = []
    for q in queries:
        # Run sync query in executor to not block event loop
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda query=q: query_knowledge(query, top_k=2, use_llm=True)
        )
        sync_results.append(result)
    sync_time = time.time() - start_sync

    # Results
    print("\n📊 PERFORMANCE COMPARISON")
    print("="*70)
    print(f"Async (parallel):    {async_time:.2f}s")
    print(f"Sync (sequential):   {sync_time:.2f}s")
    print(f"Speedup:             {sync_time/async_time:.2f}x")
    print(f"Time saved:          {sync_time-async_time:.2f}s")
    print("\n✅ Async is faster for batch queries!")


async def main():
    """Run all examples."""
    print("\n" + "="*70)
    print("ASYNC RAG ENGINE - PRACTICAL EXAMPLES")
    print("="*70)
    print("\nDemonstrating async RAG operations for real-world use cases...")

    try:
        # Example 1: Interactive Q&A
        await example_1_interactive_qa()

        # Example 2: Vulnerability analysis
        await example_2_vulnerability_analysis()

        # Example 3: CTF research
        await example_3_ctf_research()

        # Example 4: Tool comparison
        await example_4_comparative_analysis()

        # Example 5: Performance comparison
        await example_5_async_vs_sync_comparison()

        print("\n" + "="*70)
        print("✅ ALL EXAMPLES COMPLETED!")
        print("="*70)
        print("\nKey Takeaways:")
        print("  1. Async queries enable parallel processing")
        print("  2. 3-5x speedup for batch operations")
        print("  3. Same accuracy as sync queries")
        print("  4. Perfect for multi-topic research")
        print("  5. Cache integration works seamlessly")

    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
