"""
Test LLM Response Caching Performance
======================================

Tests the LLM cache integration in RAG engine to verify:
1. Cache miss on first query (LLM generation)
2. Cache hit on repeated query (instant response)
3. Performance improvement measurement
4. Cache statistics tracking
"""

import sys
import time
import codecs

# Windows UTF-8 fix
if sys.platform == 'win32':
    if hasattr(sys.stdout, 'buffer'):
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    if hasattr(sys.stderr, 'buffer'):
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add src to path
sys.path.insert(0, './src')

from skynet.knowledge.rag_engine import RAGEngine
from skynet.knowledge.llm_cache import clear_llm_cache, get_llm_cache_stats


def print_header(title: str):
    """Print formatted header."""
    print(f"\n{'='*70}")
    print(f"{title:^70}")
    print('='*70)


def print_stats(label: str, stats: dict):
    """Print cache statistics."""
    print(f"\n{label}:")
    print(f"  Hits: {stats['hits']}")
    print(f"  Misses: {stats['misses']}")
    print(f"  Hit Rate: {stats['hit_rate']}")
    print(f"  Time Saved: {stats['total_time_saved']}")
    print(f"  API Calls Saved: {stats['api_calls_saved']}")
    print(f"  Cache Size: {stats['cache_size']}/{stats['max_size']}")


def test_llm_cache():
    """Test LLM caching in RAG engine."""
    print_header("LLM RESPONSE CACHE - PERFORMANCE TEST")

    # Clear cache for clean test
    print("\n[1] Clearing LLM cache...")
    clear_llm_cache()
    initial_stats = get_llm_cache_stats()
    print_stats("Initial Cache Stats", initial_stats)

    # Initialize RAG engine
    print("\n[2] Initializing RAG engine...")
    rag = RAGEngine()

    # Test query
    test_question = "What are common SQL injection techniques?"

    # First query - CACHE MISS (should take 10-30s with LLM)
    print_header("FIRST QUERY (Cache Miss - LLM Generation)")
    print(f"Question: {test_question}")
    print("\nExecuting... (this will take 10-30 seconds)")

    start_time = time.time()
    result1 = rag.query(test_question, use_llm=True, top_k=3)
    duration1 = time.time() - start_time

    print(f"\n✓ Duration: {duration1:.2f}s")
    print(f"✓ Answer length: {len(result1['answer'])} chars")
    print(f"\nAnswer preview:")
    print("-" * 70)
    print(result1['answer'][:300] + "..." if len(result1['answer']) > 300 else result1['answer'])
    print("-" * 70)

    # Check stats after first query
    stats_after_first = get_llm_cache_stats()
    print_stats("Cache Stats After First Query", stats_after_first)

    # Second query - CACHE HIT (should be instant)
    print_header("SECOND QUERY (Cache Hit - Instant)")
    print(f"Question: {test_question}")
    print("\nExecuting... (should be <100ms)")

    start_time = time.time()
    result2 = rag.query(test_question, use_llm=True, top_k=3)
    duration2 = time.time() - start_time

    print(f"\n✓ Duration: {duration2:.3f}s ({duration2*1000:.1f}ms)")
    print(f"✓ Answer length: {len(result2['answer'])} chars")
    print(f"✓ Answer matches: {result1['answer'] == result2['answer']}")

    # Check stats after second query
    stats_after_second = get_llm_cache_stats()
    print_stats("Cache Stats After Second Query", stats_after_second)

    # Performance comparison
    print_header("PERFORMANCE COMPARISON")
    speedup = duration1 / duration2 if duration2 > 0 else 0
    time_saved = duration1 - duration2

    print(f"\n  First Query (Cache Miss):  {duration1:.2f}s")
    print(f"  Second Query (Cache Hit):  {duration2:.3f}s ({duration2*1000:.1f}ms)")
    print(f"  Time Saved:                {time_saved:.2f}s")
    print(f"  Speedup:                   {speedup:.1f}x faster")
    print(f"  Cache Hit Rate:            {stats_after_second['hit_rate']}")

    # Verification
    print_header("VERIFICATION")

    checks = [
        ("Cache miss on first query", stats_after_first['misses'] == 1),
        ("Cache hit on second query", stats_after_second['hits'] == 1),
        ("Answers are identical", result1['answer'] == result2['answer']),
        ("Second query < 1s", duration2 < 1.0),
        ("Speedup > 10x", speedup > 10),
        ("Cache size = 1", stats_after_second['cache_size'] == 1),
    ]

    all_passed = True
    for check_name, passed in checks:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status}  {check_name}")
        if not passed:
            all_passed = False

    # Final summary
    print_header("TEST SUMMARY")

    if all_passed:
        print("\n  ✅ ALL TESTS PASSED")
        print("\n  LLM Response Caching is working perfectly!")
        print(f"\n  Performance Improvement: {speedup:.1f}x faster on cache hits")
        print(f"  Time Saved per Cache Hit: {time_saved:.2f}s")
    else:
        print("\n  ❌ SOME TESTS FAILED")
        print("\n  Please review the verification results above.")

    # RAG engine stats
    print_header("RAG ENGINE STATS")
    rag_stats = rag.get_stats()
    print(f"\n  Knowledge Items: {rag_stats['total_knowledge_items']}")
    print(f"  LLM Model: {rag_stats['llm_model']}")
    print(f"  LLM Configured: {rag_stats['llm_configured']}")
    print(f"\n  LLM Cache:")
    for key, value in rag_stats['llm_cache'].items():
        print(f"    {key}: {value}")

    print("\n" + "="*70)
    print("Test completed!")
    print("="*70 + "\n")


if __name__ == "__main__":
    try:
        test_llm_cache()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
