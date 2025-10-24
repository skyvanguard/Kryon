"""
SKYNET Query Cache
==================

Cache RAG query results for faster responses.
"""

import time
import hashlib
from typing import Dict, Any, Optional
from collections import OrderedDict


class QueryCache:
    """
    LRU cache for RAG query results.

    Caches both retrieval results and LLM responses.
    """

    def __init__(self, max_size: int = 100, ttl: int = 3600):
        """
        Initialize query cache.

        Args:
            max_size: Maximum cache entries (LRU eviction)
            ttl: Time-to-live in seconds (default: 1 hour)
        """
        self.max_size = max_size
        self.ttl = ttl
        self.cache = OrderedDict()
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0
        }

    def _generate_key(self, query: str, top_k: int, source_filter: Optional[str]) -> str:
        """Generate cache key from query parameters."""
        key_str = f"{query}_{top_k}_{source_filter or 'all'}"
        return hashlib.md5(key_str.encode()).hexdigest()

    def get(
        self,
        query: str,
        top_k: int = 5,
        source_filter: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get cached result.

        Args:
            query: Query string
            top_k: Number of results
            source_filter: Optional source filter

        Returns:
            Cached result or None
        """
        key = self._generate_key(query, top_k, source_filter)

        if key in self.cache:
            entry = self.cache[key]

            # Check TTL
            if time.time() - entry["timestamp"] < self.ttl:
                # Move to end (LRU)
                self.cache.move_to_end(key)
                self.stats["hits"] += 1
                return entry["result"]
            else:
                # Expired
                del self.cache[key]

        self.stats["misses"] += 1
        return None

    def set(
        self,
        query: str,
        result: Dict[str, Any],
        top_k: int = 5,
        source_filter: Optional[str] = None
    ):
        """
        Cache query result.

        Args:
            query: Query string
            result: Query result
            top_k: Number of results
            source_filter: Optional source filter
        """
        key = self._generate_key(query, top_k, source_filter)

        # Add to cache
        self.cache[key] = {
            "result": result,
            "timestamp": time.time()
        }

        # Move to end (most recently used)
        self.cache.move_to_end(key)

        # Evict if over max size
        if len(self.cache) > self.max_size:
            self.cache.popitem(last=False)  # Remove oldest
            self.stats["evictions"] += 1

    def clear(self):
        """Clear entire cache."""
        self.cache.clear()
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_rate = self.stats["hits"] / total_requests if total_requests > 0 else 0

        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "ttl": self.ttl,
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "evictions": self.stats["evictions"],
            "hit_rate": hit_rate,
            "total_requests": total_requests
        }


# Global instance
_query_cache = None


def get_query_cache() -> QueryCache:
    """Get global query cache instance."""
    global _query_cache
    if _query_cache is None:
        _query_cache = QueryCache(max_size=100, ttl=3600)
    return _query_cache


# Convenience functions
def cache_query(query: str, result: Dict, **kwargs):
    """Cache query result."""
    return get_query_cache().set(query, result, **kwargs)


def get_cached_query(query: str, **kwargs) -> Optional[Dict]:
    """Get cached query result."""
    return get_query_cache().get(query, **kwargs)


def clear_cache():
    """Clear query cache."""
    return get_query_cache().clear()


def get_cache_stats() -> Dict:
    """Get cache statistics."""
    return get_query_cache().get_stats()
