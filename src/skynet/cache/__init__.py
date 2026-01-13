"""
SKYNET Smart Caching System

Advanced result caching with LRU eviction, TTL support, and persistent storage.
Optimizes performance by preventing duplicate scans and storing expensive results.

Available Components:
- CacheManager: Central cache management with LRU and TTL
- cache_result: Decorator for automatic function result caching
- ScanCache: Specialized cache for scan results
- get_cache: Get global cache instance
"""

from .cache_manager import CacheManager, cache_result, cache_stats, clear_cache, get_cache
from .scan_cache import ScanCache, cache_scan, cache_scan_result, find_similar_scans, get_scan_cache

__all__ = [
    # Core cache management
    "CacheManager",
    "cache_result",
    "get_cache",
    "clear_cache",
    "cache_stats",
    # Scan-specific caching
    "ScanCache",
    "cache_scan_result",
    "cache_scan",
    "get_scan_cache",
    "find_similar_scans",
]
