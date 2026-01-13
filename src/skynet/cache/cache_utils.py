"""
Cache Management Utilities

CLI and programmatic tools for managing SKYNET cache system.
"""

import json
from datetime import datetime, timedelta
from typing import Any, Optional

from .cache_manager import cache_stats, clear_cache, get_cache
from .scan_cache import get_scan_cache


class CacheInspector:
    """
    Utility class for inspecting and managing cache.
    """

    def __init__(self):
        self.cache = get_cache()
        self.scan_cache = get_scan_cache()

    def get_full_report(self) -> dict[str, Any]:
        """
        Get comprehensive cache report.

        Returns:
            Complete cache statistics and analysis
        """
        # Get base stats
        stats = cache_stats()

        # Get scan cache summary
        scan_summary = self.scan_cache.get_cache_summary()

        # Calculate storage efficiency
        if stats["total_requests"] > 0:
            requests_saved = stats["hits"]
            efficiency_percent = (requests_saved / stats["total_requests"]) * 100
        else:
            efficiency_percent = 0

        # Estimate time saved (assuming 10 seconds per scan on average)
        estimated_time_saved_seconds = stats["hits"] * 10
        time_saved_readable = str(timedelta(seconds=estimated_time_saved_seconds))

        return {
            "cache_stats": stats,
            "scan_summary": scan_summary,
            "performance": {
                "efficiency_percent": round(efficiency_percent, 2),
                "requests_saved": stats["hits"],
                "estimated_time_saved": time_saved_readable,
                "estimated_time_saved_seconds": estimated_time_saved_seconds,
            },
            "generated_at": datetime.now().isoformat(),
        }

    def print_report(self):
        """Print formatted cache report to console."""
        report = self.get_full_report()

        print("\n" + "=" * 70)
        print("SKYNET CACHE REPORT".center(70))
        print("=" * 70)

        # Cache Statistics
        print("\n📊 CACHE STATISTICS:")
        print(f"  Size: {report['cache_stats']['size']} / {report['cache_stats']['max_size']}")
        print(f"  Hits: {report['cache_stats']['hits']}")
        print(f"  Misses: {report['cache_stats']['misses']}")
        print(f"  Hit Ratio: {report['cache_stats']['hit_ratio'] * 100:.1f}%")
        print(f"  Evictions: {report['cache_stats']['evictions']}")
        print(f"  Expirations: {report['cache_stats']['expirations']}")

        # Scan Summary
        print("\n🎯 SCAN CACHE SUMMARY:")
        print(f"  Total Targets: {report['scan_summary']['total_targets']}")
        print(f"  Total Scans: {report['scan_summary']['total_scans']}")
        print(f"  Recent Scans (24h): {report['scan_summary']['recent_scans_24h']}")

        if report["scan_summary"]["tool_distribution"]:
            print("\n  Tool Distribution:")
            for tool, count in sorted(
                report["scan_summary"]["tool_distribution"].items(),
                key=lambda x: x[1],
                reverse=True,
            ):
                print(f"    {tool}: {count}")

        # Performance Metrics
        print("\n⚡ PERFORMANCE IMPACT:")
        print(f"  Efficiency: {report['performance']['efficiency_percent']:.1f}%")
        print(f"  Requests Saved: {report['performance']['requests_saved']}")
        print(f"  Estimated Time Saved: {report['performance']['estimated_time_saved']}")

        # Recent Targets
        if report["scan_summary"]["targets"]:
            print("\n🎯 RECENT TARGETS:")
            for target in report["scan_summary"]["targets"][:5]:
                print(f"    {target}")

        print("\n" + "=" * 70)
        print(f"Generated: {report['generated_at']}")
        print("=" * 70 + "\n")

    def get_target_report(self, target: str) -> dict[str, Any]:
        """
        Get detailed report for specific target.

        Args:
            target: Target to analyze

        Returns:
            Target-specific cache report
        """
        history = self.scan_cache.get_target_history(target)

        if not history:
            return {
                "target": target,
                "scans_found": 0,
                "message": "No cached scans found for this target",
            }

        # Organize by tool
        by_tool = {}
        for scan in history:
            tool = scan["tool"]
            if tool not in by_tool:
                by_tool[tool] = []
            by_tool[tool].append(scan)

        # Find oldest and newest
        oldest = min(history, key=lambda x: x["timestamp"])
        newest = max(history, key=lambda x: x["timestamp"])

        return {
            "target": target,
            "scans_found": len(history),
            "tools_used": list(by_tool.keys()),
            "by_tool": by_tool,
            "oldest_scan": {
                "tool": oldest["tool"],
                "age_seconds": oldest["age_seconds"],
                "timestamp": datetime.fromtimestamp(oldest["timestamp"]).isoformat(),
            },
            "newest_scan": {
                "tool": newest["tool"],
                "age_seconds": newest["age_seconds"],
                "timestamp": datetime.fromtimestamp(newest["timestamp"]).isoformat(),
            },
        }

    def print_target_report(self, target: str):
        """Print formatted target report."""
        report = self.get_target_report(target)

        print("\n" + "=" * 70)
        print(f"TARGET REPORT: {target}".center(70))
        print("=" * 70)

        if report["scans_found"] == 0:
            print(f"\n  {report['message']}\n")
            print("=" * 70 + "\n")
            return

        print("\n📊 SUMMARY:")
        print(f"  Total Scans: {report['scans_found']}")
        print(f"  Tools Used: {', '.join(report['tools_used'])}")

        print("\n🕐 TIMELINE:")
        print(f"  Oldest Scan: {report['oldest_scan']['tool']} - {report['oldest_scan']['timestamp']}")
        print(f"  Newest Scan: {report['newest_scan']['tool']} - {report['newest_scan']['timestamp']}")

        print("\n🔧 SCANS BY TOOL:")
        for tool, scans in report["by_tool"].items():
            print(f"  {tool}: {len(scans)} scan(s)")
            for scan in scans[:3]:  # Show first 3
                age = timedelta(seconds=int(scan["age_seconds"]))
                print(f"    - {age} ago")

        print("\n" + "=" * 70 + "\n")

    def cleanup_old_scans(self, max_age_hours: int = 24) -> dict[str, int]:
        """
        Clean up scans older than specified age.

        Args:
            max_age_hours: Maximum age in hours

        Returns:
            Cleanup statistics
        """
        max_age_seconds = max_age_hours * 3600
        targets = self.scan_cache.get_all_targets()

        deleted_count = 0
        targets_cleaned = 0

        for target in targets:
            history = self.scan_cache.get_target_history(target)
            target_deleted = 0

            for scan in history:
                if scan["age_seconds"] > max_age_seconds:
                    if self.cache.delete(scan["scan_key"]):
                        deleted_count += 1
                        target_deleted += 1

            if target_deleted > 0:
                targets_cleaned += 1

        return {
            "deleted_scans": deleted_count,
            "targets_cleaned": targets_cleaned,
            "max_age_hours": max_age_hours,
        }

    def optimize_cache(self) -> dict[str, Any]:
        """
        Optimize cache by removing expired entries.

        Returns:
            Optimization statistics
        """
        before_stats = cache_stats()

        # Cleanup expired entries
        self.cache.cleanup()

        after_stats = cache_stats()

        return {
            "before_size": before_stats["size"],
            "after_size": after_stats["size"],
            "freed_entries": before_stats["size"] - after_stats["size"],
            "expirations": after_stats["expirations"],
        }


def show_cache_stats():
    """CLI function to show cache statistics."""
    inspector = CacheInspector()
    inspector.print_report()


def show_target_cache(target: str):
    """CLI function to show target-specific cache."""
    inspector = CacheInspector()
    inspector.print_target_report(target)


def cleanup_cache(max_age_hours: int = 24):
    """CLI function to cleanup old cache entries."""
    inspector = CacheInspector()
    print(f"\n🧹 Cleaning up scans older than {max_age_hours} hours...")

    result = inspector.cleanup_old_scans(max_age_hours)

    print(f"✅ Cleaned up {result['deleted_scans']} scans from {result['targets_cleaned']} targets\n")


def optimize_cache():
    """CLI function to optimize cache."""
    inspector = CacheInspector()
    print("\n⚙️  Optimizing cache...")

    result = inspector.optimize_cache()

    print(f"✅ Freed {result['freed_entries']} entries")
    print(f"   Before: {result['before_size']} entries")
    print(f"   After: {result['after_size']} entries\n")


def reset_cache():
    """CLI function to completely reset cache."""
    print("\n⚠️  WARNING: This will delete ALL cached data!")
    response = input("Are you sure? (yes/no): ")

    if response.lower() == "yes":
        clear_cache()
        print("✅ Cache completely reset\n")
    else:
        print("❌ Operation cancelled\n")


def export_cache_report(output_file: str = "cache_report.json"):
    """Export cache report to JSON file."""
    inspector = CacheInspector()
    report = inspector.get_full_report()

    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n✅ Cache report exported to: {output_file}\n")


# Example integration function for tools
def check_cache_before_scan(
    tool: str,
    target: str,
    params: Optional[dict[str, Any]] = None,
    max_age: int = 3600,  # 1 hour
) -> Optional[Any]:
    """
    Check cache before performing scan.

    Args:
        tool: Tool name
        target: Scan target
        params: Scan parameters
        max_age: Maximum acceptable cache age in seconds

    Returns:
        Cached result if valid, None otherwise
    """
    scan_cache = get_scan_cache()

    # Check for exact match
    result = scan_cache.get_scan(tool, target, params)
    if result is not None:
        metadata = scan_cache.get_scan_metadata(tool, target, params)
        if metadata and metadata["age_seconds"] <= max_age:
            print(f"✓ Using cached {tool} result for {target} (age: {int(metadata['age_seconds'])}s)")
            return result

    # Check for similar scans
    similar = scan_cache.find_similar_scans(target, tool=tool, max_age=max_age)
    if similar:
        print(f"ℹ️  Found {len(similar)} similar cached scan(s) for {target}")

    return None
