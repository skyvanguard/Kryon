"""
SKYNET Performance Optimizer - Strategy Auto-Optimization
=========================================================

Automatic analysis and optimization of attack strategies based on historical performance.

Clearance Level: Omega-Strategic (Performance Optimization Authority)
Classification: RESTRICTED
Mission: Continuously improve operation success rates through data-driven optimization

Features:
- Historical performance analysis
- Automatic strategy parameter tuning
- Exploit success rate optimization
- Tool timing optimization
- Resource allocation optimization
"""

import json
import sqlite3
import statistics
import time
from collections import defaultdict
from pathlib import Path
from typing import Any


class PerformanceOptimizer:
    """
    Analyzes historical operation data and optimizes strategies automatically.

    Optimizations:
    - Exploit selection ordering (prioritize high success rate)
    - Timeout adjustments (based on avg successful timing)
    - Retry counts (based on eventual success patterns)
    - Tool parameter tuning (based on what worked)
    """

    def __init__(self, db_path: str = ".skynet_knowledge/operations.db"):
        """
        Initialize performance optimizer.

        Args:
            db_path: Path to operations database
        """
        self.db_path = Path(db_path)
        self.optimization_cache = {}
        self.last_analysis = 0

    def analyze_performance(self, time_window_days: int = 30, min_samples: int = 5) -> dict[str, Any]:
        """
        Analyze overall performance metrics.

        Args:
            time_window_days: How many days back to analyze
            min_samples: Minimum samples needed for statistical significance

        Returns:
            Performance analysis report
        """
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cutoff_time = time.time() - (time_window_days * 24 * 3600)

        report = {
            "analyzed_at": time.time(),
            "time_window_days": time_window_days,
            "overall_metrics": {},
            "exploit_rankings": [],
            "tool_performance": {},
            "timing_insights": {},
            "recommendations": [],
        }

        # Overall success rate
        cursor.execute(
            """
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful,
                AVG(execution_time) as avg_time
            FROM operations
            WHERE timestamp >= ?
        """,
            (cutoff_time,),
        )

        row = cursor.fetchone()
        total = row["total"]
        successful = row["successful"] or 0

        report["overall_metrics"] = {
            "total_operations": total,
            "successful_operations": successful,
            "success_rate": successful / total if total > 0 else 0.0,
            "avg_execution_time": row["avg_time"] or 0.0,
        }

        # Exploit performance rankings
        cursor.execute(
            """
            SELECT
                exploit_name,
                exploit_type,
                COUNT(*) as attempts,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successes,
                CAST(SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS REAL) / COUNT(*) as success_rate,
                AVG(CASE WHEN success = 1 THEN execution_time ELSE NULL END) as avg_success_time
            FROM operations
            WHERE timestamp >= ? AND exploit_name IS NOT NULL
            GROUP BY exploit_name, exploit_type
            HAVING attempts >= ?
            ORDER BY success_rate DESC, successes DESC
        """,
            (cutoff_time, min_samples),
        )

        for row in cursor:
            report["exploit_rankings"].append(
                {
                    "exploit_name": row["exploit_name"],
                    "exploit_type": row["exploit_type"],
                    "attempts": row["attempts"],
                    "successes": row["successes"],
                    "success_rate": row["success_rate"],
                    "avg_success_time": row["avg_success_time"],
                    "recommendation": self._get_exploit_recommendation(row["success_rate"], row["attempts"]),
                }
            )

        # Tool performance
        cursor.execute(
            """
            SELECT
                tool_name,
                COUNT(*) as uses,
                AVG(execution_time) as avg_time,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as contributed_to_success
            FROM operations
            WHERE timestamp >= ? AND tool_name IS NOT NULL
            GROUP BY tool_name
            HAVING uses >= ?
            ORDER BY contributed_to_success DESC
        """,
            (cutoff_time, min_samples),
        )

        for row in cursor:
            report["tool_performance"][row["tool_name"]] = {
                "uses": row["uses"],
                "avg_execution_time": row["avg_time"],
                "contribution_score": row["contributed_to_success"],
            }

        # Timing insights
        report["timing_insights"] = self._analyze_timing_patterns(cursor, cutoff_time)

        # Generate recommendations
        report["recommendations"] = self._generate_recommendations(report)

        conn.close()

        self.last_analysis = time.time()
        return report

    def _analyze_timing_patterns(self, cursor, cutoff_time: float) -> dict[str, Any]:
        """Analyze timing patterns to optimize timeouts."""
        cursor.execute(
            """
            SELECT
                operation_type,
                execution_time,
                success
            FROM operations
            WHERE timestamp >= ? AND execution_time IS NOT NULL
        """,
            (cutoff_time,),
        )

        timing_data = defaultdict(lambda: {"success_times": [], "failure_times": []})

        for row in cursor:
            op_type = row["operation_type"] or "unknown"
            exec_time = row["execution_time"]

            if row["success"]:
                timing_data[op_type]["success_times"].append(exec_time)
            else:
                timing_data[op_type]["failure_times"].append(exec_time)

        insights = {}
        for op_type, data in timing_data.items():
            success_times = data["success_times"]
            data["failure_times"]

            if len(success_times) >= 3:
                insights[op_type] = {
                    "success_avg": statistics.mean(success_times),
                    "success_median": statistics.median(success_times),
                    "success_stdev": statistics.stdev(success_times) if len(success_times) > 1 else 0,
                    "recommended_timeout": statistics.median(success_times) * 2,  # 2x median
                    "sample_size": len(success_times),
                }

        return insights

    def _get_exploit_recommendation(self, success_rate: float, attempts: int) -> str:
        """Get recommendation for exploit usage."""
        if success_rate >= 0.8 and attempts >= 10:
            return "HIGHLY_RECOMMENDED"
        elif success_rate >= 0.6 and attempts >= 5:
            return "RECOMMENDED"
        elif success_rate >= 0.4:
            return "ACCEPTABLE"
        elif success_rate >= 0.2:
            return "USE_WITH_CAUTION"
        else:
            return "AVOID"

    def _generate_recommendations(self, report: dict) -> list[str]:
        """Generate actionable recommendations."""
        recommendations = []

        # Success rate recommendations
        success_rate = report["overall_metrics"]["success_rate"]
        if success_rate < 0.3:
            recommendations.append("LOW_SUCCESS_RATE: Consider reviewing exploit database and updating techniques")
        elif success_rate > 0.7:
            recommendations.append(
                "HIGH_SUCCESS_RATE: Current strategies are effective, consider more aggressive tactics"
            )

        # Exploit recommendations
        top_exploits = [e for e in report["exploit_rankings"] if e["recommendation"] == "HIGHLY_RECOMMENDED"]

        if top_exploits:
            recommendations.append(
                f"PRIORITIZE_EXPLOITS: Use {', '.join([e['exploit_name'] for e in top_exploits[:3]])} as primary options"
            )

        avoid_exploits = [e for e in report["exploit_rankings"] if e["recommendation"] == "AVOID"]

        if avoid_exploits:
            recommendations.append(
                f"AVOID_EXPLOITS: Remove or fix {', '.join([e['exploit_name'] for e in avoid_exploits[:3]])}"
            )

        # Timing recommendations
        if report["timing_insights"]:
            recommendations.append("OPTIMIZE_TIMEOUTS: Apply recommended timeouts from timing analysis")

        return recommendations

    def get_optimized_exploit_order(self, service: str, available_exploits: list[str]) -> list[str]:
        """
        Reorder exploits based on historical success rates.

        Args:
            service: Service name
            available_exploits: List of available exploit names

        Returns:
            Reordered exploit list (best first)
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Get success rates for each exploit
        exploit_scores = {}

        for exploit in available_exploits:
            cursor.execute(
                """
                SELECT
                    COUNT(*) as attempts,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successes,
                    AVG(CASE WHEN success = 1 THEN execution_time ELSE NULL END) as avg_time
                FROM operations
                WHERE exploit_name = ?
            """,
                (exploit,),
            )

            row = cursor.fetchone()
            attempts = row[0]
            successes = row[1] or 0
            avg_time = row[2] or 999999

            if attempts > 0:
                # Score = success_rate * 100 - avg_time_penalty
                success_rate = successes / attempts
                time_penalty = min(avg_time / 10, 50)  # Cap penalty at 50
                score = (success_rate * 100) - time_penalty
            else:
                # No history, use neutral score
                score = 50

            exploit_scores[exploit] = score

        conn.close()

        # Sort by score (highest first)
        ordered = sorted(available_exploits, key=lambda e: exploit_scores.get(e, 50), reverse=True)

        return ordered

    def get_optimized_timeout(self, operation_type: str, default_timeout: float = 30.0) -> float:
        """
        Get optimized timeout for operation type.

        Args:
            operation_type: Type of operation
            default_timeout: Default timeout if no data

        Returns:
            Optimized timeout in seconds
        """
        # Check cache first
        cache_key = f"timeout_{operation_type}"
        if cache_key in self.optimization_cache:
            cache_time, cached_value = self.optimization_cache[cache_key]
            # Cache valid for 1 hour
            if time.time() - cache_time < 3600:
                return cached_value

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT execution_time
            FROM operations
            WHERE operation_type = ? AND success = 1
            ORDER BY timestamp DESC
            LIMIT 50
        """,
            (operation_type,),
        )

        times = [row[0] for row in cursor if row[0] is not None]
        conn.close()

        if len(times) >= 3:
            # Use 90th percentile (covers most successful operations)
            sorted_times = sorted(times)
            percentile_90 = sorted_times[int(len(sorted_times) * 0.9)]
            optimized = max(percentile_90, 5.0)  # Minimum 5 seconds
        else:
            optimized = default_timeout

        # Cache result
        self.optimization_cache[cache_key] = (time.time(), optimized)

        return optimized

    def get_optimized_retry_count(self, exploit_name: str, default_retries: int = 3) -> int:
        """
        Get optimized retry count based on eventual success patterns.

        Args:
            exploit_name: Name of exploit
            default_retries: Default retry count

        Returns:
            Optimized retry count
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Check if retries eventually lead to success
        cursor.execute(
            """
            SELECT
                retry_count,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successes
            FROM operations
            WHERE exploit_name = ? AND retry_count > 0
            GROUP BY retry_count
            ORDER BY retry_count
        """,
            (exploit_name,),
        )

        max_useful_retries = default_retries

        for row in cursor:
            retry_count = row[0]
            successes = row[1]

            # If this retry level produces successes, it's useful
            if successes > 0:
                max_useful_retries = max(max_useful_retries, retry_count)

        conn.close()

        # Cap at reasonable maximum
        return min(max_useful_retries, 5)

    def optimize_exploit_parameters(self, exploit_name: str) -> dict[str, Any]:
        """
        Suggest optimal parameters for an exploit.

        Args:
            exploit_name: Name of exploit

        Returns:
            Optimized parameters
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                parameters,
                success
            FROM operations
            WHERE exploit_name = ? AND parameters IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT 100
        """,
            (exploit_name,),
        )

        # Count parameter combinations and their success rates
        param_stats = defaultdict(lambda: {"attempts": 0, "successes": 0})

        for row in cursor:
            params_json = row[0]
            success = row[1]

            try:
                params = json.loads(params_json)
                # Create hashable key from params
                param_key = json.dumps(params, sort_keys=True)

                param_stats[param_key]["attempts"] += 1
                if success:
                    param_stats[param_key]["successes"] += 1
            except json.JSONDecodeError:
                continue

        conn.close()

        # Find best parameter set
        best_params = None
        best_score = 0

        for param_key, stats in param_stats.items():
            if stats["attempts"] >= 2:  # Minimum samples
                success_rate = stats["successes"] / stats["attempts"]
                score = success_rate * 100 + stats["attempts"]  # Bonus for more data

                if score > best_score:
                    best_score = score
                    best_params = json.loads(param_key)

        if best_params:
            return {"optimized_parameters": best_params, "confidence": min(best_score / 100, 1.0)}

        return {"optimized_parameters": {}, "confidence": 0.0}

    def auto_tune_strategy(self, target_profile: dict[str, Any]) -> dict[str, Any]:
        """
        Automatically tune attack strategy for target profile.

        Args:
            target_profile: Target characteristics (os, services, etc.)

        Returns:
            Tuned strategy configuration
        """
        # Analyze performance for similar targets
        analysis = self.analyze_performance(time_window_days=30, min_samples=3)

        strategy = {
            "exploit_order_optimized": True,
            "timeout_optimization": {},
            "retry_optimization": {},
            "recommended_exploits": [],
            "avoid_exploits": [],
        }

        # Get timeout optimizations for common operations
        common_ops = ["recon", "exploit", "post_exploit", "persistence"]
        for op in common_ops:
            strategy["timeout_optimization"][op] = self.get_optimized_timeout(op)

        # Get recommended exploits
        for ranking in analysis["exploit_rankings"]:
            if ranking["recommendation"] == "HIGHLY_RECOMMENDED":
                strategy["recommended_exploits"].append(ranking["exploit_name"])
            elif ranking["recommendation"] == "AVOID":
                strategy["avoid_exploits"].append(ranking["exploit_name"])

        # Apply timing insights
        strategy["timing_insights"] = analysis["timing_insights"]

        # Recommendations
        strategy["recommendations"] = analysis["recommendations"]

        return strategy


# Global instance
_performance_optimizer = None


def get_performance_optimizer() -> PerformanceOptimizer:
    """Get global performance optimizer instance."""
    global _performance_optimizer
    if _performance_optimizer is None:
        _performance_optimizer = PerformanceOptimizer()
    return _performance_optimizer


# Convenience functions
def analyze_performance(**kwargs) -> dict[str, Any]:
    """Analyze overall performance."""
    return get_performance_optimizer().analyze_performance(**kwargs)


def optimize_exploit_order(service: str, exploits: list[str]) -> list[str]:
    """Get optimized exploit order."""
    return get_performance_optimizer().get_optimized_exploit_order(service, exploits)


def optimize_timeout(operation_type: str, default: float = 30.0) -> float:
    """Get optimized timeout."""
    return get_performance_optimizer().get_optimized_timeout(operation_type, default)


def auto_tune_strategy(target_profile: dict) -> dict:
    """Auto-tune attack strategy."""
    return get_performance_optimizer().auto_tune_strategy(target_profile)
