"""
KRYON Learning Engine - Autonomous Learning System
===================================================

Machine learning system that records operations, identifies patterns,
and provides intelligent recommendations based on historical success.

Clearance Level: Omega-Strategic (Autonomous Learning Authority)
Classification: RESTRICTED
Mission: Learn from every operation to continuously improve

Features:
- Operation recording and pattern extraction
- Success probability calculations
- Historical exploit performance tracking
- Intelligent recommendations based on past operations
- Knowledge export/import for sharing
"""

import hashlib
import json
import sqlite3
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from kryon.sdk.agents import function_tool


class LearningEngine:
    """
    Core learning engine that manages operation history and pattern recognition.

    Learns from:
    - Successful exploits and their contexts
    - Failed attempts and reasons
    - Time-to-compromise for different techniques
    - Privilege escalation paths
    - Tool effectiveness per target type
    """

    def __init__(self, db_path: str = ".kryon_knowledge/operations.db"):
        """
        Initialize learning engine with persistent storage.

        Args:
            db_path: Path to SQLite database for knowledge storage
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Performance optimization: reusable connection with WAL mode
        self._conn = None
        self._init_database()

    def close(self):
        """Close database connection. Call this when done with the engine."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def __del__(self):
        """Cleanup on deletion."""
        self.close()

    def _get_connection(self) -> sqlite3.Connection:
        """
        Get or create reusable database connection.

        Performance: Reuses connection instead of creating new ones.
        Uses WAL mode for better concurrent access.
        """
        # Check if connection exists and is not closed
        try:
            if self._conn is not None:
                # Test if connection is alive
                self._conn.execute("SELECT 1")
                return self._conn
        except (sqlite3.ProgrammingError, sqlite3.OperationalError):
            # Connection is closed or invalid, create new one
            self._conn = None

        # Create new connection
        self._conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,  # Allow multi-thread access
            timeout=30.0,  # Longer timeout for concurrent ops
        )
        # Enable WAL mode for better concurrency (2-3x faster writes)
        self._conn.execute("PRAGMA journal_mode=WAL")
        # Optimize for performance
        self._conn.execute("PRAGMA synchronous=NORMAL")  # Faster than FULL, still safe
        self._conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
        return self._conn

    def _init_database(self):
        """Initialize database schema if not exists."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Operations table - stores complete operation history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS operations (
                operation_id TEXT PRIMARY KEY,
                timestamp REAL,
                target_ip TEXT,
                target_type TEXT,
                target_os TEXT,
                open_ports TEXT,
                services_detected TEXT,
                exploits_attempted TEXT,
                exploits_successful TEXT,
                time_to_first_shell REAL,
                time_to_root REAL,
                privilege_level TEXT,
                flags_found INTEGER,
                total_time REAL,
                success BOOLEAN,
                difficulty TEXT,
                notes TEXT
            )
        """)

        # Patterns table - stores learned patterns
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS patterns (
                pattern_id TEXT PRIMARY KEY,
                target_characteristics TEXT,
                exploit_name TEXT,
                exploit_type TEXT,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                success_rate REAL,
                avg_time_to_success REAL,
                last_used REAL,
                last_updated REAL,
                confidence_score REAL
            )
        """)

        # Exploit statistics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS exploit_stats (
                exploit_name TEXT PRIMARY KEY,
                total_attempts INTEGER DEFAULT 0,
                total_successes INTEGER DEFAULT 0,
                success_rate REAL,
                avg_time REAL,
                target_types TEXT,
                common_defenses TEXT,
                bypass_techniques TEXT,
                last_updated REAL
            )
        """)

        # Service vulnerability mappings
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS service_vulns (
                service_name TEXT,
                service_version TEXT,
                vulnerability_type TEXT,
                exploit_name TEXT,
                success_rate REAL,
                avg_time REAL,
                last_updated REAL,
                PRIMARY KEY (service_name, service_version, vulnerability_type)
            )
        """)

        # Create indices for fast lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_operations_target_type
            ON operations(target_type)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_patterns_exploit
            ON patterns(exploit_name)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_patterns_success_rate
            ON patterns(success_rate DESC)
        """)

        # Additional performance indices for common queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_operations_target_os_success
            ON operations(target_os, success)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_operations_timestamp
            ON operations(timestamp DESC)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_patterns_confidence
            ON patterns(confidence_score DESC)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_service_vulns_service
            ON service_vulns(service_name, service_version)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_patterns_last_used
            ON patterns(last_used DESC)
        """)

        conn.commit()
        # Connection is reused, don't close it

    def record_operation(self, operation_data: dict[str, Any], results: dict[str, Any]) -> str:
        """
        Record a complete operation for learning.

        Args:
            operation_data: Initial operation parameters
            results: Operation results including success/failure

        Returns:
            operation_id: Unique ID for this operation
        """
        # Generate operation ID
        operation_id = self._generate_operation_id(operation_data, results)

        # Extract relevant data
        target_profile = self._extract_target_profile(operation_data)
        exploit_history = self._extract_exploit_history(results)

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO operations VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """,
            (
                operation_id,
                time.time(),
                operation_data.get("target_ip", ""),
                operation_data.get("target_type", "unknown"),
                target_profile.get("os", "unknown"),
                json.dumps(target_profile.get("open_ports", [])),
                json.dumps(target_profile.get("services", [])),
                json.dumps(exploit_history.get("attempted", [])),
                json.dumps(exploit_history.get("successful", [])),
                results.get("time_to_first_shell"),
                results.get("time_to_root"),
                results.get("privilege_level", "none"),
                len(results.get("flags_found", [])),
                results.get("time_elapsed", 0),
                results.get("success", False),
                operation_data.get("difficulty", "unknown"),
                results.get("notes", ""),
            ),
        )

        conn.commit()
        # Connection is reused, don't close it

        # Trigger pattern learning from this operation
        self.learn_from_operation(operation_id)

        return operation_id

    def learn_from_operation(self, operation_id: str) -> dict[str, Any]:
        """
        Extract patterns and update knowledge base from an operation.

        Args:
            operation_id: ID of operation to learn from

        Returns:
            Dictionary with learning results
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Fetch operation details
        cursor.execute(
            """
            SELECT * FROM operations WHERE operation_id = ?
        """,
            (operation_id,),
        )

        row = cursor.fetchone()
        if not row:
            return {"error": "Operation not found"}

        # Parse operation data
        columns = [desc[0] for desc in cursor.description]
        operation = dict(zip(columns, row))

        # Extract learned patterns
        patterns_learned = []

        # Learn from successful exploits
        successful_exploits = json.loads(operation["exploits_successful"])
        for exploit in successful_exploits:
            pattern = self._create_pattern_from_exploit(operation, exploit, success=True)
            self._update_pattern(pattern)
            patterns_learned.append(pattern)

        # Learn from failed exploits (negative reinforcement)
        attempted = json.loads(operation["exploits_attempted"])
        failed_exploits = [e for e in attempted if e not in successful_exploits]
        for exploit in failed_exploits:
            pattern = self._create_pattern_from_exploit(operation, exploit, success=False)
            self._update_pattern(pattern)

        # Update exploit statistics
        for exploit in attempted:
            self._update_exploit_stats(
                exploit,
                success=(exploit in successful_exploits),
                time_taken=operation["time_to_first_shell"],
                target_type=operation["target_type"],
            )

        # Update service vulnerability mappings
        services = json.loads(operation["services_detected"])
        for service in services:
            for exploit in successful_exploits:
                self._update_service_vuln(
                    service, exploit, success_rate=1.0, time_taken=operation["time_to_first_shell"]
                )

        return {
            "operation_id": operation_id,
            "patterns_learned": len(patterns_learned),
            "exploits_analyzed": len(attempted),
            "success": True,
        }

    def get_learned_recommendations(
        self, target_profile: dict[str, Any], top_n: int = 5, min_confidence: float = 0.5
    ) -> dict[str, Any]:
        """
        Get intelligent recommendations based on learned patterns.

        Args:
            target_profile: Characteristics of current target
            top_n: Number of recommendations to return
            min_confidence: Minimum confidence threshold (0-1)

        Returns:
            Dictionary with recommended exploits and strategies
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Find similar past operations
        similar_ops = self._find_similar_operations(cursor, target_profile)

        # Get patterns matching target characteristics
        matching_patterns = self._find_matching_patterns(cursor, target_profile)

        # Calculate scores for each exploit
        exploit_scores = defaultdict(
            lambda: {
                "score": 0.0,
                "success_rate": 0.0,
                "avg_time": 0.0,
                "confidence": 0.0,
                "historical_uses": 0,
            }
        )

        for pattern in matching_patterns:
            if pattern["confidence_score"] >= min_confidence:
                exploit_name = pattern["exploit_name"]
                # Score based on success rate, recency, and confidence
                score = (
                    pattern["success_rate"] * 0.4
                    + pattern["confidence_score"] * 0.3
                    + self._recency_score(pattern["last_used"]) * 0.2
                    + self._frequency_score(pattern["success_count"]) * 0.1
                )

                exploit_scores[exploit_name]["score"] = max(exploit_scores[exploit_name]["score"], score)
                exploit_scores[exploit_name]["success_rate"] = pattern["success_rate"]
                exploit_scores[exploit_name]["avg_time"] = pattern["avg_time_to_success"]
                exploit_scores[exploit_name]["confidence"] = pattern["confidence_score"]
                exploit_scores[exploit_name]["historical_uses"] = pattern["success_count"]

        # Sort by score and get top N
        ranked_exploits = sorted(exploit_scores.items(), key=lambda x: x[1]["score"], reverse=True)[:top_n]

        recommendations = {
            "recommended_exploits": [
                {
                    "exploit_name": exploit,
                    "score": data["score"],
                    "success_rate": data["success_rate"],
                    "estimated_time": data["avg_time"],
                    "confidence": data["confidence"],
                    "historical_successes": data["historical_uses"],
                }
                for exploit, data in ranked_exploits
            ],
            "similar_operations_found": len(similar_ops),
            "patterns_analyzed": len(matching_patterns),
            "recommendation_confidence": sum(d[1]["confidence"] for d in ranked_exploits) / len(ranked_exploits)
            if ranked_exploits
            else 0.0,
        }

        # Add learned strategies from similar operations
        if similar_ops:
            recommendations["learned_strategies"] = self._extract_strategies(similar_ops)

        return recommendations

    def _generate_operation_id(self, operation_data: dict, results: dict) -> str:
        """Generate unique operation ID."""
        data = f"{operation_data.get('target_ip', '')}{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def _extract_target_profile(self, operation_data: dict) -> dict:
        """Extract target characteristics for pattern matching."""
        return {
            "os": operation_data.get("target_type", "unknown"),
            "open_ports": operation_data.get("open_ports", []),
            "services": operation_data.get("services_detected", []),
            "difficulty": operation_data.get("difficulty", "medium"),
        }

    def _extract_exploit_history(self, results: dict) -> dict:
        """Extract exploit attempt history."""
        return {
            "attempted": results.get("exploits_attempted", []),
            "successful": results.get("exploits_successful", []),
        }

    def _create_pattern_from_exploit(self, operation: dict, exploit: dict, success: bool) -> dict:
        """Create a pattern from an exploit attempt."""
        target_chars = {
            "os": operation["target_os"],
            "services": json.loads(operation["services_detected"]),
            "difficulty": operation["difficulty"],
        }

        pattern_id = hashlib.sha256(f"{json.dumps(target_chars)}{exploit['name']}".encode()).hexdigest()[:16]

        return {
            "pattern_id": pattern_id,
            "target_characteristics": json.dumps(target_chars),
            "exploit_name": exploit.get("name", "unknown"),
            "exploit_type": exploit.get("type", "unknown"),
            "success": success,
            "time_taken": operation["time_to_first_shell"],
        }

    def _update_pattern(self, pattern: dict):
        """Update pattern in database with new observation."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Check if pattern exists
        cursor.execute(
            """
            SELECT success_count, failure_count, avg_time_to_success
            FROM patterns WHERE pattern_id = ?
        """,
            (pattern["pattern_id"],),
        )

        existing = cursor.fetchone()

        if existing:
            success_count, failure_count, avg_time = existing
            # Update counts
            if pattern["success"]:
                success_count += 1
                # Update average time
                if avg_time and pattern["time_taken"]:
                    avg_time = (avg_time * (success_count - 1) + pattern["time_taken"]) / success_count
                elif pattern["time_taken"]:
                    avg_time = pattern["time_taken"]
            else:
                failure_count += 1

            total = success_count + failure_count
            success_rate = success_count / total if total > 0 else 0.0

            # Calculate confidence based on sample size
            confidence = min(1.0, total / 10.0)  # Full confidence at 10+ samples

            cursor.execute(
                """
                UPDATE patterns SET
                    success_count = ?,
                    failure_count = ?,
                    success_rate = ?,
                    avg_time_to_success = ?,
                    last_used = ?,
                    last_updated = ?,
                    confidence_score = ?
                WHERE pattern_id = ?
            """,
                (
                    success_count,
                    failure_count,
                    success_rate,
                    avg_time,
                    time.time(),
                    time.time(),
                    confidence,
                    pattern["pattern_id"],
                ),
            )
        else:
            # Insert new pattern
            success_count = 1 if pattern["success"] else 0
            failure_count = 0 if pattern["success"] else 1
            success_rate = 1.0 if pattern["success"] else 0.0

            cursor.execute(
                """
                INSERT INTO patterns VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """,
                (
                    pattern["pattern_id"],
                    pattern["target_characteristics"],
                    pattern["exploit_name"],
                    pattern["exploit_type"],
                    success_count,
                    failure_count,
                    success_rate,
                    pattern["time_taken"],
                    time.time(),
                    time.time(),
                    0.1,  # Low initial confidence
                ),
            )

        conn.commit()
        # Connection is reused, don't close it

    def _update_exploit_stats(self, exploit: dict, success: bool, time_taken: float, target_type: str):
        """Update global exploit statistics."""
        conn = self._get_connection()
        cursor = conn.cursor()

        exploit_name = exploit.get("name", "unknown")

        cursor.execute(
            """
            SELECT total_attempts, total_successes, avg_time, target_types
            FROM exploit_stats WHERE exploit_name = ?
        """,
            (exploit_name,),
        )

        existing = cursor.fetchone()

        if existing:
            attempts, successes, avg_time, target_types_json = existing
            attempts += 1
            if success:
                successes += 1
                if avg_time and time_taken:
                    avg_time = (avg_time * (successes - 1) + time_taken) / successes
                elif time_taken:
                    avg_time = time_taken

            target_types = json.loads(target_types_json) if target_types_json else {}
            target_types[target_type] = target_types.get(target_type, 0) + 1

            success_rate = successes / attempts if attempts > 0 else 0.0

            cursor.execute(
                """
                UPDATE exploit_stats SET
                    total_attempts = ?,
                    total_successes = ?,
                    success_rate = ?,
                    avg_time = ?,
                    target_types = ?,
                    last_updated = ?
                WHERE exploit_name = ?
            """,
                (
                    attempts,
                    successes,
                    success_rate,
                    avg_time,
                    json.dumps(target_types),
                    time.time(),
                    exploit_name,
                ),
            )
        else:
            cursor.execute(
                """
                INSERT INTO exploit_stats VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    exploit_name,
                    1,
                    1 if success else 0,
                    1.0 if success else 0.0,
                    time_taken,
                    json.dumps({target_type: 1}),
                    json.dumps({}),
                    json.dumps({}),
                    time.time(),
                ),
            )

        conn.commit()
        # Connection is reused, don't close it

    def _update_service_vuln(self, service: dict, exploit: dict, success_rate: float, time_taken: float):
        """Update service vulnerability mapping."""
        conn = self._get_connection()
        cursor = conn.cursor()

        service_name = service.get("name", "unknown")
        service_version = service.get("version", "unknown")
        vuln_type = exploit.get("type", "unknown")
        exploit_name = exploit.get("name", "unknown")

        cursor.execute(
            """
            INSERT OR REPLACE INTO service_vulns VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                service_name,
                service_version,
                vuln_type,
                exploit_name,
                success_rate,
                time_taken,
                time.time(),
            ),
        )

        conn.commit()
        # Connection is reused, don't close it

    def _find_similar_operations(self, cursor, target_profile: dict, limit: int = 10) -> list[dict]:
        """Find similar past operations."""
        # Simple similarity based on OS and service overlap
        target_os = target_profile.get("os", "unknown")

        cursor.execute(
            """
            SELECT * FROM operations
            WHERE target_os = ? AND success = 1
            ORDER BY timestamp DESC
            LIMIT ?
        """,
            (target_os, limit),
        )

        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def _find_matching_patterns(self, cursor, target_profile: dict) -> list[dict]:
        """Find patterns matching target characteristics."""
        cursor.execute("""
            SELECT * FROM patterns
            WHERE success_rate > 0.3
            ORDER BY success_rate DESC, confidence_score DESC
            LIMIT 20
        """)

        columns = [desc[0] for desc in cursor.description]
        all_patterns = [dict(zip(columns, row)) for row in cursor.fetchall()]

        # Filter patterns by target characteristics
        matching = []
        for pattern in all_patterns:
            pattern_chars = json.loads(pattern["target_characteristics"])
            if self._matches_target(pattern_chars, target_profile):
                matching.append(pattern)

        return matching

    def _matches_target(self, pattern_chars: dict, target_profile: dict) -> bool:
        """Check if pattern characteristics match target."""
        # Simple matching - can be enhanced with fuzzy matching
        if pattern_chars.get("os") != target_profile.get("os"):
            return False
        return True

    def _recency_score(self, last_used: float) -> float:
        """Score based on how recently pattern was used."""
        if not last_used:
            return 0.5

        days_ago = (time.time() - last_used) / 86400
        if days_ago < 7:
            return 1.0
        elif days_ago < 30:
            return 0.8
        elif days_ago < 90:
            return 0.6
        else:
            return 0.4

    def _frequency_score(self, success_count: int) -> float:
        """Score based on how often pattern succeeded."""
        if success_count >= 10:
            return 1.0
        elif success_count >= 5:
            return 0.8
        elif success_count >= 3:
            return 0.6
        else:
            return 0.4

    def _extract_strategies(self, similar_ops: list[dict]) -> list[str]:
        """Extract common strategies from similar operations."""
        strategies = []

        for op in similar_ops[:3]:  # Top 3 similar operations
            exploits = json.loads(op["exploits_successful"])
            if exploits:
                strategy = f"Use {exploits[0].get('name', 'exploit')} → "
                strategy += f"{op['privilege_level']} access in ~{op['time_to_first_shell']:.0f}s"
                strategies.append(strategy)

        return strategies

    def export_knowledge(self, export_path: str) -> dict[str, Any]:
        """Export learned knowledge to file for sharing."""
        conn = sqlite3.connect(str(self.db_path))

        # Export all tables
        export_data = {
            "export_time": time.time(),
            "export_date": datetime.now().isoformat(),
            "operations_count": 0,
            "patterns_count": 0,
            "exploits_count": 0,
            "data": {},
        }

        # Export operations (last 100)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM operations ORDER BY timestamp DESC LIMIT 100")
        columns = [desc[0] for desc in cursor.description]
        export_data["data"]["operations"] = [dict(zip(columns, row)) for row in cursor.fetchall()]
        export_data["operations_count"] = len(export_data["data"]["operations"])

        # Export patterns
        cursor.execute("SELECT * FROM patterns WHERE confidence_score > 0.5")
        columns = [desc[0] for desc in cursor.description]
        export_data["data"]["patterns"] = [dict(zip(columns, row)) for row in cursor.fetchall()]
        export_data["patterns_count"] = len(export_data["data"]["patterns"])

        # Export exploit stats
        cursor.execute("SELECT * FROM exploit_stats")
        columns = [desc[0] for desc in cursor.description]
        export_data["data"]["exploit_stats"] = [dict(zip(columns, row)) for row in cursor.fetchall()]
        export_data["exploits_count"] = len(export_data["data"]["exploit_stats"])

        conn.close()

        # Write to file
        with open(export_path, "w") as f:
            json.dump(export_data, f, indent=2)

        return {
            "success": True,
            "export_path": export_path,
            "operations": export_data["operations_count"],
            "patterns": export_data["patterns_count"],
            "exploits": export_data["exploits_count"],
        }


# Global learning engine instance
_learning_engine = None
_learning_engine_lock = __import__("threading").Lock()


def get_learning_engine() -> LearningEngine:
    """Get global learning engine instance."""
    global _learning_engine
    if _learning_engine is None:
        with _learning_engine_lock:
            if _learning_engine is None:
                _learning_engine = LearningEngine()
    return _learning_engine


# Convenience functions
@function_tool(strict_mode=False)
def record_operation(operation_data: dict[str, Any], results: dict[str, Any]) -> str:
    """Record an operation for learning."""
    return get_learning_engine().record_operation(operation_data, results)


@function_tool(strict_mode=False)
def get_learned_recommendations(
    target_profile: dict[str, Any], top_n: int = 5, min_confidence: float = 0.5
) -> dict[str, Any]:
    """Get learned recommendations for a target."""
    return get_learning_engine().get_learned_recommendations(target_profile, top_n, min_confidence)


def export_learned_knowledge(export_path: str = "kryon_knowledge_export.json") -> dict[str, Any]:
    """Export learned knowledge to file."""
    return get_learning_engine().export_knowledge(export_path)
