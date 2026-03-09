"""
KRYON Knowledge Synchronization System
=======================================

Share and sync knowledge between KRYON instances for collective learning.

Clearance Level: Omega-Strategic (Knowledge Sharing Authority)
Classification: RESTRICTED
Mission: Enable distributed learning across KRYON instances

Features:
- Export knowledge base to portable format
- Import knowledge from other instances
- Knowledge versioning and conflict resolution
- REST API for remote synchronization
- Selective sharing (public vs private knowledge)
"""

import gzip
import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional


class KnowledgeSync:
    """
    Knowledge synchronization engine for sharing learned patterns.

    Exports/imports:
    - Exploit success/failure patterns
    - Defense bypass techniques
    - Optimal tool configurations
    - Target fingerprints
    """

    def __init__(self, db_path: str = ".kryon_knowledge/operations.db"):
        """
        Initialize knowledge sync.

        Args:
            db_path: Path to local knowledge database
        """
        self.db_path = Path(db_path)
        self.instance_id = self._get_instance_id()

    def _get_instance_id(self) -> str:
        """Get or create unique instance ID."""
        id_file = Path.home() / ".kryon" / "instance_id"
        id_file.parent.mkdir(parents=True, exist_ok=True)

        if id_file.exists():
            return id_file.read_text().strip()

        # Generate new instance ID
        instance_id = hashlib.sha256(f"{time.time()}{id_file}".encode()).hexdigest()[
            :16
        ]

        id_file.write_text(instance_id)
        return instance_id

    def export_knowledge(
        self, output_file: str, filter_sensitive: bool = True, min_confidence: float = 0.5
    ) -> dict[str, Any]:
        """
        Export knowledge base to shareable format.

        Args:
            output_file: Output file path (.json.gz)
            filter_sensitive: Remove sensitive data (IPs, domains)
            min_confidence: Minimum confidence score to export

        Returns:
            Export statistics
        """
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        knowledge_export = {
            "version": "1.0",
            "instance_id": self.instance_id,
            "exported_at": time.time(),
            "patterns": [],
            "exploit_stats": [],
            "metadata": {
                "total_operations": 0,
                "success_rate": 0.0,
                "filters_applied": {
                    "sensitive_filtered": filter_sensitive,
                    "min_confidence": min_confidence,
                },
            },
        }

        # Export patterns
        cursor.execute(
            """
            SELECT * FROM patterns
            WHERE confidence_score >= ?
            ORDER BY success_count DESC, success_rate DESC
            LIMIT 1000
        """,
            (min_confidence,),
        )

        for row in cursor:
            pattern = dict(row)

            # Filter sensitive data
            if filter_sensitive:
                pattern["target_characteristics"] = self._anonymize_characteristics(pattern["target_characteristics"])

            knowledge_export["patterns"].append(pattern)

        # Export exploit statistics
        cursor.execute("""
            SELECT
                exploit_name,
                exploit_type,
                total_attempts,
                successful_attempts,
                CAST(successful_attempts AS REAL) / total_attempts AS success_rate,
                avg_time_to_success,
                common_failure_reasons
            FROM exploit_stats
            WHERE total_attempts >= 5
            ORDER BY success_rate DESC
            LIMIT 500
        """)

        for row in cursor:
            knowledge_export["exploit_stats"].append(dict(row))

        # Get metadata
        cursor.execute("SELECT COUNT(*) FROM operations")
        knowledge_export["metadata"]["total_operations"] = cursor.fetchone()[0]

        cursor.execute("""
            SELECT
                CAST(SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS REAL) / COUNT(*) AS success_rate
            FROM operations
        """)
        knowledge_export["metadata"]["success_rate"] = cursor.fetchone()[0] or 0.0

        conn.close()

        # Compress and save
        with gzip.open(output_file, "wt", encoding="utf-8") as f:
            json.dump(knowledge_export, f, indent=2)

        stats = {
            "exported_patterns": len(knowledge_export["patterns"]),
            "exported_exploit_stats": len(knowledge_export["exploit_stats"]),
            "total_operations": knowledge_export["metadata"]["total_operations"],
            "output_file": output_file,
            "file_size_mb": Path(output_file).stat().st_size / (1024 * 1024),
        }

        return stats

    def import_knowledge(
        self, import_file: str, merge_strategy: str = "best", trust_level: float = 0.8
    ) -> dict[str, Any]:
        """
        Import knowledge from another KRYON instance.

        Args:
            import_file: Knowledge file to import (.json.gz)
            merge_strategy: "best" (keep best), "avg" (average), "append" (add all)
            trust_level: Trust multiplier for imported data (0.0-1.0)

        Returns:
            Import statistics
        """
        # Load imported knowledge
        with gzip.open(import_file, "rt", encoding="utf-8") as f:
            imported = json.load(f)

        source_instance = imported.get("instance_id", "unknown")

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        stats = {
            "source_instance": source_instance,
            "patterns_imported": 0,
            "patterns_updated": 0,
            "exploit_stats_imported": 0,
            "conflicts_resolved": 0,
        }

        # Import patterns
        for pattern in imported.get("patterns", []):
            # Adjust confidence based on trust level
            original_confidence = pattern.get("confidence_score", 0.5)
            adjusted_confidence = original_confidence * trust_level

            # Check if pattern exists
            cursor.execute(
                """
                SELECT pattern_id, confidence_score, success_count
                FROM patterns
                WHERE target_characteristics = ? AND exploit_name = ?
            """,
                (pattern["target_characteristics"], pattern["exploit_name"]),
            )

            existing = cursor.fetchone()

            if existing:
                existing_id, existing_conf, existing_count = existing

                # Resolve conflict based on strategy
                if merge_strategy == "best":
                    # Keep pattern with higher confidence
                    if adjusted_confidence > existing_conf:
                        self._update_pattern(cursor, existing_id, pattern, adjusted_confidence)
                        stats["patterns_updated"] += 1
                    stats["conflicts_resolved"] += 1

                elif merge_strategy == "avg":
                    # Average the values
                    merged = self._merge_patterns_avg(
                        dict(zip(["pattern_id", "confidence_score", "success_count"], existing)),
                        pattern,
                        adjusted_confidence,
                    )
                    self._update_pattern(cursor, existing_id, merged, merged["confidence_score"])
                    stats["patterns_updated"] += 1
                    stats["conflicts_resolved"] += 1

                elif merge_strategy == "append":
                    # Add as new pattern with source tag
                    pattern["pattern_id"] = f"{pattern['pattern_id']}_imported_{source_instance[:8]}"
                    self._insert_pattern(cursor, pattern, adjusted_confidence)
                    stats["patterns_imported"] += 1

            else:
                # New pattern, insert
                self._insert_pattern(cursor, pattern, adjusted_confidence)
                stats["patterns_imported"] += 1

        # Import exploit statistics
        for exploit_stat in imported.get("exploit_stats", []):
            cursor.execute(
                """
                SELECT total_attempts, successful_attempts
                FROM exploit_stats
                WHERE exploit_name = ? AND exploit_type = ?
            """,
                (exploit_stat["exploit_name"], exploit_stat["exploit_type"]),
            )

            existing = cursor.fetchone()

            if existing:
                # Merge statistics
                total_attempts = existing[0] + exploit_stat["total_attempts"]
                successful_attempts = existing[1] + exploit_stat["successful_attempts"]

                cursor.execute(
                    """
                    UPDATE exploit_stats
                    SET total_attempts = ?, successful_attempts = ?
                    WHERE exploit_name = ? AND exploit_type = ?
                """,
                    (
                        total_attempts,
                        successful_attempts,
                        exploit_stat["exploit_name"],
                        exploit_stat["exploit_type"],
                    ),
                )
                stats["exploit_stats_imported"] += 1
            else:
                # Insert new exploit stat
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO exploit_stats
                    (exploit_name, exploit_type, total_attempts, successful_attempts, avg_time_to_success)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (
                        exploit_stat["exploit_name"],
                        exploit_stat["exploit_type"],
                        exploit_stat["total_attempts"],
                        exploit_stat["successful_attempts"],
                        exploit_stat.get("avg_time_to_success", 0),
                    ),
                )
                stats["exploit_stats_imported"] += 1

        conn.commit()
        conn.close()

        return stats

    def _anonymize_characteristics(self, characteristics: str) -> str:
        """Remove sensitive data from target characteristics."""
        try:
            char_dict = json.loads(characteristics)

            # Remove sensitive fields
            sensitive_fields = ["ip", "domain", "hostname", "exact_version"]
            for field in sensitive_fields:
                if field in char_dict:
                    # Generalize instead of removing
                    if field == "exact_version":
                        # Keep major version only
                        version = char_dict[field]
                        if "." in version:
                            char_dict[field] = version.split(".")[0] + ".x"

                    elif field in ["ip", "domain", "hostname"]:
                        char_dict[field] = "REDACTED"

            return json.dumps(char_dict)

        except json.JSONDecodeError:
            return characteristics

    def _insert_pattern(self, cursor, pattern: dict, confidence: float):
        """Insert new pattern into database."""
        cursor.execute(
            """
            INSERT OR IGNORE INTO patterns
            (pattern_id, target_characteristics, exploit_name, exploit_type,
             success_count, failure_count, success_rate, avg_time_to_success,
             last_used, last_updated, confidence_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                pattern["pattern_id"],
                pattern["target_characteristics"],
                pattern["exploit_name"],
                pattern["exploit_type"],
                pattern.get("success_count", 0),
                pattern.get("failure_count", 0),
                pattern.get("success_rate", 0.0),
                pattern.get("avg_time_to_success", 0.0),
                pattern.get("last_used", time.time()),
                time.time(),
                confidence,
            ),
        )

    def _update_pattern(self, cursor, pattern_id: str, pattern: dict, confidence: float):
        """Update existing pattern."""
        cursor.execute(
            """
            UPDATE patterns
            SET success_count = ?,
                failure_count = ?,
                success_rate = ?,
                avg_time_to_success = ?,
                confidence_score = ?,
                last_updated = ?
            WHERE pattern_id = ?
        """,
            (
                pattern.get("success_count", 0),
                pattern.get("failure_count", 0),
                pattern.get("success_rate", 0.0),
                pattern.get("avg_time_to_success", 0.0),
                confidence,
                time.time(),
                pattern_id,
            ),
        )

    def _merge_patterns_avg(self, existing: dict, imported: dict, imported_confidence: float) -> dict:
        """Merge two patterns by averaging their values."""
        merged = existing.copy()

        # Average numeric values
        numeric_fields = ["success_count", "failure_count", "avg_time_to_success"]
        for field in numeric_fields:
            existing_val = existing.get(field, 0)
            imported_val = imported.get(field, 0)
            merged[field] = (existing_val + imported_val) / 2

        # Recalculate success rate
        total = merged["success_count"] + merged["failure_count"]
        merged["success_rate"] = merged["success_count"] / total if total > 0 else 0.0

        # Average confidence
        existing_conf = existing.get("confidence_score", 0.5)
        merged["confidence_score"] = (existing_conf + imported_confidence) / 2

        return merged

    def sync_with_remote(
        self, remote_url: str, api_key: Optional[str] = None, direction: str = "both"
    ) -> dict[str, Any]:
        """
        Sync knowledge with remote KRYON instance.

        Args:
            remote_url: Remote instance URL (e.g., http://remote-kryon:8080)
            api_key: API key for authentication
            direction: "push", "pull", or "both"

        Returns:
            Sync statistics
        """
        import tempfile

        import requests

        stats = {"pushed": False, "pulled": False, "errors": []}

        from kryon.tools.common._url_validation import validate_external_url

        ssrf_err = validate_external_url(remote_url)
        if ssrf_err:
            stats["errors"].append(ssrf_err)
            return stats

        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        # Pull knowledge from remote
        if direction in ["pull", "both"]:
            tmp_path = None
            try:
                response = requests.get(f"{remote_url}/api/knowledge/export", headers=headers, timeout=30)

                if response.status_code == 200:
                    # Save to temp file
                    with tempfile.NamedTemporaryFile(suffix=".json.gz", delete=False) as tmp:
                        tmp.write(response.content)
                        tmp_path = tmp.name

                    # Import
                    import_stats = self.import_knowledge(tmp_path, merge_strategy="best")
                    stats["pulled"] = True
                    stats["pull_stats"] = import_stats

                else:
                    stats["errors"].append(f"Pull failed: HTTP {response.status_code}")

            except Exception as e:
                stats["errors"].append(f"Pull error: {str(e)}")
            finally:
                if tmp_path:
                    Path(tmp_path).unlink(missing_ok=True)

        # Push knowledge to remote
        if direction in ["push", "both"]:
            tmp_path = None
            try:
                # Export to temp file
                with tempfile.NamedTemporaryFile(suffix=".json.gz", delete=False) as tmp:
                    tmp_path = tmp.name

                export_stats = self.export_knowledge(tmp_path)

                # Upload
                with open(tmp_path, "rb") as f:
                    response = requests.post(
                        f"{remote_url}/api/knowledge/import",
                        headers=headers,
                        files={"knowledge": f},
                        timeout=30,
                    )

                if response.status_code == 200:
                    stats["pushed"] = True
                    stats["push_stats"] = export_stats
                else:
                    stats["errors"].append(f"Push failed: HTTP {response.status_code}")

            except Exception as e:
                stats["errors"].append(f"Push error: {str(e)}")
            finally:
                if tmp_path:
                    Path(tmp_path).unlink(missing_ok=True)

        return stats


# Global instance
_knowledge_sync = None
_knowledge_sync_lock = __import__("threading").Lock()


def get_knowledge_sync() -> KnowledgeSync:
    """Get global knowledge sync instance."""
    global _knowledge_sync
    if _knowledge_sync is None:
        with _knowledge_sync_lock:
            if _knowledge_sync is None:
                _knowledge_sync = KnowledgeSync()
    return _knowledge_sync


# Convenience functions
def export_knowledge(output_file: str, **kwargs) -> dict[str, Any]:
    """Export knowledge base to file."""
    return get_knowledge_sync().export_knowledge(output_file, **kwargs)


def import_knowledge(import_file: str, **kwargs) -> dict[str, Any]:
    """Import knowledge from file."""
    return get_knowledge_sync().import_knowledge(import_file, **kwargs)


def sync_with_remote(remote_url: str, **kwargs) -> dict[str, Any]:
    """Sync with remote KRYON instance."""
    return get_knowledge_sync().sync_with_remote(remote_url, **kwargs)
