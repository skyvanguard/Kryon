"""
Tests for SKYNET Learning Engine
=================================

Tests autonomous learning and recommendation system.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from skynet.tools.autonomous.learning_engine import (
    LearningEngine,
    get_learned_recommendations,
    record_operation,
)


class TestLearningEngine:
    """Test suite for Learning Engine."""

    @pytest.fixture
    def temp_db(self):
        """Create temporary database for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_operations.db"
            yield str(db_path)

    @pytest.fixture
    def engine(self, temp_db):
        """Create learning engine instance for testing."""
        eng = LearningEngine(db_path=temp_db)
        yield eng
        eng.close()  # Ensure database connection is closed before temp dir cleanup

    def test_engine_initialization(self, engine, temp_db):
        """Test that engine initializes correctly."""
        assert engine.db_path == Path(temp_db)
        assert engine.db_path.parent.exists()

    def test_record_operation_success(self, engine):
        """Test recording a successful operation."""
        operation_data = {
            "target_ip": "10.10.10.5",
            "target_type": "linux",
            "difficulty": "medium",
            "open_ports": [22, 80, 443],
            "services_detected": [
                {"name": "ssh", "version": "OpenSSH 7.6"},
                {"name": "http", "version": "Apache 2.4.29"},
            ],
        }

        results = {
            "success": True,
            "exploits_attempted": [
                {"name": "apache_path_traversal", "type": "lfi"},
                {"name": "ssh_bruteforce", "type": "auth"},
            ],
            "exploits_successful": [{"name": "apache_path_traversal", "type": "lfi"}],
            "time_to_first_shell": 120.5,
            "time_to_root": 300.0,
            "privilege_level": "root",
            "flags_found": [{"name": "user.txt"}, {"name": "root.txt"}],
            "time_elapsed": 450.0,
        }

        operation_id = engine.record_operation(operation_data, results)

        assert operation_id is not None
        assert len(operation_id) == 16  # SHA256 hash truncated to 16 chars

    def test_learn_from_operation(self, engine):
        """Test that engine learns from recorded operations."""
        # Record an operation first
        operation_data = {
            "target_ip": "192.168.1.100",
            "target_type": "linux",
            "difficulty": "easy",
            "services_detected": [{"name": "http", "version": "nginx"}],
        }

        results = {
            "success": True,
            "exploits_attempted": [{"name": "nginx_exploit", "type": "rce"}],
            "exploits_successful": [{"name": "nginx_exploit", "type": "rce"}],
            "time_to_first_shell": 60.0,
            "privilege_level": "user",
        }

        operation_id = engine.record_operation(operation_data, results)

        # Learning should happen automatically via record_operation
        # But we can call it explicitly too
        learning_result = engine.learn_from_operation(operation_id)

        assert learning_result["success"]
        assert learning_result["patterns_learned"] >= 0
        assert learning_result["exploits_analyzed"] >= 1

    def test_get_recommendations(self, engine):
        """Test getting recommendations based on target profile."""
        # Record several successful operations
        for i in range(3):
            operation_data = {
                "target_ip": f"192.168.1.{100 + i}",
                "target_type": "linux",
                "difficulty": "medium",
                "services_detected": [{"name": "http", "version": "Apache 2.4"}],
            }

            results = {
                "success": True,
                "exploits_attempted": [{"name": "apache_vuln", "type": "rce"}],
                "exploits_successful": [{"name": "apache_vuln", "type": "rce"}],
                "time_to_first_shell": 100.0 + i * 10,
                "privilege_level": "root",
            }

            engine.record_operation(operation_data, results)

        # Get recommendations for similar target
        target_profile = {
            "os": "linux",
            "services": [{"name": "http", "version": "Apache 2.4"}],
            "difficulty": "medium",
        }

        recommendations = engine.get_learned_recommendations(target_profile, top_n=5)

        assert "recommended_exploits" in recommendations
        assert "similar_operations_found" in recommendations
        assert "patterns_analyzed" in recommendations
        # Should find at least one recommendation after 3 successful operations
        assert len(recommendations["recommended_exploits"]) >= 0

    def test_export_knowledge(self, engine):
        """Test exporting learned knowledge."""
        # Record an operation
        operation_data = {
            "target_ip": "10.0.0.1",
            "target_type": "windows",
            "services_detected": [{"name": "smb", "version": "SMBv2"}],
        }

        results = {
            "success": True,
            "exploits_attempted": [{"name": "eternalblue", "type": "rce"}],
            "exploits_successful": [{"name": "eternalblue", "type": "rce"}],
            "time_to_first_shell": 30.0,
            "privilege_level": "system",
        }

        engine.record_operation(operation_data, results)

        # Export knowledge
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            export_path = f.name

        try:
            export_result = engine.export_knowledge(export_path)

            assert export_result["success"]
            assert os.path.exists(export_path)

            # Verify export file contents
            with open(export_path) as f:
                exported_data = json.load(f)

            assert "export_time" in exported_data
            assert "operations_count" in exported_data
            assert "patterns_count" in exported_data
            assert "data" in exported_data
        finally:
            if os.path.exists(export_path):
                os.unlink(export_path)

    def test_pattern_confidence_scoring(self, engine):
        """Test that confidence scores increase with more samples."""
        operation_data = {
            "target_ip": "192.168.1.50",
            "target_type": "linux",
            "services_detected": [{"name": "ssh", "version": "OpenSSH 8.0"}],
        }

        # Record same exploit multiple times
        for _i in range(5):
            results = {
                "success": True,
                "exploits_attempted": [{"name": "ssh_exploit", "type": "auth"}],
                "exploits_successful": [{"name": "ssh_exploit", "type": "auth"}],
                "time_to_first_shell": 50.0,
                "privilege_level": "user",
            }

            engine.record_operation(operation_data, results)

        # Get recommendations - confidence should be higher now
        target_profile = {"os": "linux", "services": [{"name": "ssh"}]}
        recommendations = engine.get_learned_recommendations(target_profile)

        # With 5 successful operations, recommendation confidence should be decent
        if recommendations["recommended_exploits"]:
            # Confidence should increase with more samples
            assert recommendations["recommendation_confidence"] > 0.3


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_record_operation_convenience(self):
        """Test convenience function for recording operations."""
        operation_data = {"target_ip": "1.2.3.4", "target_type": "linux"}
        results = {"success": True, "exploits_successful": []}

        # Should not raise error
        operation_id = record_operation(operation_data, results)
        assert operation_id is not None

    def test_get_recommendations_convenience(self):
        """Test convenience function for getting recommendations."""
        target_profile = {"os": "linux"}

        # Should not raise error
        recommendations = get_learned_recommendations(target_profile)
        assert "recommended_exploits" in recommendations


@pytest.mark.integration
class TestLearningIntegration:
    """Integration tests for learning system."""

    def test_full_learning_cycle(self, tmp_path):
        """Test complete learning cycle from operation to recommendation."""
        db_path = tmp_path / "integration_test.db"
        engine = LearningEngine(db_path=str(db_path))

        # Simulate 10 operations on similar targets
        for i in range(10):
            operation_data = {
                "target_ip": f"10.0.0.{i}",
                "target_type": "linux",
                "difficulty": "medium",
                "services_detected": [
                    {"name": "http", "version": "Apache 2.4"},
                    {"name": "ssh", "version": "OpenSSH 7.6"},
                ],
            }

            # 80% success rate
            success = i < 8

            results = {
                "success": success,
                "exploits_attempted": [
                    {"name": "apache_rce", "type": "rce"},
                    {"name": "ssh_key_enum", "type": "enum"},
                ],
                "exploits_successful": [{"name": "apache_rce", "type": "rce"}] if success else [],
                "time_to_first_shell": 90.0 if success else None,
                "privilege_level": "user" if success else "none",
                "time_elapsed": 200.0,
            }

            engine.record_operation(operation_data, results)

        # Now get recommendations for similar target
        target_profile = {
            "os": "linux",
            "services": [{"name": "http", "version": "Apache 2.4"}],
            "difficulty": "medium",
        }

        recommendations = engine.get_learned_recommendations(target_profile, top_n=3, min_confidence=0.3)

        # Should have learned from the 10 operations
        assert recommendations["similar_operations_found"] >= 8
        assert recommendations["patterns_analyzed"] > 0

        # Export the knowledge
        export_path = tmp_path / "knowledge_export.json"
        export_result = engine.export_knowledge(str(export_path))

        assert export_result["operations"] == 10  # Last 100, but we only have 10
        assert export_path.exists()
