"""
SKYNET Knowledge Health Check
==============================

Monitor health and status of knowledge system.
"""

import time
import psutil
from typing import Dict, Any
from pathlib import Path


def check_vector_db() -> Dict[str, Any]:
    """Check vector database health."""
    try:
        from .vector_db import get_vector_db

        db = get_vector_db()
        count = db.count()

        return {
            "status": "healthy",
            "document_count": count,
            "operational": True
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "operational": False
        }


def check_llm() -> Dict[str, Any]:
    """Check LLM availability."""
    try:
        import requests
        import json

        config_path = Path.home() / ".skynet" / "config.json"
        if not config_path.exists():
            return {
                "status": "not_configured",
                "operational": False
            }

        with open(config_path) as f:
            config = json.load(f)

        base_url = config.get('base_url', 'http://localhost:11434')

        response = requests.get(f"{base_url}/api/tags", timeout=5)
        if response.status_code == 200:
            models = response.json().get('models', [])
            return {
                "status": "healthy",
                "models_available": len(models),
                "operational": True
            }
        else:
            return {
                "status": "error",
                "http_status": response.status_code,
                "operational": False
            }
    except requests.ConnectionError:
        return {
            "status": "offline",
            "error": "Ollama not running",
            "operational": False
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "operational": False
        }


def check_disk_space() -> Dict[str, Any]:
    """Check disk space."""
    try:
        knowledge_path = Path(".skynet_knowledge")

        # Get directory size if exists
        size_mb = 0
        if knowledge_path.exists():
            total_size = sum(f.stat().st_size for f in knowledge_path.rglob('*') if f.is_file())
            size_mb = total_size / (1024 * 1024)

        # Get free space
        usage = psutil.disk_usage(str(Path.cwd()))
        free_gb = usage.free / (1024**3)

        return {
            "status": "healthy" if free_gb > 1 else "warning",
            "knowledge_base_size_mb": round(size_mb, 2),
            "free_space_gb": round(free_gb, 2),
            "operational": free_gb > 0.5
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "operational": True  # Non-critical
        }


def check_dependencies() -> Dict[str, Any]:
    """Check required dependencies."""
    required = ['chromadb', 'schedule', 'requests']
    optional = ['sentence_transformers', 'PyPDF2']

    installed = []
    missing = []

    for dep in required:
        try:
            __import__(dep.replace('_', ''))
            installed.append(dep)
        except ImportError:
            missing.append(dep)

    return {
        "status": "healthy" if not missing else "error",
        "installed": installed,
        "missing": missing,
        "operational": len(missing) == 0
    }


def health_check() -> Dict[str, Any]:
    """
    Perform comprehensive health check.

    Returns:
        Health status dictionary
    """
    checks = {
        "timestamp": time.time(),
        "vector_db": check_vector_db(),
        "llm": check_llm(),
        "disk_space": check_disk_space(),
        "dependencies": check_dependencies()
    }

    # Overall status
    all_operational = all(
        check.get("operational", False)
        for check in checks.values()
        if isinstance(check, dict) and "operational" in check
    )

    checks["overall_status"] = "healthy" if all_operational else "degraded"
    checks["all_systems_operational"] = all_operational

    return checks


def print_health_status():
    """Print health status to console."""
    status = health_check()

    print(f"\n{'='*60}")
    print("  SKYNET Knowledge Health Status")
    print(f"{'='*60}\n")

    # Vector DB
    vdb = status["vector_db"]
    symbol = "✅" if vdb.get("operational") else "❌"
    print(f"{symbol} Vector Database: {vdb.get('status')}")
    if "document_count" in vdb:
        print(f"   Documents: {vdb['document_count']}")

    # LLM
    llm = status["llm"]
    symbol = "✅" if llm.get("operational") else "❌"
    print(f"{symbol} LLM: {llm.get('status')}")
    if "models_available" in llm:
        print(f"   Models: {llm['models_available']}")

    # Disk
    disk = status["disk_space"]
    symbol = "✅" if disk.get("status") == "healthy" else "⚠️"
    print(f"{symbol} Disk Space:")
    if "knowledge_base_size_mb" in disk:
        print(f"   Knowledge base: {disk['knowledge_base_size_mb']} MB")
    if "free_space_gb" in disk:
        print(f"   Free space: {disk['free_space_gb']} GB")

    # Dependencies
    deps = status["dependencies"]
    symbol = "✅" if deps.get("operational") else "❌"
    print(f"{symbol} Dependencies: {deps.get('status')}")
    if deps.get("missing"):
        print(f"   Missing: {', '.join(deps['missing'])}")

    # Overall
    print(f"\n{'─'*60}")
    if status["all_systems_operational"]:
        print("✅ All systems operational")
    else:
        print("⚠️  Some systems degraded")
    print(f"{'─'*60}\n")

    return status


if __name__ == "__main__":
    print_health_status()
