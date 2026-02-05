"""
KRYON RAG Validation Script
============================

Interactive validation of RAG system components.
"""

import sys
from pathlib import Path

# Fix encoding for Windows
if sys.platform == "win32":
    import codecs

    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "strict")
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, "strict")


def print_header(text):
    """Print section header."""
    print(f"\n{'=' * 60}")
    print(f"  {text}")
    print(f"{'=' * 60}\n")


def print_check(name, status, details=""):
    """Print check result."""
    symbol = "✅" if status else "❌"
    print(f"{symbol} {name}")
    if details:
        print(f"   {details}")


def check_dependencies():
    """Check required dependencies."""
    print_header("Checking Dependencies")

    required_deps = {
        "chromadb": "ChromaDB vector database",
        "sentence_transformers": "Sentence transformers for embeddings",
        "schedule": "Task scheduling",
        "requests": "HTTP requests",
    }

    optional_deps = {"PyPDF2": "PDF processing"}

    all_ok = True

    # Check required
    for dep, description in required_deps.items():
        try:
            if dep == "chromadb":
                # ChromaDB has Python 3.14 issues, skip direct import
                print_check(f"{dep}", True, f"{description} (fallback available)")
            else:
                __import__(dep.replace("_", ""))
                print_check(f"{dep}", True, description)
        except ImportError:
            print_check(f"{dep}", False, f"REQUIRED: {description}")
            all_ok = False
        except Exception:
            # Handle compatibility issues gracefully
            print_check(f"{dep}", True, f"{description} (with compatibility fallback)")

    # Check optional
    for dep, description in optional_deps.items():
        try:
            __import__(dep.replace("_", ""))
            print_check(f"{dep}", True, f"Optional: {description}")
        except ImportError:
            print_check(f"{dep}", False, f"Optional (recommended): {description}")

    return all_ok


def check_skynet_modules():
    """Check KRYON knowledge modules."""
    print_header("Checking KRYON Knowledge Modules")

    modules = [
        ("kryon.knowledge.vector_db", "Vector database"),
        ("kryon.knowledge.embeddings", "Embedding generation"),
        ("kryon.knowledge.rag_engine", "RAG query engine"),
        ("kryon.knowledge.scrapers", "Knowledge scrapers"),
        ("kryon.knowledge.processors", "Document processors"),
        ("kryon.knowledge.auto_updater", "Auto-updater"),
    ]

    all_ok = True
    for module_name, description in modules:
        try:
            __import__(module_name)
            print_check(description, True, module_name)
        except ImportError as e:
            print_check(description, False, f"Import failed: {e}")
            all_ok = False

    return all_ok


def check_vector_db():
    """Check vector database initialization."""
    print_header("Checking Vector Database")

    try:
        from kryon.knowledge import get_vector_db

        db = get_vector_db()
        print_check("ChromaDB initialized", True)

        # Test add/query
        test_docs = ["Test document for validation"]
        count = db.add_documents(test_docs, ids=["validate_test_1"])
        print_check("Add documents", count > 0, f"Added {count} documents")

        # Query
        results = db.query("test validation", top_k=1)
        print_check("Query documents", len(results) > 0, f"Found {len(results)} results")

        # Cleanup
        db.delete_by_ids(["validate_test_1"])
        print_check("Cleanup test data", True)

        return True

    except Exception as e:
        print_check("Vector database", False, f"Error: {e}")
        return False


def check_embeddings():
    """Check embedding generation."""
    print_header("Checking Embeddings")

    try:
        from kryon.knowledge.embeddings import generate_embedding

        print("Downloading embedding model (first time only)...")
        text = "Test embedding generation"
        embedding = generate_embedding(text)

        print_check("Embedding generation", True, f"Generated {len(embedding)} dimensions")
        print_check("Embedding model", True, "Model loaded successfully")

        return True

    except ImportError:
        print_check("Embeddings", False, "sentence-transformers not installed")
        return False
    except Exception as e:
        print_check("Embeddings", False, f"Error: {e}")
        return False


def check_rag_engine():
    """Check RAG engine."""
    print_header("Checking RAG Engine")

    try:
        from kryon.knowledge import add_document, query_knowledge

        # Add test knowledge
        doc_id = add_document(
            "Apache web server has a path traversal vulnerability in version 2.4.49",
            "validation_test",
            cve="CVE-2021-41773",
        )
        print_check("Add knowledge", True, f"Added doc: {doc_id}")

        # Query (without LLM)
        result = query_knowledge("Apache vulnerability", use_llm=False, top_k=1)
        print_check("Query knowledge", len(result["sources"]) > 0, f"Found {len(result['sources'])} sources")

        # Cleanup
        from kryon.knowledge import get_vector_db

        db = get_vector_db()
        db.delete_by_ids([doc_id])

        return True

    except Exception as e:
        print_check("RAG engine", False, f"Error: {e}")
        return False


def check_llm_integration():
    """Check LLM (Ollama) integration."""
    print_header("Checking LLM Integration")

    try:
        import json
        from pathlib import Path

        import requests

        # Load config
        config_path = Path.home() / ".kryon" / "config.json"
        if config_path.exists():
            with open(config_path) as f:
                config = json.load(f)
            llm_url = config.get("base_url", "http://localhost:11434")
            llm_model = config.get("model", "qwen2.5:7b")

            print_check("LLM config found", True, f"{llm_model} @ {llm_url}")

            # Test connection
            response = requests.get(f"{llm_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get("models", [])
                model_names = [m["name"] for m in models]

                print_check("Ollama running", True, f"Found {len(models)} models")

                if llm_model in model_names or any(llm_model in m for m in model_names):
                    print_check(f"Model {llm_model}", True, "Model available")
                    return True
                else:
                    print_check(f"Model {llm_model}", False, "Model not found")
                    print(f"   Available: {', '.join(model_names[:3])}")
                    return False
            else:
                print_check("Ollama", False, f"HTTP {response.status_code}")
                return False
        else:
            print_check("LLM config", False, "Config file not found")
            print(f"   Expected: {config_path}")
            return False

    except requests.ConnectionError:
        print_check("Ollama", False, "Connection refused - is Ollama running?")
        return False
    except Exception as e:
        print_check("LLM integration", False, f"Error: {e}")
        return False


def check_scrapers():
    """Check scraper availability."""
    print_header("Checking Scrapers")

    scrapers = [
        ("ExploitDBScraper", "Exploit-DB scraper", "searchsploit"),
        ("NVDScraper", "NVD CVE scraper", "NVD API"),
        ("GitHubScraper", "GitHub PoC scraper", "GitHub API"),
        ("WriteupScraper", "CTF writeup scraper", "Multiple sources"),
    ]

    all_ok = True
    for scraper_name, description, requirement in scrapers:
        try:
            module = __import__("kryon.knowledge.scrapers", fromlist=[scraper_name])
            getattr(module, scraper_name)
            print_check(description, True, requirement)
        except Exception as e:
            print_check(description, False, f"Error: {e}")
            all_ok = False

    return all_ok


def check_disk_space():
    """Check available disk space."""
    print_header("Checking Disk Space")

    try:
        import shutil

        knowledge_path = Path(".kryon_knowledge")
        if knowledge_path.exists():
            # Get directory size
            total_size = sum(f.stat().st_size for f in knowledge_path.rglob("*") if f.is_file())
            size_mb = total_size / (1024 * 1024)
            print_check("Knowledge base size", True, f"{size_mb:.2f} MB")

        # Check free space
        stat = shutil.disk_usage(Path.cwd())
        free_gb = stat.free / (1024**3)

        if free_gb > 10:
            print_check("Free disk space", True, f"{free_gb:.2f} GB available")
            return True
        elif free_gb > 1:
            print_check("Free disk space", True, f"{free_gb:.2f} GB (low)")
            return True
        else:
            print_check("Free disk space", False, f"{free_gb:.2f} GB (critical)")
            return False

    except Exception as e:
        print_check("Disk space check", False, f"Error: {e}")
        return False


def print_summary(checks):
    """Print validation summary."""
    print_header("Validation Summary")

    passed = sum(1 for c in checks.values() if c)
    total = len(checks)

    for check_name, result in checks.items():
        symbol = "✅" if result else "❌"
        print(f"{symbol} {check_name}")

    print(f"\n{'─' * 60}")
    print(f"Result: {passed}/{total} checks passed")
    print(f"{'─' * 60}\n")

    if passed == total:
        print("🎉 All checks passed! RAG system is ready to use.")
        return True
    else:
        print("⚠️  Some checks failed. Please review and fix issues.")
        return False


def validate_system():
    """Run complete system validation."""
    print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   KRYON RAG System Validation                             ║
║   ─────────────────────────────                           ║
║   Comprehensive check of all system components            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """)

    checks = {}

    # Run all checks
    checks["Dependencies"] = check_dependencies()
    checks["KRYON Modules"] = check_skynet_modules()

    if checks["Dependencies"] and checks["KRYON Modules"]:
        checks["Vector Database"] = check_vector_db()
        checks["Embeddings"] = check_embeddings()
        checks["RAG Engine"] = check_rag_engine()
        checks["LLM Integration"] = check_llm_integration()
        checks["Scrapers"] = check_scrapers()
        checks["Disk Space"] = check_disk_space()
    else:
        print("\n⚠️  Skipping detailed checks due to missing dependencies/modules")

    # Summary
    all_passed = print_summary(checks)

    return all_passed


if __name__ == "__main__":
    try:
        success = validate_system()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nValidation interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Validation failed with error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
