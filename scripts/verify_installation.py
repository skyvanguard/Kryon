#!/usr/bin/env python3
"""
Verify Skynet installation on your notebook/local machine.
Run this after installing dependencies to check everything works.
"""
import sys
from pathlib import Path

def test_import(module_name, display_name=None):
    """Test if a module can be imported."""
    if display_name is None:
        display_name = module_name

    try:
        __import__(module_name)
        print(f"✅ {display_name}")
        return True
    except ImportError as e:
        print(f"❌ {display_name} - {e}")
        return False

def main():
    print("🧪 Skynet Installation Verification")
    print("=" * 60)
    print()

    results = {}

    # Core Python modules
    print("📦 Core Dependencies:")
    results['numpy'] = test_import('numpy', 'NumPy')
    results['pandas'] = test_import('pandas', 'Pandas')
    print()

    # Optional AI dependencies
    print("🤖 AI Dependencies (Optional):")
    results['anthropic'] = test_import('anthropic', 'Anthropic API')
    results['openai'] = test_import('openai', 'OpenAI API')
    results['chromadb'] = test_import('chromadb', 'ChromaDB')
    results['sentence_transformers'] = test_import('sentence_transformers', 'Sentence Transformers')
    print()

    # Skynet modules
    print("🛸 Skynet Modules:")
    sys.path.insert(0, str(Path(__file__).parent.parent))

    results['skynet_core'] = test_import('skynet.core.config', 'Skynet Core')
    results['skynet_tools'] = test_import('skynet.tools.network', 'Skynet Tools')
    results['skynet_agents'] = test_import('skynet.agents.base_agent', 'Skynet Agents')
    results['skynet_rag'] = test_import('skynet.rag.retriever', 'Skynet RAG')
    results['skynet_cli'] = test_import('skynet.cli.quick', 'Skynet CLI')
    print()

    # Test core functionality
    print("🔧 Core Functionality:")
    try:
        from skynet.core.flag_detector import get_flag_detector
        detector = get_flag_detector()
        test_flags = detector.detect("HTB{test_flag}", "test")
        if test_flags:
            print(f"✅ Flag Detection (detected: {test_flags[0].value})")
            results['flag_detection'] = True
        else:
            print("⚠️  Flag Detection (not detecting)")
            results['flag_detection'] = False
    except Exception as e:
        print(f"❌ Flag Detection - {e}")
        results['flag_detection'] = False

    try:
        from skynet.tools.network import NetworkTools
        net = NetworkTools()
        print("✅ Network Tools")
        results['network_tools'] = True
    except Exception as e:
        print(f"❌ Network Tools - {e}")
        results['network_tools'] = False

    try:
        from skynet.core.executor import CommandExecutor
        executor = CommandExecutor()
        result = executor.execute("echo 'test'", timeout=5)
        if result.success:
            print("✅ Command Executor")
            results['executor'] = True
        else:
            print("⚠️  Command Executor (not working)")
            results['executor'] = False
    except Exception as e:
        print(f"❌ Command Executor - {e}")
        results['executor'] = False

    print()

    # Summary
    print("=" * 60)
    print("📊 Installation Summary")
    print("=" * 60)

    core_working = all([
        results.get('skynet_core'),
        results.get('skynet_tools'),
        results.get('flag_detection')
    ])

    rag_working = all([
        results.get('chromadb'),
        results.get('skynet_rag')
    ])

    print()
    if core_working:
        print("✅ Core functionality: WORKING")
        print("   You can use Skynet tools and flag detection!")
    else:
        print("❌ Core functionality: NOT WORKING")
        print("   Check the errors above and reinstall.")

    print()
    if rag_working:
        print("✅ RAG system: WORKING")
        print("   You can use knowledge base and semantic search!")
    else:
        print("⚠️  RAG system: NOT AVAILABLE")
        print("   Install chromadb to use RAG: pip install chromadb")

    print()
    print("💡 Quick Tests:")
    print()
    print("  # Test flag detection")
    print("  python -c \"from skynet.core.flag_detector import detect_flags_in_output; print(detect_flags_in_output('HTB{test}', 'test'))\"")
    print()
    print("  # Test quick commands")
    print("  python -m skynet.cli.quick flags count")
    print()

    if rag_working:
        print("  # Initialize knowledge base")
        print("  python scripts/init_knowledge.py")
        print()
        print("  # Search knowledge")
        print("  python -m skynet.cli.quick search 'sql injection'")
        print()

    print("📖 See NOTEBOOK_SETUP.md for detailed usage examples")
    print()

    # Return exit code
    if core_working:
        return 0
    else:
        return 1

if __name__ == "__main__":
    sys.exit(main())
