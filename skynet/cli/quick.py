"""
Quick commands for Claude Code integration.
Simple, fast CLI commands that return JSON for easy parsing.
"""
import json
import sys
from pathlib import Path
from typing import Dict, Any

from ..tools.network import NetworkTools
from ..tools.web import WebTools
from ..tools.analysis import AnalysisTools
from ..rag.retriever import get_retriever
from ..core.flag_detector import get_flag_detector
from ..core.logging import get_logger


def json_output(data: Dict[str, Any]):
    """Output data as JSON."""
    print(json.dumps(data, indent=2, default=str))


def cmd_scan(target: str) -> Dict:
    """Quick port scan."""
    logger = get_logger()
    logger.info(f"Scanning {target}")

    net = NetworkTools()
    result = net.quick_scan(target)

    flag_detector = get_flag_detector()
    flags = flag_detector.detect(result.scan_output, source=f"scan:{target}")

    return {
        "success": result.success,
        "target": target,
        "open_ports": result.open_ports,
        "flags_found": [f.value for f in flags],
        "raw_output": result.scan_output[:1000]  # Truncate
    }


def cmd_enum_web(url: str) -> Dict:
    """Quick web enumeration."""
    logger = get_logger()
    logger.info(f"Enumerating {url}")

    web = WebTools()

    # Get headers
    headers = web.get_headers(url)

    # Quick directory scan
    dir_result = web.directory_bruteforce(url, timeout=60)

    flag_detector = get_flag_detector()
    flags = flag_detector.detect(str(headers), source=f"web:{url}")

    return {
        "success": True,
        "url": url,
        "headers": headers,
        "found_paths": dir_result.found_paths[:20],  # Top 20
        "flags_found": [f.value for f in flags],
        "server": headers.get("Server", "unknown")
    }


def cmd_analyze(file_path: str) -> Dict:
    """Quick file analysis."""
    logger = get_logger()
    logger.info(f"Analyzing {file_path}")

    path = Path(file_path)
    if not path.exists():
        return {"success": False, "error": f"File not found: {file_path}"}

    tools = AnalysisTools()
    analysis = tools.analyze_file(path)

    flag_detector = get_flag_detector()
    flags = flag_detector.detect_in_file(path)

    return {
        "success": True,
        "file": str(path),
        "type": analysis.file_type,
        "size": analysis.size,
        "md5": analysis.md5,
        "sha256": analysis.sha256,
        "interesting_strings": analysis.strings_found[:20],
        "flags_found": [f.value for f in flags],
        "entropy": tools.file_entropy(path)
    }


def cmd_search(query: str, limit: int = 5) -> Dict:
    """Search knowledge base."""
    logger = get_logger()
    logger.info(f"Searching: {query}")

    retriever = get_retriever()
    results = retriever.retrieve(query, top_k=limit)

    return {
        "success": True,
        "query": query,
        "results_count": len(results),
        "results": [
            {
                "content": r.content[:200],  # Truncate
                "category": r.metadata.get("category", "unknown"),
                "relevance": r.relevance_score
            }
            for r in results
        ]
    }


def cmd_crack(hash_value: str) -> Dict:
    """Quick hash cracking attempt."""
    logger = get_logger()
    logger.info(f"Cracking hash: {hash_value[:20]}...")

    tools = AnalysisTools()
    result = tools.crack_hash(hash_value)

    return {
        "success": result.cracked,
        "hash": hash_value,
        "hash_type": result.hash_type,
        "cracked": result.cracked,
        "plaintext": result.plaintext if result.cracked else None,
        "method": result.method
    }


def cmd_flags(action: str = "list") -> Dict:
    """Manage flags."""
    detector = get_flag_detector()

    if action == "list":
        flags = detector.get_found_flags()
        return {
            "success": True,
            "count": len(flags),
            "flags": flags
        }

    elif action == "count":
        return {
            "success": True,
            "count": detector.count_flags()
        }

    elif action == "clear":
        detector.clear_flags()
        return {
            "success": True,
            "message": "Flags cleared"
        }

    return {"success": False, "error": "Unknown action"}


def cmd_exploit_check(binary_path: str) -> Dict:
    """Quick binary security check."""
    logger = get_logger()
    logger.info(f"Checking {binary_path}")

    path = Path(binary_path)
    if not path.exists():
        return {"success": False, "error": f"Binary not found: {binary_path}"}

    from ..agents.exploit_agent import ExploitAgent
    agent = ExploitAgent()

    security = agent._tool_check_security(binary_path)

    return {
        "success": True,
        "binary": str(path),
        "security": security,
        "exploitable": "DISABLED" in security
    }


# CLI entry point for quick commands
def main():
    """Quick commands CLI."""
    if len(sys.argv) < 2:
        print("Usage: python -m skynet.cli.quick <command> [args]", file=sys.stderr)
        print("\nCommands:", file=sys.stderr)
        print("  scan <target>           - Quick port scan", file=sys.stderr)
        print("  enum-web <url>          - Web enumeration", file=sys.stderr)
        print("  analyze <file>          - File analysis", file=sys.stderr)
        print("  search <query>          - Search knowledge", file=sys.stderr)
        print("  crack <hash>            - Crack hash", file=sys.stderr)
        print("  flags [list|count]      - Manage flags", file=sys.stderr)
        print("  exploit-check <binary>  - Check binary security", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1]

    try:
        if command == "scan" and len(sys.argv) >= 3:
            result = cmd_scan(sys.argv[2])
        elif command == "enum-web" and len(sys.argv) >= 3:
            result = cmd_enum_web(sys.argv[2])
        elif command == "analyze" and len(sys.argv) >= 3:
            result = cmd_analyze(sys.argv[2])
        elif command == "search" and len(sys.argv) >= 3:
            result = cmd_search(" ".join(sys.argv[2:]))
        elif command == "crack" and len(sys.argv) >= 3:
            result = cmd_crack(sys.argv[2])
        elif command == "flags":
            action = sys.argv[2] if len(sys.argv) >= 3 else "list"
            result = cmd_flags(action)
        elif command == "exploit-check" and len(sys.argv) >= 3:
            result = cmd_exploit_check(sys.argv[2])
        else:
            result = {"success": False, "error": "Invalid command or missing arguments"}

        json_output(result)

    except Exception as e:
        json_output({"success": False, "error": str(e)})
        sys.exit(1)


if __name__ == "__main__":
    main()
