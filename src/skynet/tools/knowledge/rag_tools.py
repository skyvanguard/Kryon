"""
SKYNET Knowledge RAG Tools
===========================

Tools for accessing the RAG knowledge base from agents.

Clearance Level: Omega-Strategic
Classification: RESTRICTED
"""

import sys
from pathlib import Path
from typing import Any, Dict, Optional

# Add src to path for imports
_src_path = Path(__file__).parent.parent.parent
if str(_src_path) not in sys.path:
    sys.path.insert(0, str(_src_path))


def query_knowledge_base(
    question: str, top_k: int = 3, source_filter: Optional[str] = None, use_llm: bool = True
) -> Dict[str, Any]:
    """
    Query the SKYNET knowledge base with RAG.

    Args:
        question: Question to answer
        top_k: Number of documents to retrieve (default: 3)
        source_filter: Filter by source (e.g., "nvd", "github")
        use_llm: Whether to use LLM for answer generation (default: True)

    Returns:
        Dictionary with:
        - question: Original question
        - answer: LLM-generated answer (if use_llm=True)
        - sources: Retrieved documents with metadata
        - context_used: Context provided to LLM

    Example:
        >>> result = query_knowledge_base("SQL injection techniques")
        >>> print(result['answer'])
        >>> for src in result['sources']:
        ...     print(f"- {src['metadata']['source']}: {src['content'][:100]}")
    """
    try:
        from skynet.knowledge import query_knowledge

        result = query_knowledge(
            question=question, top_k=top_k, source_filter=source_filter, use_llm=use_llm
        )

        return {
            "success": True,
            "question": result["question"],
            "answer": result.get("answer", ""),
            "sources": result["sources"],
            "num_sources": len(result["sources"]),
            "context_used": result.get("context_used", ""),
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "question": question,
            "answer": "",
            "sources": [],
            "num_sources": 0,
        }


def search_vulnerabilities(
    technology: str,
    version: Optional[str] = None,
    severity_min: Optional[str] = None,
    max_results: int = 5,
) -> Dict[str, Any]:
    """
    Search for vulnerabilities related to a specific technology.

    Args:
        technology: Technology name (e.g., "apache", "wordpress")
        version: Specific version (e.g., "2.4.49")
        severity_min: Minimum severity ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        max_results: Maximum results to return

    Returns:
        Dictionary with matching CVEs and exploits

    Example:
        >>> result = search_vulnerabilities("apache", "2.4.49", "HIGH")
        >>> for vuln in result['vulnerabilities']:
        ...     print(f"{vuln['cve_id']}: {vuln['severity']}")
    """
    try:
        from skynet.knowledge import query_knowledge

        # Build query
        query = f"vulnerabilities in {technology}"
        if version:
            query += f" version {version}"

        # Query knowledge base
        result = query_knowledge(
            question=query,
            top_k=max_results,
            source_filter="nvd",  # Focus on CVEs
            use_llm=False,  # Just retrieval
        )

        vulnerabilities = []
        for src in result["sources"]:
            metadata = src.get("metadata", {})

            # Filter by severity if specified
            if severity_min:
                src_severity = metadata.get("severity", "UNKNOWN")
                severity_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

                if src_severity in severity_levels:
                    min_idx = severity_levels.index(severity_min)
                    src_idx = severity_levels.index(src_severity)
                    if src_idx < min_idx:
                        continue

            vulnerabilities.append(
                {
                    "cve_id": metadata.get("cve_id", "Unknown"),
                    "severity": metadata.get("severity", "Unknown"),
                    "cvss_score": metadata.get("cvss_score", "N/A"),
                    "description": src["content"][:200] + "...",
                    "score": src["score"],
                    "published": metadata.get("published", "Unknown"),
                }
            )

        return {
            "success": True,
            "technology": technology,
            "version": version,
            "vulnerabilities": vulnerabilities,
            "count": len(vulnerabilities),
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "technology": technology,
            "vulnerabilities": [],
            "count": 0,
        }


def get_exploit_techniques(
    attack_type: str, platform: Optional[str] = None, max_results: int = 3
) -> Dict[str, Any]:
    """
    Get exploit techniques for a specific attack type.

    Args:
        attack_type: Type of attack (e.g., "sqli", "xss", "rce", "privesc")
        platform: Target platform (e.g., "linux", "windows", "web")
        max_results: Maximum results to return

    Returns:
        Dictionary with exploit techniques and examples

    Example:
        >>> result = get_exploit_techniques("sqli", "web")
        >>> print(result['summary'])
        >>> for technique in result['techniques']:
        ...     print(f"- {technique['name']}")
    """
    try:
        from skynet.knowledge import query_knowledge

        # Build query
        query = f"{attack_type} exploitation techniques"
        if platform:
            query += f" on {platform}"

        # Query with LLM for summary
        result = query_knowledge(question=query, top_k=max_results, use_llm=True)

        techniques = []
        for src in result["sources"]:
            techniques.append(
                {
                    "source": src["metadata"].get("source", "unknown"),
                    "content": src["content"],
                    "relevance": src["score"],
                }
            )

        return {
            "success": True,
            "attack_type": attack_type,
            "platform": platform,
            "summary": result.get("answer", ""),
            "techniques": techniques,
            "count": len(techniques),
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "attack_type": attack_type,
            "techniques": [],
            "count": 0,
        }


def get_security_tools(purpose: str, max_results: int = 5) -> Dict[str, Any]:
    """
    Get security tools for a specific purpose.

    Args:
        purpose: Purpose/category (e.g., "web scanning", "network analysis")
        max_results: Maximum results to return

    Returns:
        Dictionary with security tools from GitHub

    Example:
        >>> result = get_security_tools("web vulnerability scanning")
        >>> for tool in result['tools']:
        ...     print(f"- {tool['name']}: {tool['description']}")
    """
    try:
        from skynet.knowledge import query_knowledge

        # Query GitHub repositories
        result = query_knowledge(
            question=f"security tools for {purpose}",
            top_k=max_results,
            source_filter="github",
            use_llm=False,
        )

        tools = []
        for src in result["sources"]:
            metadata = src.get("metadata", {})
            tools.append(
                {
                    "name": metadata.get("repo_name", "Unknown"),
                    "description": src["content"][:150],
                    "stars": metadata.get("stars", 0),
                    "url": metadata.get("url", ""),
                    "relevance": src["score"],
                }
            )

        return {"success": True, "purpose": purpose, "tools": tools, "count": len(tools)}

    except Exception as e:
        return {"success": False, "error": str(e), "purpose": purpose, "tools": [], "count": 0}


def get_knowledge_stats() -> Dict[str, Any]:
    """
    Get statistics about the knowledge base.

    Returns:
        Dictionary with knowledge base statistics

    Example:
        >>> stats = get_knowledge_stats()
        >>> print(f"Total documents: {stats['total_documents']}")
        >>> print(f"Sources: {stats['sources']}")
    """
    try:
        from skynet.knowledge.rag_engine import RAGEngine

        rag = RAGEngine()
        stats = rag.get_stats()

        return {
            "success": True,
            "total_documents": stats.get("total_knowledge_items", 0),
            "llm_configured": stats.get("llm_configured", False),
            "llm_model": stats.get("llm_model", "Unknown"),
            "vector_db_path": stats.get("vector_db_path", "Unknown"),
        }

    except Exception as e:
        return {"success": False, "error": str(e), "total_documents": 0}


# Tool definitions for agent integration
__all__ = [
    "query_knowledge_base",
    "search_vulnerabilities",
    "get_exploit_techniques",
    "get_security_tools",
    "get_knowledge_stats",
]
