"""
KRYON Knowledge RAG Tools
===========================

Tools for accessing the RAG knowledge base from agents.

Clearance Level: Omega-Strategic
Classification: RESTRICTED
"""

import sys
from pathlib import Path
from typing import Any, Optional

from kryon.sdk.agents import function_tool

# Add src to path for imports
_src_path = Path(__file__).parent.parent.parent
if str(_src_path) not in sys.path:
    sys.path.insert(0, str(_src_path))


@function_tool
def query_knowledge_base(
    question: str, top_k: int = 3, source_filter: str | None = None, use_llm: bool = False
) -> dict[str, Any]:
    """
    Query the KRYON knowledge base with RAG.

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
        from kryon.knowledge import query_knowledge

        result = query_knowledge(question=question, top_k=top_k, source_filter=source_filter, use_llm=use_llm)

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


# Relevance thresholds for RAG-returned CVEs.
# The RAG engine returns *negative* relevance scores where higher (closer to 0)
# means more relevant. Empirically -250 is the boundary below which results are
# semantic noise (e.g. CVEs of unrelated products that happen to share tokens).
_SEARCH_VULNS_HARD_DISCARD = -250.0
_SEARCH_VULNS_HIGH_CONFIDENCE = -100.0

# Generic terms that should NOT count as a tech-match (would let almost anything pass).
_TECH_MATCH_STOPWORDS = {"http", "web", "api", "server", "service", "ssl", "tls"}


def _tech_match(technology: str, *fields: Any) -> bool:
    """Return True when the technology name appears literally in any field.

    Avoids false positives from semantic-only matches (e.g. an "Apache" query
    pulling Telesquare/Serviio CVEs that share embedding space but never
    mention Apache in their actual text).
    """
    tech = (technology or "").strip().lower()
    if not tech or tech in _TECH_MATCH_STOPWORDS:
        return True  # Stopword-only queries can't be validated; skip the check.
    for field in fields:
        if not field:
            continue
        if tech in str(field).lower():
            return True
    return False


def _confidence_label(score: float) -> str:
    if score >= _SEARCH_VULNS_HIGH_CONFIDENCE:
        return "high"
    if score >= _SEARCH_VULNS_HARD_DISCARD:
        return "medium"
    return "low"


@function_tool
def search_vulnerabilities(
    technology: str,
    version: Optional[str] = None,  # noqa: UP045 — keep symmetry with sibling tools in this module
    severity_min: Optional[str] = None,  # noqa: UP045
    max_results: int = 5,
    min_score: float = _SEARCH_VULNS_HARD_DISCARD,
    require_tech_match: bool = True,
) -> dict[str, Any]:
    """
    Search for vulnerabilities related to a specific technology.

    Args:
        technology: Technology name (e.g., "apache", "wordpress")
        version: Specific version (e.g., "2.4.49")
        severity_min: Minimum severity ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        max_results: Maximum results to return
        min_score: Hard cutoff for RAG relevance score. Results below this
            are dropped to avoid hallucinations from low-relevance hits.
        require_tech_match: When True, drop results whose description does
            not literally mention the queried technology.

    Returns:
        Dictionary with matching CVEs (each with a `confidence` label) plus
        a `discarded` list explaining why noisy results were filtered out.
    """
    try:
        from kryon.knowledge import query_knowledge

        # Over-fetch so the post-filter still has results to return.
        fetch_k = max(max_results * 3, max_results + 5)

        query = f"vulnerabilities in {technology}"
        if version:
            query += f" version {version}"

        result = query_knowledge(
            question=query,
            top_k=fetch_k,
            source_filter="nvd",
            use_llm=False,
        )

        severity_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        min_severity_idx = severity_levels.index(severity_min) if severity_min in severity_levels else None

        vulnerabilities: list[dict[str, Any]] = []
        discarded: list[dict[str, Any]] = []

        for src in result["sources"]:
            metadata = src.get("metadata", {}) or {}
            content = src.get("content", "") or ""
            score = float(src.get("score", 0.0))
            cve_id = metadata.get("cve_id", "Unknown")

            if score < min_score:
                discarded.append(
                    {"cve_id": cve_id, "reason": f"low_relevance: score {score:.2f} < {min_score:.2f}"}
                )
                continue

            if require_tech_match and not _tech_match(
                technology, content, metadata.get("affected_product"), metadata.get("title")
            ):
                snippet = content[:80].replace("\n", " ")
                discarded.append(
                    {
                        "cve_id": cve_id,
                        "reason": f"tech_mismatch: '{technology}' not found in description ({snippet!r})",
                    }
                )
                continue

            if min_severity_idx is not None:
                src_severity = metadata.get("severity", "UNKNOWN")
                if src_severity in severity_levels:
                    if severity_levels.index(src_severity) < min_severity_idx:
                        discarded.append(
                            {"cve_id": cve_id, "reason": f"below_severity_min: {src_severity} < {severity_min}"}
                        )
                        continue

            vulnerabilities.append(
                {
                    "cve_id": cve_id,
                    "severity": metadata.get("severity", "Unknown"),
                    "cvss_score": metadata.get("cvss_score", "N/A"),
                    "description": content[:1500],
                    "score": score,
                    "confidence": _confidence_label(score),
                    "published": metadata.get("published", "Unknown"),
                }
            )

            if len(vulnerabilities) >= max_results:
                break

        return {
            "success": True,
            "technology": technology,
            "version": version,
            "vulnerabilities": vulnerabilities,
            "count": len(vulnerabilities),
            "discarded": discarded,
            "discarded_count": len(discarded),
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "technology": technology,
            "vulnerabilities": [],
            "count": 0,
            "discarded": [],
            "discarded_count": 0,
        }


@function_tool
def get_exploit_techniques(attack_type: str, platform: str | None = None, max_results: int = 3) -> dict[str, Any]:
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
        from kryon.knowledge import query_knowledge

        # Build query
        query = f"{attack_type} exploitation techniques"
        if platform:
            query += f" on {platform}"

        # Query with LLM for summary
        result = query_knowledge(question=query, top_k=max_results, use_llm=False)

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


@function_tool
def get_security_tools(purpose: str, max_results: int = 5) -> dict[str, Any]:
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
        from kryon.knowledge import query_knowledge

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


@function_tool
def get_knowledge_stats() -> dict[str, Any]:
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
        from kryon.knowledge.rag_engine import RAGEngine

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
