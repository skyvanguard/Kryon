"""
SKYNET Knowledge Base - RAG System
==================================

Retrieval-Augmented Generation system for massive knowledge access.

Clearance Level: Omega-Strategic (Knowledge Enhancement Authority)
Classification: RESTRICTED
Mission: Provide SKYNET with access to massive cybersecurity knowledge

Features:
- Vector database for semantic search (ChromaDB)
- Multi-source knowledge scraping (Exploit-DB, NVD, GitHub, writeups)
- Automatic updates (daily/weekly)
- Document processing pipeline
- RAG query engine integrated with LLM

Example Usage:
    >>> from skynet.knowledge import query_knowledge, auto_update_knowledge
    >>>
    >>> # Query knowledge base
    >>> results = query_knowledge(
    ...     "How to exploit SQL injection in MySQL?",
    ...     top_k=5
    ... )
    >>>
    >>> for result in results:
    ...     print(f"{result['source']}: {result['content'][:100]}...")
    >>>
    >>> # Start automatic updates
    >>> auto_update_knowledge(
    ...     schedule="daily",
    ...     sources=["exploit-db", "nvd", "github"]
    ... )
"""

from .rag_engine import (
    query_knowledge,
    add_document,
    get_knowledge_stats,
    RAGEngine,
    get_rag_engine
)

from .vector_db import (
    VectorDatabase,
    get_vector_db
)

from .auto_updater import (
    auto_update_knowledge,
    start_auto_updater,
    stop_auto_updater
)

from .exploitdb_scraper import (
    ExploitDBScraper,
    scrape_exploitdb,
    get_exploitdb_stats
)

__all__ = [
    # RAG Engine
    "query_knowledge",
    "add_document",
    "get_knowledge_stats",
    "RAGEngine",
    "get_rag_engine",
    # Vector Database
    "VectorDatabase",
    "get_vector_db",
    # Auto-updater
    "auto_update_knowledge",
    "start_auto_updater",
    "stop_auto_updater",
    # Exploit-DB Scraper
    "ExploitDBScraper",
    "scrape_exploitdb",
    "get_exploitdb_stats",
]
