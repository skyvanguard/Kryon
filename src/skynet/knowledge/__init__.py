"""
KRYON Knowledge Base - RAG System
==================================

Retrieval-Augmented Generation system for massive knowledge access.

Clearance Level: Omega-Strategic (Knowledge Enhancement Authority)
Classification: RESTRICTED
Mission: Provide KRYON with access to massive cybersecurity knowledge

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

from .async_rag_engine import (
    AsyncRAGEngine,
    get_async_knowledge_stats,
    get_async_rag_engine,
    query_knowledge_async,
    query_knowledge_batch,
)
from .async_vector_db import (
    AsyncVectorDatabase,
    add_documents_async,
    get_async_vector_db,
    query_async,
)
from .auto_updater import auto_update_knowledge, start_auto_updater, stop_auto_updater
from .exploitdb_scraper import ExploitDBScraper, get_exploitdb_stats, scrape_exploitdb
from .rag_engine import (
    RAGEngine,
    add_document,
    get_knowledge_stats,
    get_rag_engine,
    query_knowledge,
)
from .streaming_rag import StreamingRAGEngine, get_streaming_rag_engine, query_knowledge_stream
from .vector_db import VectorDatabase, get_vector_db

__all__ = [
    # RAG Engine
    "query_knowledge",
    "add_document",
    "get_knowledge_stats",
    "RAGEngine",
    "get_rag_engine",
    # Async RAG Engine
    "AsyncRAGEngine",
    "get_async_rag_engine",
    "query_knowledge_async",
    "query_knowledge_batch",
    "get_async_knowledge_stats",
    # Streaming RAG Engine
    "StreamingRAGEngine",
    "get_streaming_rag_engine",
    "query_knowledge_stream",
    # Vector Database
    "VectorDatabase",
    "get_vector_db",
    # Async Vector Database
    "AsyncVectorDatabase",
    "get_async_vector_db",
    "add_documents_async",
    "query_async",
    # Auto-updater
    "auto_update_knowledge",
    "start_auto_updater",
    "stop_auto_updater",
    # Exploit-DB Scraper
    "ExploitDBScraper",
    "scrape_exploitdb",
    "get_exploitdb_stats",
]
