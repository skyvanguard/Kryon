"""
RAG (Retrieval Augmented Generation) utilities module for
querying and adding data to vector databases.

Uses kryon.knowledge.simple_vector_db as backend (ChromaDB or SimpleVectorDB fallback).
"""

import os
import threading
import uuid

from kryon.knowledge.simple_vector_db import get_vector_db
from kryon.sdk.agents import function_tool

# CTF BASED MEMORY
collection_name = os.getenv("KRYON_MEMORY_COLLECTION", "default")

# Shared DB instance (double-checked locking)
_db = None
_db_lock = threading.Lock()


def _get_db():
    """Get or initialize the vector database instance."""
    global _db
    if _db is None:
        with _db_lock:
            if _db is None:
                persist_dir = os.path.expanduser("~/.kryon/vector_db")
                _db = get_vector_db(persist_dir)
    return _db


def query_memory_impl(query: str, top_k: int = 3) -> str:
    """Raw implementation of query_memory (callable without FunctionTool wrapper)."""
    try:
        db = _get_db()
        results = db.query(query_text=query, top_k=top_k)

        if not results:
            return "No documents found in memory."

        formatted = []
        for r in results:
            score = r.get("score", 0)
            content = r.get("content", "")
            formatted.append(f"[{score:.2f}] {content}")

        return "\n---\n".join(formatted)

    except Exception as e:  # pylint: disable=broad-exception-caught
        return f"Error querying memory: {str(e)}"


@function_tool(strict_mode=False)
def query_memory(query: str, top_k: int = 3, **kwargs) -> str:  # pylint: disable=unused-argument,line-too-long # noqa: E501
    """
    Query memory to retrieve relevant context. From Previous CTFs executions.

    Args:
        query (str): The search query to find relevant documents
        top_k (int): Number of top results to return (default: 3)

    Returns:
        str: Retrieved context from the vector database, formatted as a string
            with the most relevant matches
    """
    return query_memory_impl(query, top_k)


@function_tool(strict_mode=False)
def add_to_memory_episodic(texts: str, step: int = 0, **kwargs) -> str:  # pylint: disable=unused-argument,line-too-long # noqa: E501
    """
    This is a persistent memory to add relevant context to our memory.
    Use this function to add relevant context to the memory.

    Args:
        texts: relevant data to add to memory
        step: step number of the current CTF
    Returns:
        str: Status message indicating success or failure
    """
    try:
        db = _get_db()
        doc_id = f"{collection_name}_step_{step}_{uuid.uuid4().hex[:8]}"
        count = db.add_documents(
            documents=[texts],
            metadatas=[{"collection": collection_name, "CTF": True, "step": step}],
            ids=[doc_id],
        )
        if count > 0:
            return f"Successfully added document to collection {collection_name}"
        return "Failed to add documents to vector database"

    except Exception as e:  # pylint: disable=broad-exception-caught
        return f"Error adding documents to vector database: {str(e)}"


@function_tool(strict_mode=False)
def add_to_memory_semantic(texts: str, step: int = 0, **kwargs) -> str:  # pylint: disable=unused-argument,line-too-long # noqa: E501
    """
    This is a persistent memory to add relevant context to our memory.
    Use this function to add relevant context to the memory.

    Args:
        texts: relevant data to add to memory, no PII data about CTF env,
        only techniques and procedures
        do not include any information about IP
        be explicit with the tecnhiques and reasoning process
        step: step number of the current CTF
    Returns:
        str: Status message indicating success or failure
    """
    try:
        db = _get_db()
        doc_id = f"semantic_{uuid.uuid4().hex}"
        count = db.add_documents(
            documents=[texts],
            metadatas=[{"collection": "_all_", "CTF": collection_name, "step": step}],
            ids=[doc_id],
        )
        if count > 0:
            return f"Successfully added document to collection {collection_name}"
        return "Failed to add documents to vector database"

    except Exception as e:  # pylint: disable=broad-exception-caught
        return f"Error adding documents to vector database: {str(e)}"
