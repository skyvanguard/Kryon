"""
SKYNET Vector Database
======================

Vector database for semantic search with automatic ChromaDB/fallback.

Clearance Level: Omega-Strategic
Classification: RESTRICTED
"""

# Import from simple_vector_db which has automatic fallback
from .simple_vector_db import (
    VectorDatabase,
    get_vector_db,
    add_documents,
    query_db
)

__all__ = [
    'VectorDatabase',
    'get_vector_db',
    'add_documents',
    'query_db'
]
