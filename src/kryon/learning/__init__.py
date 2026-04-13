"""
KRYON self-improving loop — experience capture and retrieval.

This package turns Kryon from a stateless agent framework into a system that
accumulates what it learned from each engagement and uses that knowledge to
shape future ones.

Public API:

    from kryon.learning import (
        build_profile,
        extract_chain_from_history,
        add_experience,
        recall_similar,
        list_experiences,
        get_experience,
        delete_experience,
    )

See `docs/LEARNING_LOOP.md` for the architecture and data model.
"""

from kryon.learning.chain_extractor import extract_chain_from_history
from kryon.learning.experiences import (
    add_experience,
    count_experiences,
    delete_experience,
    get_experience,
    list_experiences,
    recall_similar,
)
from kryon.learning.profiler import build_profile

__all__ = [
    "add_experience",
    "build_profile",
    "count_experiences",
    "delete_experience",
    "extract_chain_from_history",
    "get_experience",
    "list_experiences",
    "recall_similar",
]
