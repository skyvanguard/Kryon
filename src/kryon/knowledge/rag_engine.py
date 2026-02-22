"""
KRYON RAG Engine
=================

Retrieval-Augmented Generation engine that combines vector search with LLM.

Clearance Level: Omega-Strategic
Classification: RESTRICTED
"""

import json
import time
from pathlib import Path
from typing import Any, Optional


class RAGEngine:
    """
    RAG (Retrieval-Augmented Generation) engine.

    Combines semantic search with LLM to provide contextual answers.
    """

    def __init__(self, vector_db=None, llm_config: Optional[dict] = None):
        """
        Initialize RAG engine.

        Args:
            vector_db: Vector database instance (auto-created if None)
            llm_config: LLM configuration (loads from file if None)
        """
        from .vector_db import get_vector_db

        self.vector_db = vector_db or get_vector_db()
        self.llm_config = llm_config or self._load_llm_config()

    def _load_llm_config(self) -> dict:
        """Load LLM configuration."""
        config_path = Path.home() / ".kryon" / "config.json"
        if config_path.exists():
            with open(config_path) as f:
                return json.load(f)
        return {"base_url": "https://api.openai.com", "model": "gpt-4o"}

    def add_knowledge(self, content: str, source: str, metadata: Optional[dict] = None) -> str:
        """
        Add knowledge to the database.

        Args:
            content: Knowledge content (text)
            source: Source of knowledge (e.g., "exploit-db", "nvd")
            metadata: Optional additional metadata

        Returns:
            Document ID
        """
        # Prepare metadata
        full_metadata = {
            "source": source,
            "timestamp": time.time(),
            "added_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        if metadata:
            full_metadata.update(metadata)

        # Generate ID
        doc_id = f"{source}_{int(time.time() * 1000)}"

        # Add to vector database
        self.vector_db.add_documents(documents=[content], metadatas=[full_metadata], ids=[doc_id])

        return doc_id

    def query(
        self,
        question: str,
        top_k: int = 5,
        source_filter: Optional[str] = None,
        use_llm: bool = True,
    ) -> dict[str, Any]:
        """
        Query knowledge base with RAG.

        Args:
            question: Question to answer
            top_k: Number of relevant documents to retrieve
            source_filter: Optional source filter (e.g., "exploit-db")
            use_llm: Whether to use LLM for answer generation

        Returns:
            Dictionary with:
            - question: Original question
            - answer: LLM-generated answer (if use_llm=True)
            - sources: Retrieved documents
            - context_used: Context provided to LLM
        """
        # Build metadata filter
        filter_metadata = None
        if source_filter:
            filter_metadata = {"source": source_filter}

        # Retrieve relevant documents
        retrieved_docs = self.vector_db.query(query_text=question, top_k=top_k, filter_metadata=filter_metadata)

        # Build context from retrieved documents
        context = self._build_context(retrieved_docs)

        result = {
            "question": question,
            "sources": retrieved_docs,
            "context_used": context,
            "answer": None,
        }

        # Generate answer with LLM if requested
        if use_llm and self.llm_config.get("base_url"):
            answer = self._generate_answer(question, context)
            result["answer"] = answer

        return result

    def _build_context(self, documents: list[dict]) -> str:
        """
        Build context string from retrieved documents.

        Args:
            documents: Retrieved documents

        Returns:
            Formatted context string
        """
        if not documents:
            return "No relevant information found."

        context_parts = []
        for i, doc in enumerate(documents, 1):
            source = doc["metadata"].get("source", "unknown")
            content = doc["content"]
            score = doc["score"]

            context_parts.append(f"[Source {i}: {source} (relevance: {score:.2f})]\n{content}\n")

        return "\n".join(context_parts)

    def _generate_answer(self, question: str, context: str) -> str:
        """
        Generate answer using LLM with retrieved context.

        Uses intelligent caching to avoid duplicate LLM calls:
        - Cache hit: ~10ms (1500x faster)
        - Cache miss: 10-30s (new LLM generation)

        Args:
            question: User question
            context: Retrieved context

        Returns:
            LLM-generated answer
        """
        from .llm_cache import cache_llm_response, get_cached_llm_response

        # Check cache first (reduces 10-30s queries to ~10ms)
        cached_answer = get_cached_llm_response(question, context)
        if cached_answer is not None:
            return cached_answer

        # Cache miss - generate with LLM
        try:
            import requests

            start_time = time.time()
            prompt = self._create_rag_prompt(question, context)

            response = requests.post(
                f"{self.llm_config['base_url']}/api/generate",
                json={
                    "model": self.llm_config.get("model", "gpt-4o"),
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,  # More focused answers
                        "num_predict": 500,  # Limit response length
                    },
                },
                timeout=180,  # Increased to 3 minutes
            )

            generation_time = time.time() - start_time

            if response.status_code == 200:
                answer = response.json().get("response", "")

                # Cache the response for future queries
                cache_llm_response(query=question, context=context, answer=answer, generation_time=generation_time)

                return answer
            else:
                error_msg = f"LLM error: HTTP {response.status_code}"
                # Cache errors too (with shorter TTL)
                cache_llm_response(question, context, error_msg, generation_time, ttl=300)
                return error_msg

        except Exception as e:
            error_msg = f"Error generating answer: {str(e)}"
            # Cache exceptions (5min TTL) to avoid repeated failures
            cache_llm_response(question, context, error_msg, 0.0, ttl=300)
            return error_msg

    def _create_rag_prompt(self, question: str, context: str) -> str:
        """Create RAG prompt for LLM."""
        prompt = f"""You are KRYON, an advanced cybersecurity AI assistant. Answer the question using ONLY the provided context.

**CONTEXT:**
{context}

**QUESTION:**
{question}

**INSTRUCTIONS:**
1. Use ONLY information from the context above
2. If the context doesn't contain the answer, say "I don't have enough information in my knowledge base"
3. Be specific and technical
4. Include relevant CVE numbers, tools, or techniques mentioned
5. Format code snippets with proper syntax if applicable

**ANSWER:**"""

        return prompt

    def get_stats(self) -> dict[str, Any]:
        """
        Get RAG engine statistics.

        Returns:
            Statistics dictionary
        """
        from .llm_cache import get_llm_cache_stats

        db_stats = self.vector_db.get_stats()
        cache_stats = get_llm_cache_stats()

        stats = {
            "total_knowledge_items": db_stats["total_documents"],
            "sources": db_stats.get("sources", {}),
            "llm_configured": bool(self.llm_config.get("base_url")),
            "llm_model": self.llm_config.get("model", "unknown"),
            "vector_db_path": db_stats.get("persist_directory", "N/A"),
            "llm_cache": cache_stats,  # Cache performance metrics
        }

        return stats


# Global instance
_rag_engine = None


def get_rag_engine() -> RAGEngine:
    """Get global RAG engine instance."""
    global _rag_engine
    if _rag_engine is None:
        _rag_engine = RAGEngine()
    return _rag_engine


# Convenience functions
def query_knowledge(question: str, **kwargs) -> dict[str, Any]:
    """
    Query knowledge base with RAG.

    Args:
        question: Question to answer
        **kwargs: Additional arguments (top_k, source_filter, use_llm)

    Returns:
        RAG result with answer and sources
    """
    return get_rag_engine().query(question, **kwargs)


def add_document(content: str, source: str, **kwargs) -> str:
    """
    Add document to knowledge base.

    Args:
        content: Document content
        source: Source name
        **kwargs: Additional metadata

    Returns:
        Document ID
    """
    return get_rag_engine().add_knowledge(content, source, metadata=kwargs)


def get_knowledge_stats() -> dict:
    """Get knowledge base statistics."""
    return get_rag_engine().get_stats()
