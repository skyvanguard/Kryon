"""
SKYNET Embeddings Generator
===========================

Generate semantic embeddings for knowledge base using sentence-transformers.

Clearance Level: Omega-Strategic
Classification: RESTRICTED
"""

import hashlib
from typing import List, Union
from pathlib import Path


class EmbeddingGenerator:
    """
    Generate embeddings for semantic search.

    Uses sentence-transformers for local embedding generation.
    No external API calls - everything runs locally.
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        """
        Initialize embedding generator.

        Args:
            model_name: Sentence-transformers model name
                       Default: all-MiniLM-L6-v2 (fast, 384 dimensions)
        """
        self.model_name = model_name
        self.model = None
        self._ensure_model_loaded()

    def _ensure_model_loaded(self):
        """Lazy load the embedding model."""
        if self.model is None:
            try:
                from sentence_transformers import SentenceTransformer
                self.model = SentenceTransformer(self.model_name)
            except ImportError:
                print("⚠️  sentence-transformers not installed")
                print("Install with: pip install sentence-transformers")
                raise

    def generate_embedding(self, text: str) -> List[float]:
        """
        Generate embedding for a single text.

        Args:
            text: Input text

        Returns:
            Embedding vector (list of floats)
        """
        self._ensure_model_loaded()

        # Truncate if too long (max 512 tokens for most models)
        if len(text) > 2000:
            text = text[:2000]

        embedding = self.model.encode(text, convert_to_numpy=True)
        return embedding.tolist()

    def generate_embeddings(self, texts: List[str]) -> List[List[float]]:
        """
        Generate embeddings for multiple texts (batch).

        Args:
            texts: List of input texts

        Returns:
            List of embedding vectors
        """
        self._ensure_model_loaded()

        # Truncate long texts
        truncated_texts = [
            text[:2000] if len(text) > 2000 else text
            for text in texts
        ]

        embeddings = self.model.encode(
            truncated_texts,
            convert_to_numpy=True,
            show_progress_bar=len(texts) > 10
        )

        return embeddings.tolist()

    def get_text_hash(self, text: str) -> str:
        """
        Generate unique hash for text (for deduplication).

        Args:
            text: Input text

        Returns:
            MD5 hash
        """
        return hashlib.md5(text.encode()).hexdigest()


# Global instance
_embedding_generator = None


def get_embedding_generator(model_name: str = "all-MiniLM-L6-v2") -> EmbeddingGenerator:
    """Get global embedding generator instance."""
    global _embedding_generator
    if _embedding_generator is None:
        _embedding_generator = EmbeddingGenerator(model_name)
    return _embedding_generator


# Convenience functions
def generate_embedding(text: str) -> List[float]:
    """Generate embedding for text."""
    return get_embedding_generator().generate_embedding(text)


def generate_embeddings(texts: List[str]) -> List[List[float]]:
    """Generate embeddings for multiple texts."""
    return get_embedding_generator().generate_embeddings(texts)
