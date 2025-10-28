"""
Embeddings generation module for Skynet RAG system.
Supports multiple embedding providers.
"""
from typing import List, Optional
from abc import ABC, abstractmethod
import numpy as np

from ..core.config import get_config
from ..core.logging import get_logger


class EmbeddingProvider(ABC):
    """Abstract base class for embedding providers."""

    @abstractmethod
    def embed_text(self, text: str) -> List[float]:
        """Generate embedding for a single text."""
        pass

    @abstractmethod
    def embed_texts(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts."""
        pass

    @property
    @abstractmethod
    def dimension(self) -> int:
        """Get the dimension of embeddings."""
        pass


class OpenAIEmbeddings(EmbeddingProvider):
    """OpenAI embeddings provider."""

    def __init__(self, model: str = "text-embedding-3-small"):
        self.config = get_config()
        self.logger = get_logger()
        self.model = model
        self._dimension = 1536 if "small" in model else 3072

        if not self.config.openai_api_key:
            raise ValueError("OpenAI API key not found. Set OPENAI_API_KEY environment variable.")

    def embed_text(self, text: str) -> List[float]:
        """Generate embedding for a single text."""
        try:
            import openai
            client = openai.OpenAI(api_key=self.config.openai_api_key)

            response = client.embeddings.create(
                input=text,
                model=self.model
            )

            return response.data[0].embedding

        except ImportError:
            self.logger.error("OpenAI library not installed. Run: pip install openai")
            raise
        except Exception as e:
            self.logger.error(f"Failed to generate embedding: {e}")
            raise

    def embed_texts(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts."""
        try:
            import openai
            client = openai.OpenAI(api_key=self.config.openai_api_key)

            # OpenAI API can handle batch requests
            response = client.embeddings.create(
                input=texts,
                model=self.model
            )

            return [data.embedding for data in response.data]

        except ImportError:
            self.logger.error("OpenAI library not installed. Run: pip install openai")
            raise
        except Exception as e:
            self.logger.error(f"Failed to generate embeddings: {e}")
            raise

    @property
    def dimension(self) -> int:
        return self._dimension


class SimpleEmbeddings(EmbeddingProvider):
    """
    Simple embedding provider using sentence transformers.
    Useful for offline/local usage without API keys.
    """

    def __init__(self, model: str = "all-MiniLM-L6-v2"):
        self.logger = get_logger()
        self.model_name = model
        self._model = None
        self._dimension = 384  # Default for all-MiniLM-L6-v2

    def _load_model(self):
        """Lazy load the model."""
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer(self.model_name)
                self._dimension = self._model.get_sentence_embedding_dimension()
                self.logger.info(f"Loaded embedding model: {self.model_name}")
            except ImportError:
                self.logger.error("sentence-transformers not installed. Run: pip install sentence-transformers")
                raise

    def embed_text(self, text: str) -> List[float]:
        """Generate embedding for a single text."""
        self._load_model()
        embedding = self._model.encode(text, convert_to_numpy=True)
        return embedding.tolist()

    def embed_texts(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts."""
        self._load_model()
        embeddings = self._model.encode(texts, convert_to_numpy=True)
        return embeddings.tolist()

    @property
    def dimension(self) -> int:
        if self._model is None:
            self._load_model()
        return self._dimension


class EmbeddingManager:
    """Manages embedding generation with automatic provider selection."""

    def __init__(self, provider: Optional[str] = None):
        self.config = get_config()
        self.logger = get_logger()

        # Automatically select provider
        if provider == "openai":
            self.provider = OpenAIEmbeddings(self.config.embedding_model)
        elif provider == "simple":
            self.provider = SimpleEmbeddings()
        else:
            # Auto-detect based on available API keys
            if self.config.openai_api_key:
                try:
                    self.provider = OpenAIEmbeddings(self.config.embedding_model)
                    self.logger.info("Using OpenAI embeddings")
                except Exception:
                    self.logger.warning("Failed to initialize OpenAI embeddings, falling back to simple embeddings")
                    self.provider = SimpleEmbeddings()
            else:
                self.logger.info("Using simple (local) embeddings")
                self.provider = SimpleEmbeddings()

    def embed(self, text: str) -> List[float]:
        """Generate embedding for a single text."""
        return self.provider.embed_text(text)

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts."""
        return self.provider.embed_texts(texts)

    @property
    def dimension(self) -> int:
        """Get the dimension of embeddings."""
        return self.provider.dimension


def get_embedding_manager(provider: Optional[str] = None) -> EmbeddingManager:
    """Get or create the global embedding manager."""
    return EmbeddingManager(provider=provider)
