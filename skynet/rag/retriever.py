"""
Retriever module for Skynet RAG system.
Provides high-level interface for context retrieval.
"""
from typing import List, Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass

from .embeddings import get_embedding_manager
from .vector_store import VectorStore, Document, get_vector_store
from ..core.config import get_config
from ..core.logging import get_logger


@dataclass
class RetrievedContext:
    """Represents retrieved context with metadata."""
    content: str
    metadata: Dict[str, Any]
    relevance_score: float  # Lower is more relevant (distance)

    def __str__(self) -> str:
        """Format context for display."""
        source = self.metadata.get('source', 'unknown')
        category = self.metadata.get('category', 'general')
        return f"[{category}] ({source}): {self.content}"


class KnowledgeRetriever:
    """
    High-level interface for retrieving relevant CTF knowledge.
    Handles context augmentation for agents.
    """

    def __init__(self, collection_name: str = "skynet_knowledge"):
        self.config = get_config()
        self.logger = get_logger()
        self.embedding_manager = get_embedding_manager()
        self.vector_store = get_vector_store(collection_name)

    def retrieve(
        self,
        query: str,
        top_k: Optional[int] = None,
        category: Optional[str] = None,
        min_relevance: float = 2.0  # Max distance threshold
    ) -> List[RetrievedContext]:
        """
        Retrieve relevant context for a query.

        Args:
            query: Query text
            top_k: Number of results to return (defaults to config value)
            category: Optional category filter (e.g., 'crypto', 'web', 'pwn')
            min_relevance: Maximum distance threshold (lower = more relevant)

        Returns:
            List of retrieved contexts
        """
        if top_k is None:
            top_k = self.config.top_k_results

        # Build metadata filter
        filter_metadata = None
        if category:
            filter_metadata = {"category": category}

        # Search vector store
        results = self.vector_store.search_by_text(
            query_text=query,
            top_k=top_k,
            filter_metadata=filter_metadata
        )

        # Filter by relevance threshold and convert to RetrievedContext
        contexts = []
        for doc, distance in results:
            if distance <= min_relevance:
                contexts.append(RetrievedContext(
                    content=doc.content,
                    metadata=doc.metadata,
                    relevance_score=distance
                ))

        self.logger.info(f"Retrieved {len(contexts)} relevant contexts for query: {query[:50]}...")
        return contexts

    def format_context(self, contexts: List[RetrievedContext]) -> str:
        """
        Format retrieved contexts for injection into agent prompts.

        Args:
            contexts: List of retrieved contexts

        Returns:
            Formatted context string
        """
        if not contexts:
            return "No relevant context found."

        formatted = "## Relevant CTF Knowledge:\n\n"
        for i, ctx in enumerate(contexts, 1):
            category = ctx.metadata.get('category', 'general')
            source = ctx.metadata.get('source', 'unknown')
            formatted += f"{i}. [{category.upper()}] {ctx.content}\n"
            formatted += f"   Source: {source} | Relevance: {ctx.relevance_score:.3f}\n\n"

        return formatted

    def add_knowledge(
        self,
        content: str,
        category: str,
        source: str = "manual",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Add new knowledge to the database.

        Args:
            content: Knowledge content
            category: Category (e.g., 'crypto', 'web', 'pwn', 'forensics')
            source: Source of the knowledge
            metadata: Additional metadata

        Returns:
            Document ID
        """
        import hashlib
        import time

        # Generate unique ID
        doc_id = hashlib.md5(f"{content}_{time.time()}".encode()).hexdigest()

        # Prepare metadata
        doc_metadata = {
            "category": category,
            "source": source,
            "added_at": time.time()
        }
        if metadata:
            doc_metadata.update(metadata)

        # Generate embedding
        embedding = self.embedding_manager.embed(content)

        # Create document
        doc = Document(
            id=doc_id,
            content=content,
            metadata=doc_metadata,
            embedding=embedding
        )

        # Add to vector store
        self.vector_store.add_document(doc)
        self.logger.info(f"Added knowledge: {content[:50]}... (ID: {doc_id})")

        return doc_id

    def add_knowledge_from_file(self, file_path: Path, category: str):
        """
        Add knowledge from a text file.

        Args:
            file_path: Path to the text file
            category: Category for the knowledge
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        content = file_path.read_text()

        # Split into chunks if needed
        chunks = self._chunk_text(content)

        for i, chunk in enumerate(chunks):
            self.add_knowledge(
                content=chunk,
                category=category,
                source=str(file_path),
                metadata={"chunk_index": i}
            )

        self.logger.info(f"Added {len(chunks)} chunks from {file_path}")

    def add_knowledge_from_directory(self, directory: Path, category: str, pattern: str = "*.txt"):
        """
        Add knowledge from all files in a directory.

        Args:
            directory: Directory path
            category: Category for the knowledge
            pattern: File pattern to match (default: *.txt)
        """
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")

        files = list(directory.glob(pattern))
        for file_path in files:
            try:
                self.add_knowledge_from_file(file_path, category)
            except Exception as e:
                self.logger.error(f"Failed to add knowledge from {file_path}: {e}")

        self.logger.info(f"Processed {len(files)} files from {directory}")

    def _chunk_text(self, text: str) -> List[str]:
        """
        Split text into chunks for embedding.

        Args:
            text: Text to chunk

        Returns:
            List of text chunks
        """
        chunk_size = self.config.chunk_size
        chunk_overlap = self.config.chunk_overlap

        chunks = []
        start = 0

        while start < len(text):
            end = start + chunk_size
            chunk = text[start:end]

            # Try to break at sentence boundaries
            if end < len(text):
                last_period = chunk.rfind('.')
                last_newline = chunk.rfind('\n')
                break_point = max(last_period, last_newline)

                if break_point > chunk_size // 2:  # Only break if it's not too early
                    chunk = chunk[:break_point + 1]
                    end = start + break_point + 1

            chunks.append(chunk.strip())
            start = end - chunk_overlap

        return [c for c in chunks if c]  # Filter empty chunks

    def search_by_category(self, category: str, limit: int = 10) -> List[RetrievedContext]:
        """
        Get all knowledge for a specific category.

        Args:
            category: Category to search
            limit: Maximum number of results

        Returns:
            List of contexts
        """
        # Use a generic query to retrieve by category
        return self.retrieve(
            query=f"{category} techniques and methods",
            top_k=limit,
            category=category,
            min_relevance=10.0  # High threshold for category browsing
        )

    def count_knowledge(self) -> int:
        """Get the total number of knowledge entries."""
        return self.vector_store.count()

    def export_knowledge(self, output_path: Path):
        """Export knowledge base to a file."""
        self.vector_store.export_collection(output_path)

    def import_knowledge(self, input_path: Path):
        """Import knowledge base from a file."""
        self.vector_store.import_collection(input_path)


def get_retriever(collection_name: str = "skynet_knowledge") -> KnowledgeRetriever:
    """Get or create a knowledge retriever instance."""
    return KnowledgeRetriever(collection_name=collection_name)
