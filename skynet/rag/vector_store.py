"""
Vector store module for Skynet RAG system.
Handles storage and retrieval of embeddings with metadata.
"""
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import json
import pickle
from dataclasses import dataclass, asdict

from ..core.config import get_config
from ..core.logging import get_logger


@dataclass
class Document:
    """Represents a document in the vector store."""
    id: str
    content: str
    metadata: Dict[str, Any]
    embedding: Optional[List[float]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class VectorStore:
    """
    Vector store using ChromaDB for efficient similarity search.
    Stores embeddings and metadata for CTF knowledge.
    """

    def __init__(self, collection_name: str = "skynet_knowledge", persist_directory: Optional[Path] = None):
        self.config = get_config()
        self.logger = get_logger()
        self.collection_name = collection_name

        if persist_directory is None:
            persist_directory = self.config.vector_db_path

        self.persist_directory = persist_directory
        self.persist_directory.mkdir(parents=True, exist_ok=True)

        self._client = None
        self._collection = None

    def _get_client(self):
        """Lazy load ChromaDB client."""
        if self._client is None:
            try:
                import chromadb
                from chromadb.config import Settings

                self._client = chromadb.Client(Settings(
                    persist_directory=str(self.persist_directory),
                    anonymized_telemetry=False
                ))

                self.logger.info(f"Initialized ChromaDB at {self.persist_directory}")
            except ImportError:
                self.logger.error("ChromaDB not installed. Run: pip install chromadb")
                raise

        return self._client

    def _get_collection(self):
        """Get or create collection."""
        if self._collection is None:
            client = self._get_client()
            self._collection = client.get_or_create_collection(
                name=self.collection_name,
                metadata={"description": "Skynet CTF knowledge base"}
            )
            self.logger.info(f"Loaded collection: {self.collection_name}")

        return self._collection

    def add_documents(
        self,
        documents: List[Document],
        batch_size: int = 100
    ):
        """
        Add documents to the vector store.

        Args:
            documents: List of documents to add
            batch_size: Batch size for adding documents
        """
        collection = self._get_collection()

        # Process in batches
        for i in range(0, len(documents), batch_size):
            batch = documents[i:i + batch_size]

            ids = [doc.id for doc in batch]
            embeddings = [doc.embedding for doc in batch]
            documents_text = [doc.content for doc in batch]
            metadatas = [doc.metadata for doc in batch]

            collection.add(
                ids=ids,
                embeddings=embeddings,
                documents=documents_text,
                metadatas=metadatas
            )

            self.logger.debug(f"Added batch {i // batch_size + 1}: {len(batch)} documents")

        self.logger.info(f"Added {len(documents)} documents to collection {self.collection_name}")

    def add_document(self, document: Document):
        """Add a single document to the vector store."""
        self.add_documents([document])

    def search(
        self,
        query_embedding: List[float],
        top_k: int = 5,
        filter_metadata: Optional[Dict[str, Any]] = None
    ) -> List[Tuple[Document, float]]:
        """
        Search for similar documents.

        Args:
            query_embedding: Query embedding vector
            top_k: Number of results to return
            filter_metadata: Optional metadata filter

        Returns:
            List of (document, distance) tuples
        """
        collection = self._get_collection()

        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            where=filter_metadata
        )

        # Parse results
        documents_with_scores = []
        if results['ids'] and results['ids'][0]:
            for i in range(len(results['ids'][0])):
                doc = Document(
                    id=results['ids'][0][i],
                    content=results['documents'][0][i],
                    metadata=results['metadatas'][0][i] if results['metadatas'] else {},
                    embedding=None  # Don't return embeddings for efficiency
                )
                distance = results['distances'][0][i] if results['distances'] else 0.0
                documents_with_scores.append((doc, distance))

        return documents_with_scores

    def search_by_text(
        self,
        query_text: str,
        top_k: int = 5,
        filter_metadata: Optional[Dict[str, Any]] = None
    ) -> List[Tuple[Document, float]]:
        """
        Search using text query (will be embedded automatically).

        Args:
            query_text: Query text
            top_k: Number of results to return
            filter_metadata: Optional metadata filter

        Returns:
            List of (document, distance) tuples
        """
        from .embeddings import get_embedding_manager

        embedding_manager = get_embedding_manager()
        query_embedding = embedding_manager.embed(query_text)

        return self.search(query_embedding, top_k, filter_metadata)

    def delete_documents(self, ids: List[str]):
        """Delete documents by IDs."""
        collection = self._get_collection()
        collection.delete(ids=ids)
        self.logger.info(f"Deleted {len(ids)} documents")

    def delete_collection(self):
        """Delete the entire collection."""
        client = self._get_client()
        client.delete_collection(self.collection_name)
        self._collection = None
        self.logger.info(f"Deleted collection: {self.collection_name}")

    def count(self) -> int:
        """Get the number of documents in the collection."""
        collection = self._get_collection()
        return collection.count()

    def get_document(self, doc_id: str) -> Optional[Document]:
        """Get a document by ID."""
        collection = self._get_collection()

        try:
            result = collection.get(ids=[doc_id])
            if result['ids']:
                return Document(
                    id=result['ids'][0],
                    content=result['documents'][0],
                    metadata=result['metadatas'][0] if result['metadatas'] else {},
                    embedding=result['embeddings'][0] if result['embeddings'] else None
                )
        except Exception as e:
            self.logger.warning(f"Document {doc_id} not found: {e}")

        return None

    def list_collections(self) -> List[str]:
        """List all collections in the database."""
        client = self._get_client()
        collections = client.list_collections()
        return [col.name for col in collections]

    def export_collection(self, output_path: Path):
        """Export collection to a file."""
        collection = self._get_collection()
        data = collection.get()

        export_data = {
            "collection_name": self.collection_name,
            "count": len(data['ids']),
            "documents": [
                {
                    "id": data['ids'][i],
                    "content": data['documents'][i],
                    "metadata": data['metadatas'][i] if data['metadatas'] else {},
                }
                for i in range(len(data['ids']))
            ]
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)

        self.logger.info(f"Exported collection to {output_path}")

    def import_collection(self, input_path: Path):
        """Import collection from a file."""
        with open(input_path, 'r') as f:
            import_data = json.load(f)

        from .embeddings import get_embedding_manager
        embedding_manager = get_embedding_manager()

        documents = []
        for doc_data in import_data['documents']:
            # Generate embedding for imported content
            embedding = embedding_manager.embed(doc_data['content'])

            doc = Document(
                id=doc_data['id'],
                content=doc_data['content'],
                metadata=doc_data['metadata'],
                embedding=embedding
            )
            documents.append(doc)

        self.add_documents(documents)
        self.logger.info(f"Imported {len(documents)} documents from {input_path}")


def get_vector_store(collection_name: str = "skynet_knowledge") -> VectorStore:
    """Get or create a vector store instance."""
    return VectorStore(collection_name=collection_name)
