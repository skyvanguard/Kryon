"""
Test Suite for SKYNET RAG System
=================================

Comprehensive tests for the RAG knowledge system.
"""

import pytest
import tempfile
import shutil
from pathlib import Path


class TestVectorDatabase:
    """Test ChromaDB vector database."""

    def setup_method(self):
        """Setup test database."""
        self.temp_dir = tempfile.mkdtemp()
        from skynet.knowledge.vector_db import VectorDatabase
        self.db = VectorDatabase(persist_directory=self.temp_dir)

    def teardown_method(self):
        """Cleanup test database."""
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)

    def test_database_initialization(self):
        """Test database initializes correctly."""
        assert self.db.client is not None
        assert self.db.collection is not None

    def test_add_documents(self):
        """Test adding documents."""
        docs = ["Test document 1", "Test document 2"]
        metadatas = [{"source": "test1"}, {"source": "test2"}]

        count = self.db.add_documents(docs, metadatas=metadatas)
        assert count == 2
        assert self.db.count() == 2

    def test_query_documents(self):
        """Test querying documents."""
        # Add documents
        docs = [
            "Apache web server vulnerability",
            "MySQL database exploit",
            "Linux privilege escalation"
        ]
        self.db.add_documents(docs)

        # Query
        results = self.db.query("Apache vulnerability", top_k=2)
        assert len(results) <= 2
        assert results[0]['score'] > 0

    def test_delete_documents(self):
        """Test deleting documents."""
        docs = ["Test doc"]
        ids = ["test_id_1"]
        self.db.add_documents(docs, ids=ids)

        deleted = self.db.delete_by_ids(ids)
        assert deleted == 1

    def test_get_stats(self):
        """Test getting statistics."""
        docs = ["Doc 1", "Doc 2"]
        metadatas = [{"source": "test"}, {"source": "test"}]
        self.db.add_documents(docs, metadatas=metadatas)

        stats = self.db.get_stats()
        assert stats['total_documents'] == 2
        assert 'test' in stats.get('sources', {})


class TestEmbeddings:
    """Test embedding generation."""

    def test_embedding_generation(self):
        """Test generating embeddings."""
        try:
            from skynet.knowledge.embeddings import generate_embedding

            text = "Apache web server vulnerability"
            embedding = generate_embedding(text)

            assert isinstance(embedding, list)
            assert len(embedding) > 0
            assert all(isinstance(x, float) for x in embedding)
        except ImportError:
            pytest.skip("sentence-transformers not installed")

    def test_batch_embeddings(self):
        """Test batch embedding generation."""
        try:
            from skynet.knowledge.embeddings import generate_embeddings

            texts = ["Text 1", "Text 2", "Text 3"]
            embeddings = generate_embeddings(texts)

            assert len(embeddings) == 3
            assert all(isinstance(emb, list) for emb in embeddings)
        except ImportError:
            pytest.skip("sentence-transformers not installed")


class TestRAGEngine:
    """Test RAG query engine."""

    def setup_method(self):
        """Setup test RAG engine."""
        self.temp_dir = tempfile.mkdtemp()
        from skynet.knowledge.vector_db import VectorDatabase
        from skynet.knowledge.rag_engine import RAGEngine

        db = VectorDatabase(persist_directory=self.temp_dir)
        self.rag = RAGEngine(vector_db=db)

    def teardown_method(self):
        """Cleanup."""
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)

    def test_add_knowledge(self):
        """Test adding knowledge."""
        doc_id = self.rag.add_knowledge(
            content="Test exploit for Apache",
            source="test",
            metadata={"cve": "CVE-2021-1234"}
        )

        assert doc_id is not None
        assert "test" in doc_id

    def test_query_knowledge(self):
        """Test querying knowledge."""
        # Add some knowledge
        self.rag.add_knowledge(
            "Apache path traversal exploit",
            "test"
        )
        self.rag.add_knowledge(
            "MySQL SQL injection technique",
            "test"
        )

        # Query
        result = self.rag.query(
            "How to exploit Apache?",
            use_llm=False  # Don't use LLM in tests
        )

        assert 'sources' in result
        assert len(result['sources']) > 0

    def test_get_stats(self):
        """Test getting RAG statistics."""
        self.rag.add_knowledge("Test content", "test")

        stats = self.rag.get_stats()
        assert 'total_knowledge_items' in stats
        assert stats['total_knowledge_items'] >= 1


class TestDocumentProcessor:
    """Test document processor."""

    def test_chunk_text(self):
        """Test text chunking."""
        from skynet.knowledge.processors import DocumentProcessor

        processor = DocumentProcessor(chunk_size=10, chunk_overlap=2)

        text = " ".join([f"word{i}" for i in range(50)])
        chunks = processor._chunk_text(text)

        assert len(chunks) > 1
        assert all(isinstance(chunk, str) for chunk in chunks)

    def test_process_text_file(self):
        """Test processing text file."""
        from skynet.knowledge.processors import DocumentProcessor

        # Create temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Test content for knowledge base.\n" * 100)
            temp_file = f.name

        try:
            processor = DocumentProcessor()
            chunks = processor.process_file(temp_file)

            assert len(chunks) > 0
            assert all('content' in chunk for chunk in chunks)
            assert all('metadata' in chunk for chunk in chunks)
        finally:
            Path(temp_file).unlink()


class TestMetadataExtractor:
    """Test metadata extraction."""

    def test_extract_cves(self):
        """Test CVE extraction."""
        from skynet.knowledge.processors import MetadataExtractor

        extractor = MetadataExtractor()
        content = "This exploit targets CVE-2021-41773 and CVE-2021-42013"

        metadata = extractor.extract(content)
        assert 'cves' in metadata
        assert len(metadata['cves']) == 2

    def test_extract_tools(self):
        """Test tool extraction."""
        from skynet.knowledge.processors import MetadataExtractor

        extractor = MetadataExtractor()
        content = "Use nmap for scanning and metasploit for exploitation"

        metadata = extractor.extract(content)
        assert 'tools' in metadata
        assert 'nmap' in metadata['tools']
        assert 'metasploit' in metadata['tools']

    def test_extract_platforms(self):
        """Test platform extraction."""
        from skynet.knowledge.processors import MetadataExtractor

        extractor = MetadataExtractor()
        content = "Linux privilege escalation on Ubuntu systems"

        metadata = extractor.extract(content)
        assert 'platforms' in metadata
        assert 'linux' in metadata['platforms']

    def test_extract_attack_types(self):
        """Test attack type extraction."""
        from skynet.knowledge.processors import MetadataExtractor

        extractor = MetadataExtractor()
        content = "SQL injection and XSS vulnerabilities found"

        metadata = extractor.extract(content)
        assert 'attack_types' in metadata
        assert 'sqli' in metadata['attack_types']
        assert 'xss' in metadata['attack_types']


def test_imports():
    """Test that all modules can be imported."""
    try:
        from skynet.knowledge import (
            query_knowledge,
            add_document,
            get_vector_db,
            start_auto_updater
        )
        assert True
    except ImportError as e:
        pytest.fail(f"Import failed: {e}")


def test_dependencies():
    """Test that required dependencies are installed."""
    required = ['chromadb', 'schedule']
    optional = ['sentence_transformers', 'PyPDF2']

    for dep in required:
        try:
            __import__(dep.replace('_', '-'))
        except ImportError:
            pytest.fail(f"Required dependency not installed: {dep}")

    # Optional dependencies - warn but don't fail
    for dep in optional:
        try:
            __import__(dep.replace('_', '-'))
        except ImportError:
            print(f"⚠️  Optional dependency not installed: {dep}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
