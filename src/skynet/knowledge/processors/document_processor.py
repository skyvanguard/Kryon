"""
Document Processor
==================

Process various document types (PDF, MD, TXT) for knowledge base.
"""

import os
from typing import List, Dict, Any, Optional
from pathlib import Path


class DocumentProcessor:
    """
    Process documents into chunks suitable for embedding.

    Supports:
    - PDF files
    - Markdown files
    - Text files
    """

    def __init__(self, chunk_size: int = 512, chunk_overlap: int = 50):
        """
        Initialize document processor.

        Args:
            chunk_size: Maximum tokens per chunk
            chunk_overlap: Overlap between chunks
        """
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def process_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Process a file into chunks.

        Args:
            file_path: Path to file

        Returns:
            List of chunks with metadata
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Determine file type
        extension = file_path.suffix.lower()

        if extension == ".pdf":
            return self._process_pdf(file_path)
        elif extension in [".md", ".markdown"]:
            return self._process_markdown(file_path)
        elif extension in [".txt", ".text"]:
            return self._process_text(file_path)
        else:
            # Try as text
            return self._process_text(file_path)

    def _process_pdf(self, file_path: Path) -> List[Dict[str, Any]]:
        """Process PDF file."""
        try:
            import PyPDF2

            chunks = []

            with open(file_path, "rb") as f:
                pdf_reader = PyPDF2.PdfReader(f)
                num_pages = len(pdf_reader.pages)

                for page_num in range(num_pages):
                    page = pdf_reader.pages[page_num]
                    text = page.extract_text()

                    # Chunk the page text
                    page_chunks = self._chunk_text(text)

                    for i, chunk in enumerate(page_chunks):
                        chunks.append({
                            "content": chunk,
                            "metadata": {
                                "file": str(file_path.name),
                                "page": page_num + 1,
                                "chunk": i,
                                "file_type": "pdf"
                            }
                        })

            return chunks

        except ImportError:
            print("⚠️  PyPDF2 not installed. Install with: pip install PyPDF2")
            return []
        except Exception as e:
            print(f"Error processing PDF {file_path}: {e}")
            return []

    def _process_markdown(self, file_path: Path) -> List[Dict[str, Any]]:
        """Process Markdown file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()

            # Chunk text
            text_chunks = self._chunk_text(text)

            chunks = []
            for i, chunk in enumerate(text_chunks):
                chunks.append({
                    "content": chunk,
                    "metadata": {
                        "file": str(file_path.name),
                        "chunk": i,
                        "file_type": "markdown"
                    }
                })

            return chunks

        except Exception as e:
            print(f"Error processing Markdown {file_path}: {e}")
            return []

    def _process_text(self, file_path: Path) -> List[Dict[str, Any]]:
        """Process plain text file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()

            # Chunk text
            text_chunks = self._chunk_text(text)

            chunks = []
            for i, chunk in enumerate(text_chunks):
                chunks.append({
                    "content": chunk,
                    "metadata": {
                        "file": str(file_path.name),
                        "chunk": i,
                        "file_type": "text"
                    }
                })

            return chunks

        except Exception as e:
            print(f"Error processing text {file_path}: {e}")
            return []

    def _chunk_text(self, text: str) -> List[str]:
        """
        Chunk text into smaller pieces.

        Simple word-based chunking with overlap.

        Args:
            text: Input text

        Returns:
            List of text chunks
        """
        words = text.split()

        if len(words) <= self.chunk_size:
            return [text]

        chunks = []
        start = 0

        while start < len(words):
            end = start + self.chunk_size
            chunk_words = words[start:end]
            chunks.append(" ".join(chunk_words))

            # Move start with overlap
            start = end - self.chunk_overlap

        return chunks

    def process_directory(
        self,
        directory: str,
        recursive: bool = True,
        extensions: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Process all files in a directory.

        Args:
            directory: Directory path
            recursive: Process subdirectories
            extensions: File extensions to process (default: all supported)

        Returns:
            List of all chunks from all files
        """
        directory = Path(directory)

        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")

        if extensions is None:
            extensions = [".pdf", ".md", ".markdown", ".txt"]

        all_chunks = []

        # Get all matching files
        if recursive:
            files = []
            for ext in extensions:
                files.extend(directory.rglob(f"*{ext}"))
        else:
            files = []
            for ext in extensions:
                files.extend(directory.glob(f"*{ext}"))

        # Process each file
        for file_path in files:
            try:
                file_chunks = self.process_file(str(file_path))
                all_chunks.extend(file_chunks)
            except Exception as e:
                print(f"Error processing {file_path}: {e}")

        return all_chunks


# Convenience function
def process_document(file_path: str, **kwargs) -> List[Dict]:
    """Process a document file."""
    processor = DocumentProcessor(**kwargs)
    return processor.process_file(file_path)
