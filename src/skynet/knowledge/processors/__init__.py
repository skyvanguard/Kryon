"""
SKYNET Document Processors
==========================

Process various document types for knowledge base ingestion.

Available Processors:
- DocumentProcessor: PDF, Markdown, Text files
- CodeProcessor: Source code analysis
- MetadataExtractor: Extract metadata from documents
"""

from .code_processor import CodeProcessor, process_code
from .document_processor import DocumentProcessor, process_document
from .metadata_extractor import MetadataExtractor, extract_metadata

__all__ = [
    "DocumentProcessor",
    "process_document",
    "CodeProcessor",
    "process_code",
    "MetadataExtractor",
    "extract_metadata",
]
