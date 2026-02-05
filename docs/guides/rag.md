# KRYON RAG System Guide

**Knowledge Enhancement with Retrieval-Augmented Generation**

---

## Overview

**RAG (Retrieval-Augmented Generation)** enables KRYON to access massive knowledge from multiple sources:

- **Exploit-DB**: 40,000+ exploits
- **NVD**: National Vulnerability Database (CVEs)
- **GitHub**: PoC exploits and tools
- **CTF Writeups**: Techniques and methodologies

KRYON can now answer questions like:
- "How to exploit Apache 2.4.49?"
- "Linux privilege escalation techniques"
- "PoC for CVE-2024-1234"

---

## Quick Start

### 1. Install Dependencies

```bash
pip install chromadb sentence-transformers schedule PyPDF2
```

### 2. Initialize Knowledge Base

```python
from kryon.knowledge import query_knowledge, start_auto_updater

# Query (will auto-initialize on first use)
result = query_knowledge("How to exploit SQL injection?")
print(result['answer'])
```

### 3. Start Auto-Updates

```python
from kryon.knowledge import start_auto_updater

# Update daily at 2 AM
start_auto_updater(
    schedule_type="daily",
    sources=["exploit-db", "nvd", "github", "writeups"],
    time_of_day="02:00"
)
```

---

## Basic Usage

### Query Knowledge

```python
from kryon.knowledge import query_knowledge

# Ask any security question
result = query_knowledge(
    "How to perform privilege escalation on Linux?",
    top_k=5  # Return top 5 relevant sources
)

# Get LLM-generated answer
print(result['answer'])

# Get source documents
for source in result['sources']:
    print(f"Source: {source['metadata']['source']}")
    print(f"Content: {source['content'][:200]}...")
    print(f"Relevance: {source['score']:.2f}\n")
```

### Add Your Own Knowledge

```python
from kryon.knowledge import add_document

# Add a document
doc_id = add_document(
    content="Custom exploit technique for XYZ...",
    source="manual",
    technique="rce",
    platform="linux"
)
```

### Add Files (PDF, MD, TXT)

```python
from kryon.knowledge.processors import DocumentProcessor
from kryon.knowledge import get_rag_engine

processor = DocumentProcessor()
rag = get_rag_engine()

# Process PDF
chunks = processor.process_file("/path/to/document.pdf")

# Add to knowledge base
for chunk in chunks:
    rag.add_knowledge(
        content=chunk["content"],
        source="pdf",
        metadata=chunk["metadata"]
    )
```

---

## Manual Scraping

### Scrape Exploit-DB

```python
from kryon.knowledge.scrapers import ExploitDBScraper
from kryon.knowledge import get_rag_engine

scraper = ExploitDBScraper()
exploits = scraper.scrape(
    keywords=["apache", "wordpress", "php"],
    max_results=50
)

# Add to knowledge base
rag = get_rag_engine()
for exploit in exploits:
    rag.add_knowledge(
        content=exploit["content"],
        source="exploit-db",
        metadata=exploit["metadata"]
    )

print(f"Added {len(exploits)} exploits")
```

### Scrape NVD (CVEs)

```python
from kryon.knowledge.scrapers import NVDScraper

scraper = NVDScraper()
cves = scraper.scrape(
    days_back=30,
    keywords=["apache", "nginx"],
    severity_min="MEDIUM",
    max_results=100
)

print(f"Found {len(cves)} CVEs")
```

### Scrape GitHub

```python
from kryon.knowledge.scrapers import GitHubScraper

scraper = GitHubScraper()
repos = scraper.scrape(
    keywords=["CVE exploit", "pentesting tool"],
    min_stars=10,
    max_results=50
)

print(f"Found {len(repos)} repositories")
```

---

## Auto-Update System

### Daily Updates

```python
from kryon.knowledge import start_auto_updater, stop_auto_updater

# Start daily updates at 2 AM
start_auto_updater(
    schedule_type="daily",
    sources=["exploit-db", "nvd", "github", "writeups"],
    time_of_day="02:00"
)

# Stop when needed
stop_auto_updater()
```

### Hourly Updates

```python
# Update every hour
start_auto_updater(
    schedule_type="hourly",
    sources=["nvd", "github"]  # Faster sources
)
```

### Manual Update

```python
from kryon.knowledge import auto_update_knowledge

# Update now
auto_update_knowledge(sources=["exploit-db", "nvd"])
```

---

## Integration with Agents

### Use RAG in T-1000 Hunter

```python
from kryon.agents import t1000_hunter
from kryon.knowledge import query_knowledge

# Query knowledge for specific service
result = query_knowledge(
    f"Exploits for Apache 2.4.49",
    source_filter="exploit-db",
    top_k=3
)

# Use discovered techniques
for source in result['sources']:
    print(f"Technique: {source['content'][:200]}...")
```

### RAG Mixin for Agents

```python
from kryon.agents.mixins import RAGMixin

class TestAgent(RAGMixin):
    def test_knowledge(self):
        # Query general knowledge
        result = self.query_rag("How to exploit Apache?")
        print(f"Answer: {result['answer'][:200]}...")

        # Get specific exploits
        exploits = self.get_exploits_for_service("apache", "2.4.49")
        print(f"Found {len(exploits)} exploits")

        # Get CVE info
        cve_info = self.get_cve_info("CVE-2021-41773")
        if cve_info:
            print(f"CVE Info: {cve_info['answer'][:200]}...")
```

---

## CLI Usage

### CLI Commands

```bash
# Query knowledge
kryon-knowledge query "How to exploit SQL injection?"

# Add document
kryon-knowledge add /path/to/document.pdf

# Show statistics
kryon-knowledge stats

# Update knowledge
kryon-knowledge update exploit-db nvd github

# Scrape specific source
kryon-knowledge scrape github

# Help
kryon-knowledge help
```

---

## Testing and Validation

### System Validation

```bash
python scripts/validate_rag.py
```

**Expected Output:**
```
[ ] Dependencies
[ ] KRYON Modules
[ ] Vector Database
[ ] Embeddings
[ ] RAG Engine
[ ] LLM Integration
[ ] Scrapers
[ ] Disk Space

Result: 8/8 checks passed
All checks passed! RAG system is ready to use.
```

### Initialize Knowledge Base

```bash
python scripts/initialize_knowledge.py --sources all --exploits 100
```

### Verify Knowledge

```bash
python scripts/verify_knowledge.py
```

### Run Unit Tests

```bash
pytest tests/test_rag_system.py -v
```

---

## Statistics and Monitoring

### View Stats

```python
from kryon.knowledge import get_knowledge_stats

stats = get_knowledge_stats()

print(f"Total knowledge items: {stats['total_knowledge_items']}")
print(f"Sources: {stats['sources']}")
print(f"LLM model: {stats['llm_model']}")
```

### Health Check

```python
from kryon.knowledge.health_check import print_health_status

# Check system health
print_health_status()
```

---

## Configuration

### Change Embedding Model

```python
from kryon.knowledge.embeddings import get_embedding_generator

# Use different model (more accuracy, slower)
generator = get_embedding_generator(model_name="all-mpnet-base-v2")
```

### Custom Chunk Size

```python
from kryon.knowledge.processors import DocumentProcessor

processor = DocumentProcessor(
    chunk_size=1024,  # Larger chunks
    chunk_overlap=100
)
```

---

## Performance Benchmarks

**Expected performance:**
- **Without LLM**: ~0.1-0.3s per query
- **With LLM**: ~3-5s per query
- **Cached**: ~0.01-0.02s per query

---

## Architecture

```
+---------------------------------------------+
|           KRYON Knowledge Base             |
+---------------------------------------------+
|                                             |
|  Scrapers --> Processors --> ChromaDB       |
|  (4 sources)  (3 types)     (vectors)       |
|                                  |          |
|                                  v          |
|                           RAG Engine        |
|                                  |          |
|                                  v          |
|                          Ollama (qwen)      |
|                                  |          |
|                                  v          |
|                         KRYON Agents       |
+---------------------------------------------+
```

---

## File Structure

```
src/kryon/knowledge/
|-- __init__.py                   # Main exports
|-- vector_db.py                  # ChromaDB wrapper
|-- embeddings.py                 # Sentence transformers
|-- rag_engine.py                 # RAG query engine
|-- auto_updater.py               # Auto-update scheduler
|-- cli.py                        # CLI tools
|-- scrapers/
|   |-- base_scraper.py           # Abstract base
|   |-- exploit_db_scraper.py     # Exploit-DB
|   |-- nvd_scraper.py            # NVD/CVE
|   |-- github_scraper.py         # GitHub repos
|   `-- writeup_scraper.py        # CTF writeups
`-- processors/
    |-- document_processor.py     # PDF/MD/TXT
    |-- code_processor.py         # Code analysis
    `-- metadata_extractor.py     # Metadata extraction
```

---

## Troubleshooting

### "chromadb not installed"

```bash
pip install chromadb
```

### "sentence-transformers not installed"

```bash
pip install sentence-transformers
```

### "GitHub rate limit exceeded"

Set `GITHUB_TOKEN` environment variable:

```bash
export GITHUB_TOKEN="your_github_token_here"
```

### "Ollama not responding"

```bash
# Start Ollama
ollama serve

# Verify
ollama list
```

### Vector DB Too Large

```python
from kryon.knowledge import get_vector_db

db = get_vector_db()
# Reset database (WARNING: deletes all knowledge)
db.reset()
```

---

## Pro Tips

1. **Start small**: Scrape 50-100 items per source initially
2. **Use filters**: Query with `source_filter` for specific sources
3. **Monitor size**: Check disk usage of `.kryon_knowledge/chromadb`
4. **GitHub token**: Set token to avoid rate limits
5. **Chunk wisely**: Smaller chunks = more precise, larger = more context

---

**KRYON now has access to thousands of exploits, CVEs, and techniques!**

*Last Updated: January 2025*
