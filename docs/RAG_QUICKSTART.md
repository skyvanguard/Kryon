# SKYNET RAG System - Quick Start Guide

**Knowledge Enhancement with Retrieval-Augmented Generation**

---

## What is RAG?

**RAG (Retrieval-Augmented Generation)** permite a SKYNET acceder a conocimiento masivo de múltiples fuentes:
- ✅ **Exploit-DB**: 40,000+ exploits
- ✅ **NVD**: National Vulnerability Database (CVEs)
- ✅ **GitHub**: PoC exploits y herramientas
- ✅ **CTF Writeups**: Técnicas y metodologías

SKYNET puede ahora responder preguntas como:
- "¿Cómo explotar Apache 2.4.49?"
- "Técnicas de privilege escalation en Linux"
- "PoC para CVE-2024-1234"

---

## 5-Minute Setup

### 1. Install Dependencies

```bash
pip install chromadb sentence-transformers schedule PyPDF2
```

### 2. Initialize Knowledge Base

```python
from skynet.knowledge import query_knowledge, start_auto_updater

# Query (will auto-initialize on first use)
result = query_knowledge("How to exploit SQL injection?")
print(result['answer'])
```

### 3. Start Auto-Updates

```python
from skynet.knowledge import start_auto_updater

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
from skynet.knowledge import query_knowledge

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
from skynet.knowledge import add_document

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
from skynet.knowledge.processors import DocumentProcessor
from skynet.knowledge import get_rag_engine

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
from skynet.knowledge.scrapers import ExploitDBScraper
from skynet.knowledge import get_rag_engine

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
from skynet.knowledge.scrapers import NVDScraper

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
from skynet.knowledge.scrapers import GitHubScraper

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
from skynet.knowledge import start_auto_updater, stop_auto_updater

# Start daily updates at 2 AM
start_auto_updater(
    schedule_type="daily",
    sources=["exploit-db", "nvd", "github", "writeups"],
    time_of_day="02:00"
)

# ... SKYNET keeps learning automatically ...

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
from skynet.knowledge import auto_update_knowledge

# Update now
auto_update_knowledge(sources=["exploit-db", "nvd"])
```

---

## Integration with Agents

### Use RAG in T-1000 Hunter

```python
from skynet.agents import t1000_hunter
from skynet.knowledge import query_knowledge

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

### Enhance Central Core

```python
from skynet.agents import central_core
from skynet.knowledge import query_knowledge

# Before exploitation, query knowledge
def enhanced_exploit(target, service):
    # Query RAG for techniques
    knowledge = query_knowledge(
        f"How to exploit {service}",
        top_k=5
    )

    # Use LLM answer
    techniques = knowledge['answer']

    # Execute with knowledge
    # ...
```

---

## CLI Usage

### Install CLI

```bash
# Add to PATH (optional)
alias skynet-knowledge="python -m skynet.knowledge.cli"
```

### CLI Commands

```bash
# Query knowledge
skynet-knowledge query "How to exploit SQL injection?"

# Add document
skynet-knowledge add /path/to/document.pdf

# Show statistics
skynet-knowledge stats

# Update knowledge
skynet-knowledge update exploit-db nvd github

# Scrape specific source
skynet-knowledge scrape github

# Help
skynet-knowledge help
```

---

## Statistics & Monitoring

### View Stats

```python
from skynet.knowledge import get_knowledge_stats

stats = get_knowledge_stats()

print(f"Total knowledge items: {stats['total_knowledge_items']}")
print(f"Sources: {stats['sources']}")
print(f"LLM model: {stats['llm_model']}")
```

### Update Stats

```python
from skynet.knowledge import get_auto_updater

updater = get_auto_updater()
stats = updater.get_stats()

print(f"Running: {stats['running']}")
print(f"Last update: {stats['last_update']}")
print(f"Total updates: {stats['total_updates']}")
```

---

## Real-World Examples

### Example 1: Research Vulnerability

```python
from skynet.knowledge import query_knowledge

# Research CVE-2021-41773
result = query_knowledge("CVE-2021-41773 Apache exploit")

print("**Vulnerability Info:**")
print(result['answer'])

print("\n**Available Exploits:**")
for source in result['sources']:
    if 'exploit' in source['content'].lower():
        print(f"- {source['metadata']['source']}: {source['content'][:150]}...")
```

### Example 2: Learn New Technique

```python
# Learn about privilege escalation
result = query_knowledge(
    "Linux privilege escalation using SUID binaries",
    top_k=10
)

print(result['answer'])

# Extract specific techniques
for source in result['sources']:
    if 'suid' in source['content'].lower():
        print(f"\nTechnique: {source['content'][:300]}...")
```

### Example 3: CTF Preparation

```python
# Prepare for HackTheBox
result = query_knowledge(
    "HackTheBox writeup techniques",
    source_filter="writeups",
    top_k=10
)

# Get common patterns
print("Common CTF patterns:")
print(result['answer'])
```

---

## Configuration

### Change Embedding Model

```python
from skynet.knowledge.embeddings import get_embedding_generator

# Use different model (more accuracy, slower)
generator = get_embedding_generator(model_name="all-mpnet-base-v2")
```

### Custom Chunk Size

```python
from skynet.knowledge.processors import DocumentProcessor

processor = DocumentProcessor(
    chunk_size=1024,  # Larger chunks
    chunk_overlap=100
)
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

### Vector DB Too Large

```python
from skynet.knowledge import get_vector_db

db = get_vector_db()

# Reset database (WARNING: deletes all knowledge)
db.reset()
```

---

## Architecture

```
┌─────────────────────────────────────────────┐
│           SKYNET Knowledge Base             │
├─────────────────────────────────────────────┤
│                                             │
│  Scrapers ──► Processors ──► ChromaDB      │
│  (4 sources)  (3 types)      (vectors)     │
│                                  │          │
│                                  ▼          │
│                           RAG Engine        │
│                                  │          │
│                                  ▼          │
│                          Ollama (qwen)      │
│                                  │          │
│                                  ▼          │
│                         SKYNET Agents       │
└─────────────────────────────────────────────┘
```

---

## File Structure

```
src/skynet/knowledge/
├── __init__.py                   # Main exports
├── vector_db.py                  # ChromaDB wrapper
├── embeddings.py                 # Sentence transformers
├── rag_engine.py                 # RAG query engine
├── auto_updater.py               # Auto-update scheduler
├── cli.py                        # CLI tools
├── scrapers/
│   ├── base_scraper.py           # Abstract base
│   ├── exploit_db_scraper.py     # Exploit-DB
│   ├── nvd_scraper.py            # NVD/CVE
│   ├── github_scraper.py         # GitHub repos
│   └── writeup_scraper.py        # CTF writeups
└── processors/
    ├── document_processor.py     # PDF/MD/TXT
    ├── code_processor.py         # Code analysis
    └── metadata_extractor.py     # Metadata extraction
```

---

## Next Steps

1. ✅ **Initialize**: Run first query to initialize ChromaDB
2. ✅ **Scrape**: Manually scrape initial knowledge
3. ✅ **Auto-update**: Start automatic daily updates
4. ✅ **Integrate**: Use RAG in your agents
5. ✅ **Monitor**: Check stats regularly

---

## Pro Tips

1. **Start small**: Scrape 50-100 items per source initially
2. **Use filters**: Query with `source_filter` for specific sources
3. **Monitor size**: Check disk usage of `.skynet_knowledge/chromadb`
4. **GitHub token**: Set token to avoid rate limits
5. **Chunk wisely**: Smaller chunks = more precise, larger = more context

---

**SKYNET now has access to thousands of exploits, CVEs, and techniques! 🚀**

For detailed documentation, see `docs/RAG_SYSTEM.md`
