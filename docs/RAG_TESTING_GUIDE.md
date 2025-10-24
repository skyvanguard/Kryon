# SKYNET RAG System - Testing & Validation Guide

**Complete Testing Framework for Knowledge Enhancement System**

---

## Quick Start - Test in 5 Minutes

### 1. Validate System

```bash
cd C:\Users\admin\Documents\cai
python scripts/validate_rag.py
```

**Expected Output:**
```
✅ Dependencies
✅ SKYNET Modules
✅ Vector Database
✅ Embeddings
✅ RAG Engine
✅ LLM Integration
✅ Scrapers
✅ Disk Space

Result: 8/8 checks passed
🎉 All checks passed! RAG system is ready to use.
```

### 2. Initialize Knowledge Base

```bash
python scripts/initialize_knowledge.py --sources all --exploits 100
```

**This will:**
- Scrape ~100 exploits from Exploit-DB
- Scrape ~50 CVEs from NVD (last 7 days)
- Scrape ~20 GitHub repositories
- Add CTF writeup methodologies
- Show progress bars and statistics

**Time:** ~5-10 minutes depending on network

### 3. Verify Knowledge

```bash
python scripts/verify_knowledge.py
```

**Generates:**
- Document count
- Source breakdown
- Sample query tests
- JSON report file

---

## Comprehensive Testing

### Unit Tests

Run all unit tests:

```bash
pytest tests/test_rag_system.py -v
```

**Tests included:**
- ✅ Vector database initialization
- ✅ Document add/query/delete
- ✅ Embedding generation
- ✅ RAG query engine
- ✅ Document processing
- ✅ Metadata extraction
- ✅ Imports and dependencies

**Sample output:**
```
tests/test_rag_system.py::TestVectorDatabase::test_database_initialization PASSED
tests/test_rag_system.py::TestVectorDatabase::test_add_documents PASSED
tests/test_rag_system.py::TestVectorDatabase::test_query_documents PASSED
tests/test_rag_system.py::TestEmbeddings::test_embedding_generation PASSED
tests/test_rag_system.py::TestRAGEngine::test_query_knowledge PASSED
...
============================== 15 passed in 12.34s ==============================
```

---

## Validation Scripts

### 1. System Validation (`validate_rag.py`)

**What it checks:**
- Dependencies installed (chromadb, sentence-transformers, etc.)
- SKYNET modules importable
- ChromaDB initialization
- Embedding model download
- RAG engine functionality
- LLM (Ollama) connectivity
- Scraper availability
- Disk space

**Usage:**
```bash
python scripts/validate_rag.py
```

**Output sections:**
1. **Checking Dependencies** - Required and optional packages
2. **Checking SKYNET Modules** - Import tests
3. **Checking Vector Database** - ChromaDB operations
4. **Checking Embeddings** - Model download and generation
5. **Checking RAG Engine** - Add/query functionality
6. **Checking LLM Integration** - Ollama connectivity
7. **Checking Scrapers** - Availability of all scrapers
8. **Checking Disk Space** - Free space and KB size

### 2. Knowledge Initialization (`initialize_knowledge.py`)

**What it does:**
- Scrapes multiple knowledge sources
- Shows progress bars
- Adds to vector database
- Displays statistics

**Basic usage:**
```bash
python scripts/initialize_knowledge.py
```

**Advanced options:**
```bash
# Specific sources only
python scripts/initialize_knowledge.py --sources exploit-db nvd

# Custom counts
python scripts/initialize_knowledge.py \
  --exploits 500 \
  --nvd-days 14 \
  --nvd-count 300 \
  --github-count 100

# Quick test (small dataset)
python scripts/initialize_knowledge.py \
  --exploits 50 \
  --nvd-count 20 \
  --github-count 10
```

**Progress output:**
```
═══════════════════════════════════════════════════════════════
  Scraping Exploit-DB
═══════════════════════════════════════════════════════════════

Scraping with 17 keyword sets...
Target: ~500 exploits

Progress |████████████████████████████████████████████████| 17/17 100.0% Complete

✅ Scraped 487 unique exploits from Exploit-DB

Adding 487 items to knowledge base...
Adding |████████████████████████████████████████████████| 487/487 100.0% documents

───────────────────────────────────────────────────────────────
  Initialization Complete
───────────────────────────────────────────────────────────────

⏱️  Time elapsed: 245.3 seconds
📊 Total items added: 612

Sources breakdown:
  - exploit-db: 487 items
  - nvd: 52 items
  - github: 48 items
  - writeups: 25 items
```

### 3. Knowledge Verification (`verify_knowledge.py`)

**What it does:**
- Counts documents
- Shows source breakdown
- Tests sample queries
- Generates JSON report

**Usage:**
```bash
python scripts/verify_knowledge.py
```

**Output:**
```
✅ Total Knowledge Items: 612
✅ LLM Configured: Yes
✅ LLM Model: qwen2.5:7b
✅ Database: .skynet_knowledge/chromadb

📚 Source Breakdown:
  - exploit-db: 487 documents
  - nvd: 52 documents
  - github: 48 documents
  - writeups: 25 documents

🔍 Testing Sample Queries...

✅ 'SQL injection techniques': 15 results
✅ 'Apache vulnerability': 23 results
✅ 'Linux privilege escalation': 31 results
✅ 'XSS exploitation': 12 results

📄 Report saved to: knowledge_report_20251023_142530.json
```

---

## Health Check System

### Real-time Health Monitoring

```python
from skynet.knowledge.health_check import print_health_status

# Check system health
print_health_status()
```

**Output:**
```
============================================================
  SKYNET Knowledge Health Status
============================================================

✅ Vector Database: healthy
   Documents: 612

✅ LLM: healthy
   Models: 3

✅ Disk Space:
   Knowledge base: 142.35 MB
   Free space: 245.67 GB

✅ Dependencies: healthy

────────────────────────────────────────────────────────────
✅ All systems operational
────────────────────────────────────────────────────────────
```

### Programmatic Health Check

```python
from skynet.knowledge import health_check

status = health_check()

if status["all_systems_operational"]:
    print("✅ Ready to use")
else:
    print("⚠️  Issues detected:")
    for component, details in status.items():
        if isinstance(details, dict) and not details.get("operational"):
            print(f"  - {component}: {details.get('status')}")
```

---

## Query Cache Testing

### Test Cache Performance

```python
from skynet.knowledge import query_knowledge
from skynet.knowledge.query_cache import get_cache_stats
import time

# Query 1 (miss - slow)
start = time.time()
result1 = query_knowledge("SQL injection techniques")
time1 = time.time() - start

# Query 2 (hit - fast)
start = time.time()
result2 = query_knowledge("SQL injection techniques")
time2 = time.time() - start

print(f"First query: {time1:.2f}s")
print(f"Cached query: {time2:.2f}s")
print(f"Speedup: {time1/time2:.1f}x")

# Cache stats
stats = get_cache_stats()
print(f"\nCache hit rate: {stats['hit_rate']:.1%}")
print(f"Total requests: {stats['total_requests']}")
```

**Expected output:**
```
First query: 3.45s
Cached query: 0.02s
Speedup: 172.5x

Cache hit rate: 50.0%
Total requests: 2
```

---

## Agent Integration Testing

### Test RAG Mixin

```python
from skynet.agents.mixins import RAGMixin

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

        # Check knowledge availability
        if self.check_knowledge_available("WordPress exploit"):
            print("✅ WordPress knowledge available")

# Test it
agent = TestAgent()
agent.test_knowledge()
```

---

## Performance Benchmarks

### Benchmark Script

```python
import time
from skynet.knowledge import query_knowledge

queries = [
    "SQL injection in MySQL",
    "Apache 2.4.49 vulnerability",
    "Linux SUID privilege escalation",
    "XSS bypass techniques",
    "WordPress plugin exploits"
]

print("Running performance benchmark...\n")

times = []
for query in queries:
    start = time.time()
    result = query_knowledge(query, top_k=5, use_llm=False)
    elapsed = time.time() - start
    times.append(elapsed)

    print(f"Query: '{query}'")
    print(f"  Time: {elapsed:.3f}s")
    print(f"  Results: {len(result['sources'])}")
    print()

avg_time = sum(times) / len(times)
print(f"Average query time: {avg_time:.3f}s")
```

**Expected performance:**
- **Without LLM**: ~0.1-0.3s per query
- **With LLM**: ~3-5s per query
- **Cached**: ~0.01-0.02s per query

---

## Troubleshooting Tests

### Test 1: Dependencies

```bash
python -c "import chromadb, sentence_transformers, schedule; print('✅ All dependencies OK')"
```

### Test 2: ChromaDB

```python
from skynet.knowledge import get_vector_db

db = get_vector_db()
print(f"✅ Database initialized")
print(f"📊 Documents: {db.count()}")
```

### Test 3: Embeddings

```python
from skynet.knowledge.embeddings import generate_embedding

emb = generate_embedding("test")
print(f"✅ Embedding size: {len(emb)}")
```

### Test 4: LLM Connection

```python
import requests

response = requests.get("http://localhost:11434/api/tags")
if response.status_code == 200:
    models = response.json()['models']
    print(f"✅ Ollama running: {len(models)} models")
else:
    print(f"❌ Ollama not responding")
```

### Test 5: End-to-End Query

```python
from skynet.knowledge import query_knowledge, add_document

# Add test document
doc_id = add_document("Test Apache exploit CVE-2021-41773", "test")
print(f"✅ Added document: {doc_id}")

# Query it
result = query_knowledge("Apache CVE-2021-41773", use_llm=False)
print(f"✅ Query successful: {len(result['sources'])} sources")

# Cleanup
from skynet.knowledge import get_vector_db
get_vector_db().delete_by_ids([doc_id])
print(f"✅ Cleanup successful")
```

---

## Common Issues & Fixes

### Issue: "chromadb not installed"

```bash
pip install chromadb
```

### Issue: "sentence-transformers not installed"

```bash
pip install sentence-transformers
```

### Issue: "Ollama not responding"

```bash
# Start Ollama
ollama serve

# In another terminal, verify
ollama list
```

### Issue: "No documents in knowledge base"

```bash
# Initialize with some data
python scripts/initialize_knowledge.py --exploits 50
```

### Issue: "Disk space warning"

```python
from skynet.knowledge import get_vector_db

# Reset database (WARNING: deletes all data)
db = get_vector_db()
db.reset()
```

---

## Testing Checklist

Before using RAG in production:

- [ ] ✅ Run `validate_rag.py` - all checks pass
- [ ] ✅ Run `pytest tests/test_rag_system.py` - all tests pass
- [ ] ✅ Initialize knowledge base - at least 100 documents
- [ ] ✅ Test sample queries - get meaningful results
- [ ] ✅ Check LLM integration - Ollama responding
- [ ] ✅ Verify cache working - queries faster on second try
- [ ] ✅ Test agent mixin - can be imported and used
- [ ] ✅ Check disk space - > 1GB free
- [ ] ✅ Run health check - all systems operational

---

## Next Steps

1. **Initialize**: `python scripts/initialize_knowledge.py`
2. **Verify**: `python scripts/verify_knowledge.py`
3. **Test**: `pytest tests/test_rag_system.py`
4. **Use**: Start querying with `query_knowledge()`

---

**All testing infrastructure is ready! 🚀**

For usage examples, see `docs/RAG_QUICKSTART.md`
