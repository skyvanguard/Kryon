# Skynet Scripts

Helper scripts for Skynet framework initialization and management.

## init_knowledge.py

Initializes the Skynet knowledge base with CTF techniques.

### Usage

```bash
# After installing dependencies:
python scripts/init_knowledge.py
```

This will import knowledge from:
- `data/ctf_knowledge/web_techniques.txt` → Web exploitation
- `data/ctf_knowledge/linux_privesc.txt` → Linux privilege escalation
- `data/ctf_knowledge/crypto_techniques.txt` → Cryptography
- `data/ctf_knowledge/pwn_techniques.txt` → Binary exploitation

### What it does

1. Reads all `.txt` files from `data/ctf_knowledge/`
2. Chunks the content intelligently
3. Generates embeddings (using local sentence-transformers or OpenAI)
4. Stores in ChromaDB vector database
5. Makes knowledge searchable via semantic search

### After initialization

Test the knowledge base:

```bash
# Search for techniques
python -m skynet.cli.quick search "sql injection bypass"
python -m skynet.cli.quick search "privilege escalation linux"
python -m skynet.cli.quick search "buffer overflow"

# Check count
python skynet.py knowledge count
```

## Adding More Knowledge

### From files

```bash
# Add single file
python skynet.py knowledge add \
  --file ~/my_ctf_writeup.txt \
  --category general \
  --source "HTB-Machine-Name"

# Add directory of writeups
python skynet.py knowledge add \
  --directory ~/ctf_writeups/ \
  --category general \
  --pattern "*.md"
```

### Manually

```python
from skynet.rag.retriever import get_retriever

retriever = get_retriever()
retriever.add_knowledge(
    content="Your CTF technique here",
    category="web",
    source="manual"
)
```

## Maintenance

### Export knowledge base

```bash
python skynet.py knowledge export --output backup.json
```

### Import knowledge base

```bash
python skynet.py knowledge import --input backup.json
```

### Check statistics

```bash
python skynet.py knowledge count
```
