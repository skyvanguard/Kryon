---
description: "Research a vulnerability, service, or technique using web search and local RAG"
---

# CTF Research Command

Perform comprehensive research on a topic using multiple sources.

## Research Strategy

### 1. Local Knowledge Base (RAG)
Query SKYNET's RAG system for instant knowledge:
```python
from skynet.knowledge import query_knowledge_async
result = await query_knowledge_async("[topic]")
```

### 2. Web Search (Primary Intelligence)
Execute targeted web searches:
- **General**: "[topic] exploitation technique"
- **CTF-Specific**: "[topic] ctf writeup github"
- **Technical**: "[topic] vulnerability research paper"
- **Practical**: "[topic] metasploit module"
- **Recent**: "[topic] exploit 2024" or "[topic] exploit 2025"

### 3. Exploit Database
Search local and online databases:
- `searchsploit [topic]`
- Check: exploit-db.com, packetstormsecurity.com
- GitHub search: "[topic] exploit poc"

### 4. Tool Documentation
Find advanced usage:
- Official tool documentation
- GitHub README and issues
- Security blogs and tutorials

### 5. CVE Correlation
If version is known:
- Search: "CVE [service] [version]"
- Check: nvd.nist.gov, cvedetails.com
- Find PoCs: "[CVE-ID] exploit"

## Output Format

Structured intelligence report:
1. **Summary**: What is this vulnerability/service?
2. **Exploitation**: How can it be exploited?
3. **Tools**: Which tools can help?
4. **Examples**: Real-world examples/CTF writeups
5. **PoCs**: Proof-of-concept code/commands
6. **Prevention**: How is it typically defended? (helps understand attacker mindset)

## Smart Aggregation

Combine findings from:
- RAG knowledge base
- Web search results
- Exploit databases
- Community writeups

Synthesize into actionable intelligence.

**Usage**: `/ctf-research [vulnerability/service/technique]`
