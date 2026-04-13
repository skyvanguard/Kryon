# Kryon Self-Improving Loop v1

> Status: draft — v1 MVP
> Owner: skyvanguard
> Updated: 2026-04-12

## Problem

Kryon as shipped is a *stateless* agent framework: every engagement starts
from zero. The knowledge base is useful but static (MITRE, NVD, OWASP,
public writeups). Nothing that the agent **did** in a previous engagement
influences the next one. Handoffs between agents forget findings. There is
no feedback loop.

Goal of v1: **turn Kryon into a system that gets measurably better at
finding and exploiting vulnerabilities the more engagements it runs.**

## Non-goals for v1

- Fine-tuning the model
- RL / reward shaping
- Automatic prompt rewriting
- Sharing experiences across users or tenants
- Binary/exploit generation from mined chains

## Architecture (v1)

```
 user starts a new engagement
         │
         ▼
 ┌───────────────────────┐
 │ 1. Target Profiler    │  extract profile from user msg +
 │                       │  any early recon results
 └───────────┬───────────┘
             │ { host, ports, tech, os_hint, notes }
             ▼
 ┌───────────────────────┐
 │ 2. Experience Recall  │  query ChromaDB "kryon_experiences"
 │                       │  for top-K similar past engagements
 └───────────┬───────────┘
             │ top-K chains
             ▼
 ┌───────────────────────┐
 │ 3. Agent runs tools   │  every tool call is logged in the
 │                       │  existing conversation history
 └───────────┬───────────┘
             │
             ▼
 ┌───────────────────────┐
 │ 4. Engagement closure │  /close-engagement (or REPL exit):
 │    + chain mining     │  parse tool calls, classify outcome,
 │                       │  store experience
 └───────────────────────┘
```

## Data model

### Target profile

```python
{
  "host": "www.britimp.com.py",
  "resolved_ip": "54.69.84.63",
  "ports": [80, 110, 443, 993],
  "services": {"80": "http/apache", "443": "https/apache", "110": "pop3"},
  "tech": ["apache", "wordpress?"],     # from whatweb / nmap scripts
  "os_hint": "linux",                    # best guess
  "asn": "AS16509 AMAZON-02",            # optional
  "notes": "shared hosting with aldeatech",
}
```

### Experience record

```python
{
  "id": "eng_<uuid>",
  "created_at": "2026-04-12T02:18:00Z",
  "target_profile": { ... },             # as above
  "chain": [                             # ordered tool calls
    {"tool": "nmap",     "args": "-sV -sC -T4", "status": "ok"},
    {"tool": "whatweb",  "args": "https://...", "status": "ok"},
    {"tool": "gobuster", "args": "dir -u ...",  "status": "ok"},
    {"tool": "nuclei",   "args": "-t cves/",    "status": "ok"},
    ...
  ],
  "outcome": "partial",                  # success | partial | fail
  "outcome_signals": [                   # what we detected
    "shell_gained": false,
    "flag_found": false,
    "cve_confirmed": ["CVE-2024-XXXX"],
    "directories_found": 12,
  ],
  "agent_path": ["recon_scout"],         # agents that participated
  "duration_s": 320,
  "summary": "short text description",
}
```

The embedding goes over a **document** built from
`target_profile + summary + tools_used`, so similarity search finds
profiles with similar tech/port/outcome combinations.

### Storage

New ChromaDB collection: `kryon_experiences`, separate from
`kryon_knowledge`. Both use the same Ollama HTTP embedder
(`nomic-embed-text`).

Path: `/workspace/.kryon_knowledge/chromadb/` (same sqlite file,
different collection).

## Retrieval flow

When Recon Scout (or any recon-capable agent) identifies a target:

1. Build a preliminary profile (host + any known ports/tech).
2. Call `recall_similar_experiences(profile, k=3)`.
3. The tool returns a list of summaries like:
   > *"Previously against `AWS IP + Apache + WordPress + port 443`:
   >  nmap → whatweb → wpscan → credential-stuffing gave shell in 4m20s."*
4. The agent uses these as **hints**, not orders, to shape its plan.
   If prior chains show that step X was wasted on similar targets, skip
   it. If a specific tool combo worked fast before, try it first.

## Capture flow

`/close-engagement` command in the REPL:

1. Walk the current `conversation_input` / message history.
2. Extract every tool call + arguments + result excerpt.
3. Build a profile from the first successful scan (nmap or curl).
4. Classify outcome from signals:
   - Shell obtained → grep for `whoami`, `uid=`, shell prompts
   - Flag found → grep for `flag{`, `HTB{`, `THM{`
   - CVE confirmed → grep nuclei/searchsploit output for `CVE-`
   - Otherwise → `partial` or `fail`
5. Ask the user for a short `summary` line (optional, 1 prompt).
6. `add_experience(...)` persists the record.

Manual trigger first; auto-capture on exit can come later.

## REPL commands

| Command | Action |
|---|---|
| `/experiences` | List last N experiences with profile + outcome |
| `/experiences <id>` | Dump one full experience record |
| `/experiences search <query>` | Free-text similarity search |
| `/close-engagement [summary]` | Mine current session and save |

## Module layout

```
src/kryon/learning/
├── __init__.py            # public API: add_experience, recall,
│                          # build_profile, extract_chain
├── experiences.py         # ChromaDB store (add, query, list, get)
├── profiler.py            # target profile extractor
├── chain_extractor.py     # parse message history → tool chain +
│                          # outcome classification
└── README.md              # quick dev reference
```

Tools exposed to agents (in `src/kryon/tools/knowledge/`):

```
recall_similar_experiences(target_profile: dict, k: int = 3) -> list
```

## Metrics to track

v1 is a success if, over 10-15 engagements, we see:

- Median `duration_s` against similar profiles **decreasing**
- `outcome=success` rate **increasing**
- First attack-chain step reliably chosen from recalled chains
- Users (you) perceive Kryon as "remembering" prior work

We won't wire metrics dashboards in v1. Engagement logs already land in
`kryon-logs` volume; extracting metrics is a follow-up.

## Failure modes to watch

- **Garbage-in/garbage-out**: bad outcome classification poisons the store.
  Mitigation: user can delete experiences via `/experiences delete <id>`.
- **Profile drift**: two real-world targets with the same port list but
  completely different apps. Mitigation: include `tech` and `summary` in
  the embedding text so similarity is not purely ports-based.
- **Over-reliance on recall**: agent blindly follows a past chain that
  doesn't apply. Mitigation: prompt wording emphasizes "hints, not orders".

## v2 ideas (out of scope for this change)

- Failure memory ("this chain does not work against nginx+cloudflare")
- Automatic prompt patches when a new chain consistently outperforms the
  default playbook
- Cross-agent experience sharing (Pentest Agent reads Recon Scout experiences)
- Outcome auto-labeling via a small classifier model
- Time-decay on old experiences
