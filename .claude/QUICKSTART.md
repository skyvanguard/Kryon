# SKYNET CTF Master - Quick Start Guide

Get started with your enhanced Claude Code in 5 minutes.

## ⚡ Quick Setup

### 1. Verify Installation
```bash
cd /home/user/Skynet
ls .claude/
# Should see: commands/, skills/, prompts/, scripts/
```

### 2. Test Web Search
In Claude Code, try:
```
Search for "apache 2.4.49 exploit"
```

You should see Claude use WebSearch automatically.

### 3. Load CTF Skill
The CTF Master skill loads automatically when you mention CTF-related terms.

Test it:
```
I'm working on a TryHackMe challenge
```

### 4. Try a Command
```
/ctf-research "sql injection bypass waf"
```

## 🎯 Your First CTF with Enhanced Claude

### Scenario: TryHackMe Box at 10.10.10.5

**Step 1**: Start reconnaissance
```
/ctf-recon 10.10.10.5
```

Claude will:
- Run comprehensive port scans
- Enumerate services
- Search for known vulnerabilities
- Provide prioritized attack vectors

**Step 2**: Research findings
```
/ctf-research "apache 2.4.49"
```

Claude will:
- Query local RAG knowledge base
- Web search for exploits
- Find CTF writeups
- Aggregate findings

**Step 3**: If you get stuck
```
/ctf-stuck "found web server but no entry point"
```

Claude will:
- Web search similar challenges
- Suggest lateral approaches
- Provide creative techniques
- Give specific action items

**Step 4**: Privilege escalation
```
/ctf-privesc linux
```

Claude will:
- Guide through automated enumeration
- Check all common privesc vectors
- Research specific findings
- Provide exploitation commands

## 🧠 Key Differences vs. Vanilla Claude

### Before (Vanilla)
```
You: "How do I exploit Apache 2.4.49?"
Claude: "Apache 2.4.49 has a known path traversal vulnerability..."
[Only uses training data knowledge]
```

### After (CTF Master)
```
You: "How do I exploit Apache 2.4.49?"
Claude:
1. [Queries local RAG knowledge base]
2. [Searches web for recent exploits]
3. "Apache 2.4.49 has CVE-2021-41773, here's the latest PoC from GitHub..."
4. [Provides multiple exploitation methods]
5. [Links to working exploits]
6. "If that doesn't work, try these alternatives..."
```

## 🎮 Common Workflows

### Workflow 1: Start Challenge
```
Hey Claude, I'm solving TryHackMe "BasicPentesting" at 10.10.10.5
/ctf-recon 10.10.10.5
```

### Workflow 2: Research Vulnerability
```
/ctf-research "wordpress 5.8 xmlrpc exploit"
```

### Workflow 3: Get Unstuck
```
/ctf-stuck "tried SQLi, LFI, and directory fuzzing - no luck"
```

### Workflow 4: Privilege Escalation
```
Got www-data shell. Help me escalate to root.
/ctf-privesc linux
```

### Workflow 5: Generate Writeup
```
/ctf-writeup BasicPentesting
```

## 💡 Pro Tips

### 1. Use Commands Liberally
Don't wait to get stuck:
```
# At start
/ctf-recon [target]

# For any unknown
/ctf-research [service]

# Before giving up
/ctf-stuck

# After solving
/ctf-writeup [name]
```

### 2. Be Specific in Research
```
# Good
/ctf-research "apache 2.4.49 path traversal rce"

# Even better
/ctf-research "apache 2.4.49 cve-2021-41773 poc github"
```

### 3. Leverage Web Search
Just ask naturally:
```
"Search for recent apache exploits"
"Find writeups for similar challenges"
"Look up GTFOBins for /usr/bin/find"
```

### 4. Combine with SKYNET Agents
```bash
# In terminal
SKYNET_CORE=t800_infiltrator skynet

# Then in SKYNET, Claude has all these capabilities
```

### 5. Iterate on Stuck
```
/ctf-stuck "no web vulns found"
[Try suggestions]

/ctf-stuck "web vulns didn't work, maybe internal services?"
[Try new suggestions]
```

## 🔍 Test Your Setup

Run these tests to verify everything works:

### Test 1: Web Search
```
Search for "CVE-2021-41773 exploit"
```
✅ Should show web search results

### Test 2: CTF Skill
```
I'm stuck on a CTF challenge
```
✅ Should activate creative problem-solving

### Test 3: RAG Integration
```
/ctf-research "buffer overflow"
```
✅ Should query both RAG and web

### Test 4: Commands
```
/ctf-stuck
```
✅ Should provide unstuck strategies

## 📊 What Claude Does Automatically Now

### When You Say "CTF"
- Activates CTF Master skill
- Enables creative thinking mode
- Prepares to use web search aggressively
- Loads exploitation methodologies

### When You Get Stuck
- Detects frustration/confusion
- Automatically searches web for solutions
- Suggests lateral approaches
- Never gives up

### When Researching
- Queries local RAG first
- Searches web for recent intel
- Aggregates findings
- Synthesizes actionable plan

### When Exploiting
- Thinks in exploit chains
- Tries multiple approaches
- Learns from failures
- Pivots quickly

## 🚀 Ready to Go!

You're all set. Claude is now:
- ✅ Enhanced with CTF methodologies
- ✅ Connected to web search
- ✅ Integrated with SKYNET RAG
- ✅ Equipped with specialized commands
- ✅ Configured for maximum persistence

## 🎯 Your Next Steps

1. Pick a TryHackMe challenge
2. Use `/ctf-recon [target]` to start
3. Research as you go with `/ctf-research`
4. Never get stuck with `/ctf-stuck`
5. Document with `/ctf-writeup`

## 💪 You've Got This!

Remember:
- **Claude doesn't give up** - neither should you
- **Web search is your superpower** - use it liberally
- **Think creatively** - try the "stupid" ideas
- **Chain exploits** - small vulns combine into big wins
- **Document everything** - learn for next time

Happy hacking! 🎯🔥

---

**Need help?** Check `.claude/README.md` for full documentation.
