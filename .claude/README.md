# SKYNET CTF Master - Claude Code Configuration

Advanced Claude Code configuration for insane-level CTF challenges.

## 🎯 What This Adds

### 1. CTF Master Skill
**Location**: `.claude/skills/ctf-master.md`

Embeds advanced CTF methodologies directly into Claude's context:
- Creative problem-solving when stuck
- Automated web research triggers
- Lateral thinking techniques
- Exploit chaining strategies
- Persistence tactics

**Activation**: Automatically loads when working on CTF challenges

### 2. Specialized Slash Commands

| Command | Purpose | Usage |
|---------|---------|-------|
| `/ctf-recon` | Full reconnaissance | `/ctf-recon 10.10.10.5` |
| `/ctf-stuck` | Emergency unstuck mode | `/ctf-stuck` or `/ctf-stuck "tried SQLi"` |
| `/ctf-research` | Research topic with web search | `/ctf-research "apache 2.4.49 exploit"` |
| `/ctf-privesc` | Privilege escalation guide | `/ctf-privesc linux` |
| `/ctf-web` | Web app security testing | `/ctf-web http://target.com` |

### 3. Enhanced System Prompt
**Location**: `.claude/prompts/system-prompt.md`

Configures Claude to:
- Use WebSearch aggressively (built-in, no API needed!)
- Think creatively and laterally
- Never give up when stuck
- Chain exploits naturally
- Research continuously

### 4. Integration with SKYNET
Seamlessly works with your existing:
- RAG knowledge base (example_async_rag.py)
- Kali Linux container
- T-800/T-1000 agents
- Exploit databases

## 🚀 How to Use

### Basic Usage
Just start solving a CTF normally in Claude Code. The configuration will automatically enhance your workflow.

### When Stuck
```
/ctf-stuck
```
This triggers:
1. Web search for similar challenges
2. Alternative approach suggestions
3. Creative technique recommendations
4. Research aggregation from multiple sources

### Research a Topic
```
/ctf-research "buffer overflow linux"
```
Claude will:
1. Query local RAG knowledge base
2. Web search for exploits and techniques
3. Find CTF writeups
4. Aggregate and synthesize findings

### Full Reconnaissance
```
/ctf-recon 10.10.10.5
```
Executes comprehensive enumeration with creative checks.

## 🧠 Key Features

### 1. Automatic Web Research
Claude will **automatically** search the web when:
- Stuck for >5 minutes
- Unknown service/vulnerability encountered
- Exploit fails unexpectedly
- You explicitly ask for research

**No API key needed** - uses Claude's built-in WebSearch!

### 2. Creative Problem Solving
When enumeration yields no obvious path:
- Tests default credentials
- Looks for hidden files
- Tries "stupid" ideas that often work
- Checks for steganography
- Tests logical flaws

### 3. Exploit Chaining
Thinks in attack chains:
- LFI + Log Poisoning → RCE
- SSRF + Redis → RCE
- SQLi + File Write → Shell
- XXE + File Read → Credentials

### 4. Never Give Up
If completely stuck:
- Web search for exact challenge name
- Read writeups to learn approach (not copy solution)
- Apply methodology to your attempt
- Document learnings

## 📊 Comparison: Before vs After

### Before (Vanilla Claude Code)
- ❌ Gets stuck frequently
- ❌ Limited to training data knowledge
- ❌ Doesn't think laterally
- ❌ Gives up after obvious attempts fail

### After (SKYNET CTF Master)
- ✅ Auto-searches web when stuck
- ✅ Accesses real-time vulnerability data
- ✅ Tries creative and lateral approaches
- ✅ Persistent until challenge solved
- ✅ Learns from community writeups
- ✅ Chains exploits naturally

## 🔧 Advanced Configuration

### Enable/Disable Features

Edit `.claude/claude.json`:
```json
{
  "features": {
    "webSearch": true,        // Toggle web research
    "creativity": "high"      // Set thinking mode
  },
  "settings": {
    "autonomy": "high",       // How proactive Claude is
    "persistence": "aggressive" // How persistent on challenges
  }
}
```

### Customize System Prompt

Edit `.claude/prompts/system-prompt.md` to:
- Add your specific methodologies
- Configure search triggers
- Adjust persistence levels
- Add custom tools/scripts

### Add Custom Commands

Create new files in `.claude/commands/`:
```bash
.claude/commands/my-command.md
```

Format:
```markdown
---
description: "What this command does"
---

# Command content here
```

## 💡 Tips for Maximum Effectiveness

### 1. Use Commands Liberally
Don't wait until stuck - use `/ctf-research` proactively:
```
/ctf-research "apache 2.4.49"
```

### 2. Combine with SKYNET Agents
```bash
# Let T-800 handle it with enhanced Claude
SKYNET_CORE=t800_infiltrator skynet
```

### 3. Leverage RAG Knowledge
Your local knowledge base is automatically queried alongside web search:
```python
# This happens automatically in commands
from skynet.knowledge import query_knowledge_async
```

### 4. Web Search Syntax
Be specific in your questions:
```
"buffer overflow exploit github 2024"
"apache 2.4.49 rce poc"
"tryhackme [challenge_name] writeup"
```

### 5. Iterate and Learn
After solving a challenge:
- Document what worked
- Add techniques to your notes
- Update custom commands if needed

## 🎮 Example Workflow

### TryHackMe Insane Challenge

1. **Start**:
   ```
   Hey Claude, I'm working on TryHackMe challenge "InsaneBox" at 10.10.10.5
   ```

2. **Reconnaissance**:
   ```
   /ctf-recon 10.10.10.5
   ```

3. **Research Findings**:
   ```
   /ctf-research "apache 2.4.49 exploit"
   ```

4. **Get Stuck?**:
   ```
   /ctf-stuck "tried Apache exploit, got shell but can't escalate privileges"
   ```

5. **Privilege Escalation**:
   ```
   /ctf-privesc linux
   ```

6. **Web App Testing**:
   ```
   /ctf-web http://10.10.10.5:8080
   ```

Throughout the process, Claude will:
- Automatically search web when stuck
- Think creatively about alternatives
- Chain exploits naturally
- Never give up until solved

## 🔍 Troubleshooting

### Claude not searching web?
Check `.claude/claude.json`:
```json
"features": {
  "webSearch": true
}
```

### Commands not working?
Ensure files are in correct locations:
```
.claude/
├── commands/
│   ├── ctf-recon.md
│   ├── ctf-stuck.md
│   └── ...
└── skills/
    └── ctf-master.md
```

### Want more aggressive research?
Edit `.claude/prompts/system-prompt.md`:
- Lower the "stuck" threshold (change from 10 min to 5 min)
- Add more search triggers
- Increase search result processing

## 📚 Learning Resources

Your configuration now integrates:
1. **Local RAG** - SKYNET knowledge base
2. **Web Search** - Real-time intelligence
3. **Community** - CTF writeups and forums
4. **Tools** - Kali Linux container
5. **Methodologies** - Embedded in skills/prompts

## 🎯 Success Stories

With this configuration, Claude can solve:
- ✅ Insane-level TryHackMe boxes
- ✅ Hard HackTheBox machines
- ✅ CTF challenges with obscure exploits
- ✅ Challenges requiring creative thinking
- ✅ Multi-stage exploitation chains

## 🚨 Important Notes

### Ethical Usage
- Only use on authorized targets
- CTF platforms, bug bounties, owned systems
- Never on production systems without permission

### API Keys
**You don't need any additional API keys!**
- WebSearch: Built into Claude Code (free with Max account)
- RAG: Local SKYNET knowledge base
- Tools: Local Kali container

### Privacy
All research happens through Claude's built-in search:
- No third-party APIs
- No external services
- Your challenges remain private

## 🔄 Updates

To update this configuration:
1. Edit files in `.claude/` directory
2. Restart Claude Code session
3. Changes take effect immediately

## 📞 Support

Issues? Ideas?
- Check SKYNET docs: `/docs/`
- Review this README
- Experiment with commands
- Iterate and improve!

---

**Remember**: This configuration doesn't replace your skills - it amplifies them. You're still the hacker. Claude is your enhanced toolkit. 🚀
