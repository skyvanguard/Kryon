# SKYNET Autonomy & Self-Improvement - Quick Start Guide

**5-Minute Quick Start** | **Clearance Level: Omega-Command**

---

## What's New? 🚀

SKYNET now has **complete autonomy** and **self-improvement** capabilities:

- ✅ **Autonomous Decision Making** - No human intervention needed (configurable)
- ✅ **Learning Engine** - Learns from every operation
- ✅ **Auto-Evasion** - Bypasses WAF/IDS/IPS automatically
- ✅ **Exploit Generation** - Creates custom exploits with LLM
- ✅ **CVE Discovery** - Auto-discovers and integrates new CVEs
- ✅ **Knowledge Sharing** - Share learning between instances
- ✅ **Performance Optimization** - Auto-tunes strategies

---

## Quick Examples

### 1. Solve a CTF Automatically (Most Common Use Case)

```python
from skynet.tools.autonomous import autonomous_ctf_solver

# Just provide the IP - SKYNET does the rest
result = autonomous_ctf_solver(
    target_ip="10.10.245.67",
    difficulty="medium",
    max_time_hours=2
)

# Check results
if result['success']:
    print(f"✅ Flags found: {len(result['flags_found'])}")
    for flag in result['flags_found']:
        print(f"  {flag['name']}: {flag['value']}")
else:
    print(f"❌ Failed: {result.get('error')}")
```

**What happens automatically:**
1. Reconnaissance (nmap, gobuster, vulnerability scan)
2. Exploit selection based on learned patterns
3. Adaptive exploitation with auto-retry
4. Privilege escalation
5. Flag hunting
6. Records operation for future learning

---

### 2. Check Learning Recommendations

```python
from skynet.tools.autonomous import get_learned_recommendations

# Get recommendations for a Linux target with Apache
recommendations = get_learned_recommendations(
    target_profile={
        "os": "linux",
        "services": ["apache", "ssh"]
    },
    top_n=5
)

print("Recommended exploits based on past success:")
for exploit in recommendations['recommended_exploits']:
    print(f"  - {exploit['exploit_name']}: {exploit['success_rate']:.1%} success")
```

---

### 3. Share Knowledge with Your Team

```python
from skynet.tools.autonomous import export_knowledge, import_knowledge

# Export your learned patterns
export_knowledge(
    output_file="/tmp/my_knowledge.json.gz",
    filter_sensitive=True  # Removes IPs/domains
)

# Import from teammate
import_knowledge(
    import_file="/tmp/teammate_knowledge.json.gz",
    merge_strategy="best"  # Keep best patterns
)
```

---

### 4. Auto-Update Exploit Database

```python
from skynet.tools.autonomous import auto_update_exploits

# Automatically discover new CVEs and add them
stats = auto_update_exploits(
    services=["apache", "nginx", "wordpress", "ssh"]
)

print(f"Discovered {stats['scraped']} CVEs")
print(f"Integrated {stats['integrated']} into database")
```

---

### 5. Generate Custom Exploit

```python
from skynet.tools.autonomous import generate_exploit

# LLM creates a custom exploit
exploit = generate_exploit(
    service="apache",
    version="2.4.41",
    vulnerability="CVE-2021-41773"
)

if exploit['valid']:
    print("✅ Exploit generated successfully!")
    print(exploit['code'])
else:
    print(f"❌ Validation failed: {exploit['validation_errors']}")
```

---

## Configuration

### Set Operation Mode

```python
from skynet.tools.autonomous import get_decision_engine, OperationMode

engine = get_decision_engine()

# Choose your autonomy level:
engine.set_mode(OperationMode.CONSERVATIVE)  # Confirm MEDIUM+ risk
engine.set_mode(OperationMode.MODERATE)      # Confirm HIGH+ risk (recommended)
engine.set_mode(OperationMode.AGGRESSIVE)    # Confirm CRITICAL only
```

### Configure LLM (Already Done for You)

Your Ollama is already configured with `qwen2.5:7b` at `http://localhost:11434`.

To change:

```bash
# Edit ~/.skynet/config.json
{
  "base_url": "http://localhost:11434",
  "model": "qwen2.5:7b",
  "temperature": 0.3
}
```

---

## Performance Analysis

```python
from skynet.tools.autonomous import analyze_performance

report = analyze_performance(time_window_days=30)

print(f"Success rate: {report['overall_metrics']['success_rate']:.1%}")
print(f"Total operations: {report['overall_metrics']['total_operations']}")
print("\nTop exploits:")
for e in report['exploit_rankings'][:3]:
    print(f"  {e['exploit_name']}: {e['success_rate']:.1%}")
```

---

## Real-World Example: TryHackMe Room

```python
from skynet.tools.autonomous import (
    autonomous_ctf_solver,
    analyze_performance,
    export_knowledge
)

# 1. Solve the room
print("🎯 Starting autonomous CTF solver...")
result = autonomous_ctf_solver(
    target_ip="10.10.245.67",
    target_type="linux",
    difficulty="medium",
    max_time_hours=2,
    flags_needed=["user.txt", "root.txt"]
)

# 2. Show results
if result['success']:
    print("✅ CTF SOLVED!")
    print(f"Time: {result['time_elapsed']:.1f}s")
    print(f"Privilege: {result['privilege_level']}")

    for flag in result['flags_found']:
        print(f"  🚩 {flag['name']}: {flag['value']}")

    # 3. Export knowledge for next time
    export_knowledge("/tmp/thm_knowledge.json.gz")
    print("💾 Knowledge exported for future use")

    # 4. Check what worked
    perf = analyze_performance()
    print(f"📊 Overall success rate: {perf['overall_metrics']['success_rate']:.1%}")
else:
    print(f"❌ Failed: {result.get('error')}")
    print("💡 SKYNET will learn from this and improve")
```

---

## Evasion Techniques

### Automatic Payload Encoding

```python
from skynet.tools.evasion import encode

# Original payload
payload = "<?php system($_GET['cmd']); ?>"

# Automatically encoded to bypass WAF
encoded = encode(payload, technique="auto")  # Random technique
base64 = encode(payload, technique="base64")
url = encode(payload, technique="url")
hex_enc = encode(payload, technique="hex")
```

### Command Obfuscation

```python
from skynet.tools.evasion import obfuscate

command = "cat /etc/passwd"
variants = obfuscate(command)

# Returns multiple obfuscated versions:
# - Base64 + decode
# - Hex + decode
# - IFS substitution
# - Variable indirection
```

---

## Safety Features

### Honeypot Detection

Automatically detects and avoids honeypots:
- Too many open ports (>50)
- Suspicious banners
- Unusual service combinations

### Production Protection

HIGH+ risk actions automatically blocked on production systems detected by:
- Corporate IP ranges
- Critical infrastructure keywords

### Risk Levels

| Level    | Examples                | Auto-Execute? |
|----------|------------------------|---------------|
| SAFE     | Recon, passive scan    | ✅ Always     |
| LOW      | Safe exploits          | ✅ Always     |
| MEDIUM   | Active exploitation    | ✅ MODERATE+  |
| HIGH     | Aggressive exploits    | ❌ Ask first  |
| CRITICAL | Data exfil, persistence| ❌ Ask first  |

---

## Knowledge Database

All operations are stored in `.skynet_knowledge/operations.db` (SQLite).

**View your learning:**

```python
import sqlite3

conn = sqlite3.connect('.skynet_knowledge/operations.db')
cursor = conn.cursor()

# See all successful exploits
cursor.execute("""
    SELECT exploit_name, COUNT(*) as uses,
           SUM(CASE WHEN success=1 THEN 1 ELSE 0 END) as successes
    FROM operations
    GROUP BY exploit_name
    ORDER BY successes DESC
    LIMIT 10
""")

for row in cursor:
    print(f"{row[0]}: {row[2]}/{row[1]} successful")
```

---

## Common Workflows

### Workflow 1: Solo CTF Practice

```python
from skynet.tools.autonomous import autonomous_ctf_solver, analyze_performance

# Solve multiple rooms
rooms = ["10.10.10.5", "10.10.10.6", "10.10.10.7"]

for room in rooms:
    result = autonomous_ctf_solver(room, difficulty="medium", max_time_hours=1)
    print(f"{room}: {'✅' if result['success'] else '❌'}")

# Check improvement over time
perf = analyze_performance()
print(f"Success rate: {perf['overall_metrics']['success_rate']:.1%}")
```

### Workflow 2: Team Knowledge Sharing

```python
from skynet.tools.autonomous import export_knowledge, sync_with_remote

# After successful operations, share with team
export_knowledge("/shared/team_knowledge.json.gz")

# Or use remote sync
sync_with_remote(
    remote_url="http://team-skynet:8080",
    direction="both"
)
```

### Workflow 3: Continuous CVE Monitoring

```bash
# Add to cron for daily updates
0 2 * * * python -c "from skynet.tools.autonomous import auto_update_exploits; auto_update_exploits(['apache','nginx','ssh','mysql'])"
```

---

## Testing Your Setup

```python
# Quick test to verify everything works
from skynet.tools.autonomous import (
    get_decision_engine,
    get_learning_engine,
    get_performance_optimizer
)

# 1. Test decision engine
decision_engine = get_decision_engine()
print(f"✅ Decision engine: {decision_engine.get_mode()}")

# 2. Test learning engine
learning_engine = get_learning_engine()
print(f"✅ Learning engine: Database at {learning_engine.db_path}")

# 3. Test performance optimizer
optimizer = get_performance_optimizer()
print(f"✅ Performance optimizer ready")

# 4. Test LLM
from skynet.tools.autonomous import generate_exploit
exploit = generate_exploit("test", "1.0", vulnerability="test")
print(f"✅ LLM connection: {'Working' if exploit else 'Failed'}")
```

---

## Next Steps

1. **Read Full Documentation**: See `docs/AUTONOMOUS_OPERATIONS.md`
2. **Try First CTF**: Use `autonomous_ctf_solver()` on scanme.nmap.org
3. **Review Learning**: Check `analyze_performance()` after operations
4. **Share Knowledge**: Export and share with your team
5. **Customize**: Adjust operation mode and risk levels

---

## Troubleshooting

**"LLM not responding"**
```bash
# Check Ollama is running
ollama list
# Should show qwen2.5:7b

# If not, pull model
ollama pull qwen2.5:7b
```

**"Database locked"**
- SQLite allows only one writer at a time
- Wait a moment and retry
- Operations are queued automatically

**"No learned recommendations"**
- Need at least 5 successful operations for patterns
- Keep using SKYNET - it learns continuously

---

## Summary

**Before:**
- Manual exploit selection
- No learning from failures
- Static payloads
- Human intervention required

**Now:**
- ✅ Automatic exploit selection based on success patterns
- ✅ Learning from every operation
- ✅ Adaptive payloads with auto-evasion
- ✅ Fully autonomous (configurable)
- ✅ LLM-powered decisions and exploit generation
- ✅ Knowledge sharing between instances
- ✅ Continuous self-improvement

**Just run `autonomous_ctf_solver()` and let SKYNET do the work! 🚀**

---

For detailed information, see:
- `docs/AUTONOMOUS_OPERATIONS.md` - Complete guide
- `docs/agents.md` - Agent architecture
- `docs/examples.md` - More examples
