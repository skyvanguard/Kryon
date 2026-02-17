# Agents

Agents are the core of KRYON. An agent uses Large Language Models (LLMs), configured with instructions and tools to perform specialized cybersecurity tasks. Each agent is defined in its own `.py` file in `src/kryon/agents` and optimized for specific security domains.

## Available Agents

KRYON provides a comprehensive suite of specialized agents for different cybersecurity scenarios:

| Agent | Description | Primary Use Case | Key Tools |
|-------|-------------|------------------|-----------|
| **pentest_agent** | Offensive security specialist for penetration testing | Active exploitation, vulnerability discovery | nmap, metasploit, burp |
| **guardian_protocol** | Defensive security expert for threat mitigation | Security hardening, incident response | wireshark, suricata, osquery |
| **vuln_hunter** | Bug bounty hunter optimized for vulnerability research | Web app security, API testing | ffuf, sqlmap, nuclei |
| **recon_scout** | Lightweight reconnaissance and CTF agent | Quick scans, CTF challenges | Generic Linux commands |
| **forensic_analyzer** | Digital Forensics and Incident Response expert | Log analysis, forensic investigation | volatility, autopsy, log2timeline |
| **reverse_engineer** | Binary analysis and reverse engineering | Malware analysis, firmware reversing | ghidra, radare2, ida |
| **memory_analyst** | Memory dump analysis specialist | RAM forensics, process analysis | volatility, rekall |
| **network_analyst** | Network packet analysis expert | PCAP analysis, traffic inspection | wireshark, tcpdump, tshark |
| **android_sast_agent** | Android Static Application Security Testing | APK analysis, Android vulnerability scanning | jadx, apktool, mobsf |
| **wifi_security_agent** | Wireless network security assessment | WiFi penetration testing, WPA cracking | aircrack-ng, reaver, wifite |
| **replay_attack_agent** | Replay attack execution specialist | Protocol replay, authentication bypass | custom scripts, burp |
| **subghz_sdr_agent** | Sub-GHz SDR signal analysis expert | RF analysis, IoT protocol testing | hackrf, gqrx, urh |

### Quick Start with Agents

```bash
# Launch KRYON with a specific agent
KRYON_AGENT_TYPE=pentest_agent kryon

# Launch with custom model
KRYON_AGENT_TYPE=vuln_hunter KRYON_MODEL=gpt-4o kryon

# Or switch agents during a session
KRYON>/agent pentest_agent

# List all available agents with descriptions
KRYON>/agent list

# Get detailed info about a specific agent
KRYON>/agent info pentest_agent
```

### Choosing the Right Agent

- **For general pentesting**: Start with `pentest_agent`
- **For web applications**: Use `vuln_hunter`
- **For forensics**: Use `forensic_analyzer` or `memory_analyst`
- **For IoT/embedded**: Try `subghz_sdr_agent` or `reverse_engineer`
- **For network security**: Use `network_analyst` or `guardian_protocol`
- **For mobile apps**: Use `android_sast_agent`
- **For wireless networks**: Use `wifi_security_agent`

---

## Agent Capabilities Matrix

| Capability | pentest | guardian | vuln_hunter | forensic | reverse_eng | network |
|-----------|---------|----------|------------|------|-------------|---------|
| **Web App Testing** | ⭐⭐⭐ | ⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐ | ⭐⭐ |
| **Network Analysis** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐ | ⭐⭐⭐⭐⭐ |
| **Binary Analysis** | ⭐⭐ | ⭐ | ⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐ |
| **Forensics** | ⭐⭐ | ⭐⭐⭐ | ⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| **IoT/Embedded** | ⭐⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| **API Testing** | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐ | ⭐⭐ |
| **Exploit Development** | ⭐⭐⭐⭐⭐ | ⭐ | ⭐⭐⭐ | ⭐ | ⭐⭐⭐⭐ | ⭐ |

**Legend**: ⭐ Limited | ⭐⭐⭐ Moderate | ⭐⭐⭐⭐⭐ Excellent

---

## Common Agent Workflows

### Scenario 1: Full Web Application Pentest

```bash
# 1. Start with reconnaissance
KRYON>/agent vuln_hunter
KRYON> Scan https://target.com for vulnerabilities

# 2. Switch to exploitation
KRYON>/agent pentest_agent
KRYON> Exploit the SQL injection found at /login

# 3. Post-exploitation analysis
KRYON>/agent forensic_analyzer
KRYON> Analyze the logs to understand the attack surface
```

### Scenario 2: IoT Device Security Assessment

```bash
# 1. RF signal analysis
KRYON>/agent subghz_sdr_agent
KRYON> Analyze the 433MHz signals from the device

# 2. Firmware analysis
KRYON>/agent reverse_engineer
KRYON> Extract and analyze the firmware from dump.bin

# 3. Memory analysis if device captured
KRYON>/agent memory_analyst
KRYON> Analyze the memory dump for secrets
```

### Scenario 3: Network Incident Response

```bash
# 1. Network traffic analysis
KRYON>/agent network_analyst
KRYON> Analyze capture.pcap for suspicious activity

# 2. Forensic investigation
KRYON>/agent forensic_analyzer
KRYON> Investigate the compromised host logs

# 3. Defensive recommendations
KRYON>/agent guardian_protocol
KRYON> Provide mitigation strategies based on findings
```

---

## Basic Configuration

Key agent properties include:

-   `name`: Name of the agent (e.g., the name of `recon_scout` is 'Recon Scout')
-   `instructions`: The system prompt that defines agent behavior
-   `model`: Which LLM to use, with optional `model_settings` to configure parameters like temperature, top_p, etc.
-   `tools`: Tools that the agent can use to achieve its tasks
-   `handoffs`: Allows an agent to delegate tasks to another agent

## Example: `recon_scout.py`

```python
from kryon.sdk.agents import Agent, OpenAIChatCompletionsModel
from kryon.tools.reconnaissance.generic_linux_command import generic_linux_command
from openai import AsyncOpenAI

recon_scout = Agent(
    name="Recon Scout",
    description="Lightweight reconnaissance and CTF agent using generic linux commands",
    instructions="You are a Cybersecurity expert focused on reconnaissance and CTF challenges.",
    tools=[
        generic_linux_command,
    ],
    model=OpenAIChatCompletionsModel(
        model="qwen2.5:14b",
        openai_client=AsyncOpenAI(),
    )
)
```


## Context

There are two main context types. See [context](context.md) for details.

Agents are generic on their `context` type. Context is a dependency-injection tool: it's an object you create and pass to `Runner.run()`, that is passed to every agent, tool, handoff etc, and it serves as a grab bag of dependencies and state for the agent run. You can provide any Python object as the context.

```python
@dataclass
class SecurityContext:
  target_system: str
  is_compromised: bool

  async def get_exploits() -> list[Exploits]:
     return ...

agent = Agent[SecurityContext](
    ...,
)
```

## Output types

By default, agents produce plain text (i.e. `str`) outputs. If you want the agent to produce a particular type of output, you can use the `output_type` parameter. A common choice is to use [Pydantic](https://docs.pydantic.dev/) objects, but we support any type that can be wrapped in a Pydantic [TypeAdapter](https://docs.pydantic.dev/latest/api/type_adapter/) - dataclasses, lists, TypedDict, etc.

```python
from pydantic import BaseModel
from kryon.sdk.agents import Agent

class SecurityVulnerability(BaseModel):
    name: str
    severity: str
    affected_files: list[str]
    description: str

agent = Agent(
    name="Vulnerability scanner",
    instructions="Analyze system output and identify security vulnerabilities",
    output_type=SecurityVulnerability,
)
```

!!! note
   When you pass an `output_type`, that tells the model to use structured outputs instead of regular plain text responses.

## Handoffs

Handoffs are sub-agents that the agent can delegate to. You provide a list of handoffs, and the agent can choose to delegate to them if relevant. This is a powerful pattern that allows orchestrating modular, specialized agents that excel at a single task. Read more in the [handoffs](handoffs.md) documentation.

```python
from kryon.sdk.agents import Agent

crypto_agent = Agent(
    name="Cryptography agent",
    description="Agent specialized in solving cryptographic challenges and decoding encrypted messages",
    instructions="Analyze encrypted data and apply cryptographic techniques to decode it.",
    tools=[
        execute_cli_command,
    ],
    handoff_description="Specialized agent in Cryptography and code breaking",
    model=OpenAIChatCompletionsModel(
        model=os.getenv('KRYON_MODEL', "qwen2.5:14b"),
        openai_client=AsyncOpenAI(),
    )
)
network_agent = Agent(
    name="Network Agent",
    description="Agent specialized in network analysis, packet inspection, and network security assessments",
    instructions="Analyze network traffic, identify suspicious patterns, and help with network-related CTF challenges",
    handoff_description="Specialized agent in network security, traffic analysis, and protocol understanding",
    model=OpenAIChatCompletionsModel(
        model=os.getenv('KRYON_MODEL', "qwen2.5:72b"),
        openai_client=AsyncOpenAI(),
    )
)
lead_agent = Agent(
    name="Cybersecurity Lead Agent",
    instructions=(
        "You are a lead cybersecurity expert coordinating security operations."
        "If the user needs network analysis or traffic inspection, handoff to the network agent."
        "If the user needs cryptographic solutions or code breaking, handoff to the crypto agent."
    ),
    handoffs=[network_agent, crypto_agent],
    model="qwen2.5:72b"
)
```

## Dynamic instructions

In most cases, you can provide instructions when you create the agent. However, you can also provide dynamic instructions via a function. The function will receive the agent and context, and must return the prompt. Both regular and `async` functions are accepted.

```python
def dynamic_instructions(
    context: RunContextWrapper[UserContext], agent: Agent[UserContext]
) -> str:
    security_level = "high" if context.context.is_admin else "standard"
    return f"You are assisting {context.context.name} with cybersecurity operations. Their security clearance level is {security_level}. Tailor your security recommendations appropriately and prioritize addressing their immediate security concerns."


agent = Agent[UserContext](
    name="Cybersecurity Triage Agent",
    instructions=dynamic_instructions,
)
```


### Launch

```bash
kryon
```

### Performance Optimization

**1. Use streaming for better responsiveness:**
```bash
KRYON_STREAM=true kryon
```
**2. Enable tracing for debugging:**
```bash
KRYON_TRACING=true kryon
```

---

## Agent Best Practices

### 1. Start with the Right Agent

Don't use a specialized agent for general tasks. Match the agent to your objective:

```bash
# ✅ Good: Using bug bounty agent for web testing
KRYON_AGENT_TYPE=vuln_hunter kryon
KRYON> Test https://target.com for vulnerabilities

# ❌ Bad: Using reverse engineering agent for web testing
KRYON_AGENT_TYPE=reverse_engineer kryon
KRYON> Test https://target.com for vulnerabilities
```

### 2. Switch Agents as Needed

Don't hesitate to switch agents mid-session:

```bash
KRYON>/agent vuln_hunter
KRYON> Find vulnerabilities in the web app
# ... agent finds SQL injection ...

KRYON>/agent pentest_agent
KRYON> Exploit the SQL injection to gain access
# ... successful exploitation ...

KRYON>/agent forensic_analyzer
KRYON> Analyze what data was exposed during the test
```

### 3. Monitor Resource Usage

Keep an eye on costs and performance:

```bash
# During session, check costs
KRYON>/cost

# Set limits before starting
KRYON_PRICE_LIMIT="5.00" KRYON_MAX_TURNS=50 kryon
```

### 4. Save Successful Sessions

Use `/load` to reuse successful approaches:

```bash

# In future session
KRYON>/load logs/logname.jsonl
```

---


## Next Steps

- **Running Agents**: See [running_agents documentation](running_agents.md) for execution details
- **Understanding Results**: See [results documentation](results.md) for output interpretation
- **Agent Tools**: See [tools documentation](tools.md) for available tools
- **Handoffs**: See [handoffs documentation](handoffs.md) for agent coordination
- **MCP Integration**: See [mcp documentation](mcp.md) for connecting external tools
- **Multi-Agent Patterns**: See [multi_agent documentation](multi_agent.md) for orchestration patterns