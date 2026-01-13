# SKYNET + Kali Linux Container - Integration Guide

**Purpose:** Use SKYNET AI agents to automate offensive security operations in your Kali Linux container

**Environment:** Windows 10/11 host + Kali Linux Docker container

---

## 🎯 Architecture Overview

```
┌─────────────────────────────────────┐
│   Windows Host (Development)       │
│                                     │
│   ┌─────────────────────────────┐  │
│   │  SKYNET CLI (.venv313)      │  │
│   │  - T-800 Infiltrator         │  │
│   │  - T-1000 Hunter             │  │
│   │  - Central Core              │  │
│   └─────────┬───────────────────┘  │
│             │ SSH/Docker API        │
│             ▼                       │
│   ┌─────────────────────────────┐  │
│   │  Kali Container             │  │
│   │  - nmap, metasploit          │  │
│   │  - sqlmap, nuclei            │  │
│   │  - aircrack, wifite          │  │
│   │  - All offensive tools       │  │
│   └─────────────────────────────┘  │
└─────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Option 1: SKYNET on Windows, Tools in Kali (Recommended)

**Best for:** CTF challenges, bug bounty, pentesting

```bash
# Windows (Host)
cd C:\path\to\Skynet
.venv313\Scripts\activate
skynet

# In SKYNET CLI, tools will execute in Kali container via SSH/Docker
```

### Option 2: SKYNET Inside Kali Container

**Best for:** Pure Linux operations, maximum tool compatibility

```bash
# Copy project to container
docker cp C:\path\to\Skynet kali_container:/root/skynet

# Enter container
docker exec -it kali_container /bin/bash

# Inside Kali
cd /root/skynet
python3.13 -m venv .venv313
source .venv313/bin/activate
pip install -e .[tracing,viz,voice]
skynet
```

---

## 📦 Setup Instructions

### Step 1: Verify Kali Container

```bash
# Check if Kali container is running
docker ps | grep kali

# If not running, start it
docker start kali_container

# Verify network access
docker exec kali_container ping -c 2 8.8.8.8
```

### Step 2: Install Python 3.13 in Kali (if needed)

```bash
# Enter Kali container
docker exec -it kali_container /bin/bash

# Update package list
apt update

# Install Python 3.13
apt install -y python3.13 python3.13-venv python3.13-dev

# Verify
python3.13 --version
```

### Step 3: Configure SSH Access (for remote execution)

```bash
# Inside Kali container
apt install -y openssh-server

# Enable SSH
systemctl start ssh
systemctl enable ssh

# Set root password (or create user)
passwd root

# Get container IP
ip addr show eth0 | grep "inet "
```

### Step 4: Configure SKYNET for Kali Integration

**Option A: Environment Variables (Recommended)**

```bash
# On Windows host (.env file)
SKYNET_KALI_HOST=172.17.0.2        # Kali container IP
SKYNET_KALI_USER=root               # SSH user
SKYNET_KALI_PASSWORD=your_password  # Or use SSH key
SKYNET_KALI_PORT=22                 # SSH port
SKYNET_EXECUTION_MODE=remote        # Execute tools remotely
```

**Option B: Docker Integration**

```bash
# Configure Docker socket access
DOCKER_CONTAINER=kali_container
SKYNET_EXECUTION_MODE=docker
```

---

## 🔧 Tool Execution Modes

### Mode 1: Direct Docker Execution

Tools run directly inside Kali container:

```python
# SKYNET automatically detects and uses Docker
from skynet.tools.reconnaissance import run_nmap

result = run_nmap(
    target="192.168.1.0/24",
    execution_mode="docker",  # Execute in container
    container="kali_container"
)
```

### Mode 2: SSH Remote Execution

Tools execute via SSH:

```python
from skynet.tools.reconnaissance import run_nmap

result = run_nmap(
    target="192.168.1.0/24",
    execution_mode="ssh",
    ssh_host="172.17.0.2",
    ssh_user="root"
)
```

### Mode 3: Hybrid Mode (Best for CTFs)

SKYNET on Windows, tools in Kali, results aggregated:

```bash
# Windows - Run SKYNET
SKYNET_AGENT_TYPE=t800_infiltrator skynet

# Agent will:
# 1. Plan attack strategy (Windows - AI)
# 2. Execute nmap scan (Kali - native tool)
# 3. Analyze results (Windows - AI)
# 4. Execute exploits (Kali - metasploit)
# 5. Generate report (Windows - AI)
```

---

## 🎮 Usage Examples

### Example 1: CTF Challenge Automation

```bash
# Windows host
.venv313\Scripts\activate

# Set CTF environment
set CTF_NAME=tryhackme
set CTF_CHALLENGE=basic_pentesting
set CTF_IP=10.10.10.5
set SKYNET_KALI_HOST=172.17.0.2

# Launch T-800 Infiltrator
set SKYNET_AGENT_TYPE=t800_infiltrator
skynet

# In SKYNET prompt
> Enumerate the target 10.10.10.5 and find all entry points
```

**What happens:**
1. SKYNET plans reconnaissance strategy
2. Executes `nmap -sV -sC 10.10.10.5` in Kali container
3. Runs `gobuster` for directory enumeration in Kali
4. Analyzes results with AI
5. Suggests next steps

### Example 2: Bug Bounty Subdomain Enumeration

```bash
# Use T-1000 Hunter for advanced reconnaissance
set SKYNET_AGENT_TYPE=t1000_hunter
set SKYNET_KALI_HOST=172.17.0.2
skynet

# In SKYNET
> Find all subdomains for example.com using multiple techniques
```

**Tools executed in Kali:**
- `amass enum -d example.com`
- `subfinder -d example.com`
- `assetfinder example.com`
- Results aggregated and deduplicated

### Example 3: Wireless Network Assessment

```bash
# Use Wireless Infiltrator agent
set SKYNET_AGENT_TYPE=wireless_infiltrator
skynet

# In SKYNET
> Scan for nearby WiFi networks and identify vulnerable WPS routers
```

**Tools in Kali:**
- `airmon-ng start wlan0`
- `airodump-ng wlan0mon`
- `wash -i wlan0mon`
- `reaver -i wlan0mon -b <BSSID>`

### Example 4: Web Application Scanning

```bash
set SKYNET_AGENT_TYPE=t800_infiltrator
skynet

# In SKYNET
> Scan https://target.com for vulnerabilities using nuclei and sqlmap
```

**Execution flow:**
1. **Nuclei scan** (Kali): `nuclei -u https://target.com -t cves/`
2. **SQLMap** (Kali): `sqlmap -u "https://target.com/login.php" --batch`
3. **Analysis** (Windows AI): Correlate findings, prioritize vulnerabilities
4. **Report** (Windows AI): Generate comprehensive pentesting report

---

## 🔌 Network Configuration

### Container Networking Options

#### Option 1: Bridge Network (Default)
```bash
docker network create skynet-bridge
docker network connect skynet-bridge kali_container
```

#### Option 2: Host Network (Maximum Performance)
```bash
docker run --network host kali_container
```

#### Option 3: Custom Network (Recommended for CTFs)
```bash
# Create isolated network for CTF
docker network create --subnet=192.168.100.0/24 ctf-network
docker network connect ctf-network kali_container
docker network connect ctf-network target_container
```

---

## 📁 File Sharing Between Host and Container

### Method 1: Docker Volumes
```bash
# Mount SKYNET project directory
docker run -v C:\path\to\Skynet:/root/skynet kali_container
```

### Method 2: Docker CP
```bash
# Copy files to container
docker cp results.txt kali_container:/root/

# Copy files from container
docker cp kali_container:/root/scan_results.xml ./results/
```

### Method 3: Shared Network Drive
```bash
# Inside Kali
apt install cifs-utils
mount -t cifs //192.168.1.100/share /mnt/share
```

---

## 🛡️ Security Considerations

### 1. Container Isolation
```bash
# Run Kali with security options
docker run --cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN kali_container
```

### 2. SSH Key Authentication (Recommended)
```bash
# Generate SSH key on Windows
ssh-keygen -t ed25519 -f ~/.ssh/skynet_kali

# Copy to container
docker cp ~/.ssh/skynet_kali.pub kali_container:/root/.ssh/authorized_keys

# Configure SKYNET
set SKYNET_KALI_SSH_KEY=C:\Users\admin\.ssh\skynet_kali
```

### 3. Firewall Rules
```bash
# Inside Kali - Limit SSH access
ufw allow from 172.17.0.1 to any port 22
ufw enable
```

---

## 🎯 Agent-Specific Kali Integration

### T-800 Infiltrator + Kali
**Use case:** Full-stack pentesting with autonomous decision-making

**Kali tools utilized:**
- nmap, masscan (reconnaissance)
- metasploit, exploit-db (exploitation)
- john, hashcat (password cracking)
- sqlmap, xsstrike (web attacks)

### T-1000 Hunter + Kali
**Use case:** Bug bounty hunting with advanced enumeration

**Kali tools utilized:**
- amass, subfinder, assetfinder (subdomain enum)
- nuclei, httpx (vulnerability scanning)
- ffuf, gobuster (fuzzing)
- gau, waybackurls (historical data)

### Wireless Infiltrator + Kali
**Use case:** WiFi penetration testing

**Kali tools utilized:**
- aircrack-ng suite
- wifite, bettercap
- kismet, reaver
- hashcat (WPA/WPA2 cracking)

### Forensic Analyzer + Kali
**Use case:** Digital forensics and incident response

**Kali tools utilized:**
- volatility (memory forensics)
- autopsy, sleuthkit (disk forensics)
- wireshark, tcpdump (network forensics)
- binwalk, foremost (file carving)

---

## 🚨 Troubleshooting

### Issue 1: Cannot connect to Kali container
```bash
# Check container status
docker ps -a | grep kali

# Check container network
docker inspect kali_container | grep IPAddress

# Test connectivity
ping <container_ip>
```

### Issue 2: Tools not found in Kali
```bash
# Update Kali package list
docker exec kali_container apt update

# Install missing tools
docker exec kali_container apt install -y nmap metasploit-framework

# Or install all tools
docker exec kali_container apt install -y kali-linux-everything
```

### Issue 3: Permission denied errors
```bash
# Run container with elevated privileges (for wireless tools)
docker run --privileged kali_container

# Or add specific capabilities
docker run --cap-add=NET_RAW --cap-add=NET_ADMIN kali_container
```

### Issue 4: Slow Docker performance on Windows
```bash
# Enable WSL 2 backend
wsl --set-default-version 2

# Allocate more resources in Docker Desktop
# Settings > Resources > CPU: 4, Memory: 8GB
```

---

## 📊 Performance Optimization

### 1. Docker Resource Allocation
```json
// Docker Desktop settings
{
  "cpus": 4,
  "memory": "8192",
  "swap": "2048"
}
```

### 2. Container Caching
```bash
# Cache tool outputs in volume
docker run -v skynet-cache:/root/.skynet_cache kali_container
```

### 3. Persistent Container
```bash
# Keep container running
docker run -d --restart=unless-stopped kali_container sleep infinity

# Reuse instead of recreating
docker exec kali_container <command>
```

---

## 📚 Example Workflows

### Workflow 1: TryHackMe Room Automation
```bash
# 1. Start Kali container
docker start kali_container

# 2. Configure SKYNET
set CTF_NAME=tryhackme
set CTF_IP=10.10.10.5
set SKYNET_KALI_HOST=172.17.0.2
set SKYNET_AGENT_TYPE=t800_infiltrator

# 3. Launch SKYNET
skynet

# 4. Let AI handle the room
> Complete the TryHackMe room at 10.10.10.5
```

### Workflow 2: Bug Bounty Recon Pipeline
```bash
# 1. Configure for bug bounty
set SKYNET_AGENT_TYPE=t1000_hunter
set SKYNET_PARALLEL=5  # Run 5 parallel hunters
set SKYNET_KALI_HOST=172.17.0.2

# 2. Run reconnaissance
skynet

# 3. In SKYNET
> Perform full reconnaissance on *.example.com and identify attack surface
```

### Workflow 3: WiFi Penetration Test
```bash
# 1. Container needs wireless adapter access
docker run --privileged --net=host -v /dev/bus/usb:/dev/bus/usb kali_container

# 2. Configure agent
set SKYNET_AGENT_TYPE=wireless_infiltrator

# 3. Run assessment
skynet
> Scan for WiFi networks and test WPA2 handshakes
```

---

## 🎓 Best Practices

1. **Always use dummy API keys for testing**: `OPENAI_API_KEY=sk-dummy`
2. **Keep Kali container updated**: `docker exec kali_container apt update && apt upgrade -y`
3. **Use SSH keys instead of passwords** for automation
4. **Cache results** to avoid re-running expensive scans
5. **Monitor container resources** with `docker stats kali_container`
6. **Backup important findings** regularly from container to host
7. **Use Docker volumes** for persistent storage
8. **Limit container network access** to authorized targets only

---

## 📖 Additional Resources

- [Kali Linux Official Docs](https://www.kali.org/docs/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [SKYNET Agent Documentation](./docs/agents.md)
- [SKYNET Tools Reference](./docs/tools.md)

---

**Created:** 2025-10-24
**For:** SKYNET Framework + Kali Linux Integration
**Platform:** Windows Host + Docker Kali Container
