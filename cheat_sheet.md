
```markdown
#  Network Scanner Cheat Sheet

##  Quick Start

```bash
# Basic usage (auto-detects your network)
python3 network_scanner.py

# Scan specific network
python3 network_scanner.py -n 192.168.1.0/24

# Quick scan common ports
python3 network_scanner.py -p 22,80,443,3389

# Save results to file
python3 network_scanner.py -o
```

##  Command Reference

### Core Commands

| Command | Description | Example |
|---------|-------------|---------|
| `-n, --network` | Target network range | `-n 192.168.1.0/24` |
| `-p, --ports` | Ports to scan | `-p 22,80,443` or `-p 1-1000` |
| `-t, --timeout` | Connection timeout (seconds) | `-t 0.5` |
| `-m, --max-threads` | Max concurrent threads | `-m 150` |
| `-o, --output` | Save to JSON file | `-o` |
| `-v, --verbose` | Verbose output | `-v` |

### Port Specifications

```bash
# Single port
-p 80

# Multiple ports
-p 22,80,443,3306

# Port range
-p 1-1024

# Mixed
-p 22,80,443,8000-9000
```

##  Scan Types

### 1. Full Network Scan
```bash
# Scan entire /24 network
python3 network_scanner.py -n 192.168.1.0/24

# With custom ports
python3 network_scanner.py -n 10.0.0.0/24 -p 1-1024
```

### 2. Single Host Scan
```bash
# Scan specific IP
python3 network_scanner.py -n 192.168.1.100/32

# Scan localhost
python3 network_scanner.py -n 127.0.0.1/32
```

### 3. Fast Scan (Speed Optimized)
```bash
# Aggressive settings for speed
python3 network_scanner.py -t 0.3 -m 200 -p 80,443,22,3389
```

### 4. Deep Scan (Detailed)
```bash
# Slower but more thorough
python3 network_scanner.py -t 1.5 -m 50 -p 1-65535 -o
```

### 5. Service Discovery
```bash
# Focus on common services
python3 network_scanner.py -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080
```

##  Output Examples

### Standard Output
```bash
$ python3 network_scanner.py -n 192.168.1.0/24

======================================================================
  PROFESSIONAL NETWORK SCANNER v2.0
======================================================================
  Target Network: 192.168.1.0/24
  Ports to Scan: 13 ports
  Timeout: 0.5s
  Max Threads: 100
======================================================================

[*] Discovering live hosts on 192.168.1.0/24
[*] Your IP: 192.168.1.100
  ✓ 192.168.1.1 - Host is alive
  ✓ 192.168.1.42 - Host is alive

[+] Found 2 live host(s)
----------------------------------------------------------------------

[*] Scanning 192.168.1.1 for open ports...
    [+] 192.168.1.1:22 OPEN - SSH
        → Banner: SSH-2.0-OpenSSH_8.2p1
    [+] 192.168.1.1:80 OPEN - HTTP
        → Banner: HTTP/1.1 200 OK
```

### JSON Output
```bash
$ python3 network_scanner.py -o
# Creates: scan_results_20240115_143045.json
```

## ⚡ Performance Tuning

### For Speed
| Setting | Value | Use Case |
|---------|-------|----------|
| Timeout | 0.2-0.3s | Fast local network |
| Threads | 150-200 | Large networks |
| Ports | <50 | Quick checks |

### For Accuracy
| Setting | Value | Use Case |
|---------|-------|----------|
| Timeout | 1-2s | Slow/remote networks |
| Threads | 30-50 | Stable scanning |
| Ports | Full range | Deep inspection |

##  Common Scenarios

### 1. Find All Web Servers
```bash
python3 network_scanner.py -p 80,443,8080,8443
```

### 2. SSH Server Discovery
```bash
python3 network_scanner.py -p 22
```

### 3. Database Discovery
```bash
python3 network_scanner.py -p 1433,3306,5432,27017
```

### 4. Windows Network Scan
```bash
python3 network_scanner.py -p 135,139,445,3389
```

### 5. IoT Device Discovery
```bash
python3 network_scanner.py -p 23,80,443,554,8080,8443
```

## 🔧 Troubleshooting Commands

### No Hosts Found
```bash
# Increase timeout
python3 network_scanner.py -t 2

# Use /24 range explicitly
python3 network_scanner.py -n 192.168.1.0/24 -t 1
```

### Too Slow
```bash
# Reduce ports and timeout, increase threads
python3 network_scanner.py -p 22,80,443 -t 0.3 -m 200
```

### Permission Issues (Linux)
```bash
# Run with sudo if needed
sudo python3 network_scanner.py
```

### Network Detection Issues
```bash
# Manually specify network
ifconfig  # or ipconfig on Windows
# Then use the detected network
python3 network_scanner.py -n 192.168.1.0/24
```

## 📁 File Management

### Output Files
```bash
# Scan results are saved as:
scan_results_YYYYMMDD_HHMMSS.json

# Example:
scan_results_20240115_143045.json
```

### View Results
```bash
# Pretty print JSON
cat scan_results_*.json | python3 -m json.tool

# Extract open ports
grep -A 5 "open_ports" scan_results_*.json
```

##  Common Port Reference

| Port | Service | Scan Command |
|------|---------|--------------|
| 21 | FTP | `-p 21` |
| 22 | SSH | `-p 22` |
| 23 | Telnet | `-p 23` |
| 25 | SMTP | `-p 25` |
| 53 | DNS | `-p 53` |
| 80 | HTTP | `-p 80` |
| 443 | HTTPS | `-p 443` |
| 445 | SMB | `-p 445` |
| 3306 | MySQL | `-p 3306` |
| 3389 | RDP | `-p 3389` |
| 5432 | PostgreSQL | `-p 5432` |
| 5900 | VNC | `-p 5900` |
| 8080 | Proxy/Alt HTTP | `-p 8080` |

##  Workflow Examples

### 1. Reconnaissance Workflow
```bash
# Step 1: Discover network
python3 network_scanner.py -n 192.168.1.0/24

# Step 2: Deep scan discovered hosts
python3 network_scanner.py -n 192.168.1.1/32 -p 1-10000

# Step 3: Save full results
python3 network_scanner.py -n 192.168.1.0/24 -p 1-1024 -o
```

### 2. Quick Assessment
```bash
# Fast scan of common services
python3 network_scanner.py -t 0.3 -m 150 -p 22,80,443,3389,3306 -o
```

### 3. Security Audit
```bash
# Full port scan with timeout
python3 network_scanner.py -t 1.0 -m 100 -p 1-65535 -o
```

##  Pro Tips

### 1. Save Default Config
Create an alias in your `.bashrc` or `.zshrc`:
```bash
alias netscan='python3 /path/to/network_scanner.py -t 0.5 -m 100'
```

### 2. Quick Network Detection
```bash
# Find your network quickly
ip route | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}'
```

### 3. Parse Results
```bash
# Extract all open ports from JSON
cat scan_results_*.json | grep -o '"port": [0-9]*' | sort -u
```

### 4. Multiple Network Scanning
```bash
# Scan multiple networks
for net in 192.168.1.0/24 10.0.0.0/24; do
    python3 network_scanner.py -n $net -o
done
```

## ⚠️ Safety Checklist

Before scanning:
- [ ] Do I own this network?
- [ ] Do I have written permission?
- [ ] Is this legal in my jurisdiction?
- [ ] Will this violate terms of service?
- [ ] Am I prepared to handle findings responsibly?

##  Quick Help

```bash
# Display help
python3 network_scanner.py -h
python3 network_scanner.py --help

# Check version
python3 --version

# Verify script is executable (Linux/macOS)
ls -l network_scanner.py
chmod +x network_scanner.py  # Make executable
```

---

**Remember**: This tool is for educational and authorized testing only! Always get permission before scanning networks. 🔐
```

This cheat sheet gives you quick access to:
- All command options
- Common use cases
- Performance tuning
- Troubleshooting
- Port references
- Workflow examples
- Safety checklist

Print it out or keep it open while using the scanner! Want me to add any specific sections?
