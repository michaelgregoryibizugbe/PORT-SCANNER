# 🔍 PortScanner

A fast, multi-threaded TCP port scanner written in Python.

## Features
- TCP Connect & SYN scan modes
- Multi-threaded (configurable thread count)
- Service & banner detection
- OS fingerprinting (basic TTL-based)
- Output to JSON / CSV / console table
- CIDR & range notation support
- Top-ports mode (top 100/1000)

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
# Basic scan
python main.py -t 192.168.1.1

# Scan specific ports
python main.py -t 192.168.1.1 -p 22,80,443,8080

# Scan port range with 200 threads
python main.py -t 192.168.1.1 -p 1-1024 --threads 200

# Top 100 ports with banner grabbing
python main.py -t 192.168.1.1 --top-ports 100 --banners

# SYN scan (requires root/admin)
sudo python main.py -t 192.168.1.1 -p 1-65535 --syn

# Scan subnet, output JSON
python main.py -t 192.168.1.0/24 -p 22,80,443 -o results.json

# Verbose with timeout
python main.py -t 10.0.0.1 -p 1-1024 -v --timeout 2
```

## ⚠️ Legal Disclaimer
**Only scan networks and systems you own or have explicit written permission to test.**
Unauthorized scanning may violate laws (CFAA, CMA, etc.).
