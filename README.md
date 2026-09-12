# NetRecon: High-Concurrency Network Reconnaissance & CVE Mapper

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform Kali/Linux](https://img.shields.io/badge/tested_on-Kali_Linux-red.svg)](https://www.kali.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight, multi-threaded network scanner and reconnaissance tool built in Python. Designed for red team initial access triage and blue team perimeter auditing, **NetRecon** combines asynchronous TCP connect probing, protocol-specific banner grabbing, SSL/TLS handshake interrogation, and heuristic CVE vulnerability mapping into a single standalone utility with zero external dependencies.

---

## Key Capabilities

* **High-Speed Thread Pool Concurrency:** Utilizes Python's `concurrent.futures.ThreadPoolExecutor` to scan hundreds of ports per second without thread exhaustion.
* **Adaptive Application Probing:** Automatically delivers protocol-tuned payloads:
  * HTTP/HTTPS: Dispatches RFC-compliant `HEAD / HTTP/1.1` requests to capture web headers.
  * SSH / FTP / SMTP / IRC: Transmits CRLF handshakes to trigger interactive daemon banners.
* **SSL/TLS Metadata Extraction:** Leverages Python's native `ssl` library to inspect TLS protocols, cipher suites, and X.509 certificate Common Names (CN) on ports `443` and `8443`.
* **Automated CVE & Vulnerability Mapping:** Ingests banner signatures and cross-references them against a built-in CVE correlation engine (e.g., `CVE-2011-2523`, `CVE-2010-2075`, `CVE-2008-0166`) reporting CVSS base scores directly to terminal output.
* **Dual Reporting Pipelines:** Exports audit artifacts directly to **JSON** (for SIEM/orchestration ingestion) and **CSV** (for compliance reports and spreadsheets).

---

## Architectural Workflow

```
[ Target Input: IP / FQDN ]
            │
    (DNS Resolution)
            ▼
[ Target IPv4 Address ]
            │
    (ThreadPoolExecutor) ──► Concurrent Workers (Default: 50)
            │
 ┌──────────┴────────────────────────┐
 │                                   │
 ▼                                   ▼
[TCP Connect Handshake]     [TLS Wrap: Ports 443/8443]
 │ (If Open)                         │
 ▼                                   ▼
[Protocol-Specific Probe]   [Extract Cert CN, Cipher, TLS Ver]
 │
 ▼
[Capture Raw Daemon Banner]
 │
 ▼
[CVE Correlation Engine]
 │ (Regex Signature Matching)
 ├─► Terminal Formatted Output
 ├─► JSON Output (-oJ report.json)
 └─► CSV Output (-oC report.csv)
```

---

## Installation & Setup

NetRecon relies entirely on the **Python 3 Standard Library**. No `pip install` commands are necessary.

```bash
# Clone the repository
git clone https://github.com/yourusername/netrecon.git
cd netrecon

# Grant execution permissions
chmod +x recon_grabber.py
```

---

## Usage Syntax

```text
usage: recon_grabber.py [-h] [-p PORTS] [-t THREADS] [-w TIMEOUT] [-oJ JSON] [-oC CSV] target

positional arguments:
  target                Target IP address or FQDN

optional arguments:
  -h, --help            show this help message and exit
  -p PORTS, --ports     Port range (e.g. '21-100' or '21,22,80,443,6667')
  -t THREADS, --threads Worker threads (Default: 50)
  -w TIMEOUT, --timeout Socket timeout in seconds (Default: 1.5)
  -oJ JSON, --json      Export scan report to JSON file
  -oC CSV, --csv        Export scan report to CSV file
```

---

## Lab Demonstration (Metasploitable 2)

Running NetRecon against an intentionally vulnerable target machine demonstrates immediate heuristic CVE tagging:

```bash
python3 recon_grabber.py 192.168.56.101 -p 21,22,80,1524,6667 -oJ report.json -oC report.csv
```

### Terminal Output:

```text
================================================================================
[*] Target:       192.168.56.101 (192.168.56.101)
[*] Ports:        5 specified
[*] Threads:      50
[*] Timeout:      1.5s
[*] Start Time:   2026-09-12 15:30:00
================================================================================
PORT     STATE    SERVICE BANNER / TLS                         
--------------------------------------------------------------------------------
21       OPEN     220 (vsFTPd 2.3.4)                           
  └─> [CRITICAL] CVE-2011-2523 (CVSS 9.8): vsftpd 2.3.4 contains an intentional backdoor triggered by a smiley face (':)') in username.
22       OPEN     SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1        
  └─> [HIGH] CVE-2008-0166 (CVSS 7.8): Debian/Ubuntu OpenSSL weak PRNG key generation allows predictable host keys.
  └─> [MEDIUM] CVE-2016-10009 (CVSS 6.8): Untrusted search path vulnerability in ssh-agent allowing arbitrary PKCS#11 load.
80       OPEN     HTTP/1.1 200 OK  Date: Sat, 12 Sep 2026 10:00
  └─> [MEDIUM] CVE-2008-0455 (CVSS 5.0): Legacy Apache 2.2.8 exposes mod_negotiation filename disclosure and mod_proxy vulnerabilities.
1524     OPEN     root@metasploitable:/#                       
  └─> [CRITICAL] GENERIC-ROOT-SHELL (CVSS 10.0): Unauthenticated interactive root bind shell detected.
6667     OPEN     :irc.Metasploitable.LAN NOTICE AUTH :*** Look
  └─> [CRITICAL] CVE-2010-2075 (CVSS 10.0): UnrealIRCd 3.2.8.1 Trojaned source code execution backdoor.
--------------------------------------------------------------------------------
[*] Scan completed in 0.42 seconds | Found 5 open ports
[+] Scan report exported to JSON: report.json
[+] Scan report exported to CSV: report.csv
```

---

## Export Artifacts

### JSON Schema (`report.json`)
```json
{
  "scan_metadata": {
    "target": "192.168.56.101",
    "target_ip": "192.168.56.101",
    "ports_scanned": 5,
    "open_ports_count": 5,
    "duration_seconds": 0.42,
    "scan_time": "2026-09-12T15:30:00.123456"
  },
  "findings": [
    {
      "port": 21,
      "state": "open",
      "banner": "220 (vsFTPd 2.3.4)",
      "ssl_metadata": null,
      "cves": [
        {
          "cve": "CVE-2011-2523",
          "severity": "CRITICAL",
          "cvss": 9.8,
          "description": "vsftpd 2.3.4 contains an intentional backdoor triggered by a smiley face (':)') in username."
        }
      ]
    }
  ]
}
```

### CSV Schema (`report.csv`)
```csv
Port,State,Banner,CVE_ID,Severity,CVSS,Description
21,open,220 (vsFTPd 2.3.4),CVE-2011-2523,CRITICAL,9.8,vsftpd 2.3.4 contains an intentional backdoor...
```

---

## Defensive Countermeasures & Hardening

1. **Banner Masking:** Disable software banner emission across daemons (e.g., set `ServerTokens Prod` in Apache, `banner = no` in vsftpd).
2. **Stateful Firewalls:** Implement egress and ingress filtering using `iptables`/`ufw` to drop unauthorized SYN probes silently instead of returning TCP `RST` packets.
3. **Patch Management:** Remediate legacy software components identified by CVE tags to eliminate known public exploit vectors.

---

## Legal Disclaimer

This utility is developed for legitimate penetration testing, authorized network audits, and educational research in controlled lab environments only. Scanning targets without explicit prior authorization is illegal. The author assumes no liability for misuse.