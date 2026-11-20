# Controlled Reconnaissance Lab

A modern, responsive, defensive cybersecurity reconnaissance and security assessment laboratory built with **Python Flask**, **SQLite**, and modern **HTML5/CSS3/JavaScript**.

Designed for cybersecurity students, ethical hackers, and defensive analysts to safely explore, analyze, and document security observations across Linux systems, DNS infrastructure, network ports, packet captures, and web applications in a strictly controlled environment.

---

## Table of Contents
1. [Key Features](#key-features)
2. [Security Architecture & Scope Guardrails](#security-architecture--scope-guardrails)
3. [Technology Stack](#technology-stack)
4. [Project Structure](#project-structure)
5. [Installation & Setup](#installation--setup)
   - [Windows Installation](#windows-installation)
   - [Kali Linux / Debian Installation](#kali-linux--debian-installation)
6. [Launching the Application](#launching-the-application)
7. [Running the Test Suite](#running-the-test-suite)
8. [Module Walkthrough](#module-walkthrough)
   - [1. Overview Dashboard](#1-overview-dashboard)
   - [2. Linux Fundamentals](#2-linux-fundamentals)
   - [3. DNS Reconnaissance](#3-dns-reconnaissance)
   - [4. Nmap Port Scanning](#4-nmap-port-scanning)
   - [5. Network Enumeration](#5-network-enumeration)
   - [6. PCAP Packet Capture Analysis](#6-pcap-packet-capture-analysis)
   - [7. Web Security (Burp Suite & OWASP ZAP)](#7-web-security-burp-suite--owasp-zap)
   - [8. Security Findings Tracker](#8-security-findings-tracker)
   - [9. Scan History](#9-scan-history)
   - [10. Formalized PDF Security Reports](#10-formalized-pdf-security-reports)
9. [License & Ethics](#license--ethics)

---

## Key Features

- **Cybersecurity Dark Operations Theme**: Clean glassmorphism cards, responsive layouts, color-coded severity badges, and terminal emulation windows.
- **Linux Fundamentals Module**:
  - Filesystem Hierarchy Standard (FHS) guide (`/etc`, `/proc`, `/var/log`, `/tmp`).
  - Interactive File Permission & Special Bit Calculator (Calculates octal `0755`, symbolic `-rwxr-xr-x`, `chmod` commands, and evaluates security risks).
  - Safe Linux Command Sandbox with pre-configured reconnaissance commands.
  - Interactive Security Knowledge Assessment Quiz with real-time scoring and progress tracking.
- **Active & Passive DNS Reconnaissance**:
  - Standard record lookup (A, AAAA, MX, NS, TXT, SOA, PTR).
  - Dictionary subdomain discovery simulation for lab environments.
  - DNS hygiene checks (SPF/DMARC verification and sensitive subdomain exposure alerts).
- **Nmap Port Scanning Integration**:
  - Live execution of installed `nmap.exe` or `nmap` with safe TCP Connect scan (`-sT -Pn`).
  - Pre-configured profiles: Quick Top 20, Service Version Detection (`-sV`), Comprehensive Well-Known (1-1024), and Custom Port Ranges.
  - Built-in pure-Python socket scanner fallback if Nmap is absent.
  - Automatic security finding generation for open unencrypted services (FTP 21, Telnet 23, HTTP 80, SMB 445, MySQL 3306).
- **Network Enumeration Module**:
  - Host network interface inspector (IP, MAC address, hostname, interface type).
  - Fast concurrent private subnet sweep across `/24` or `/32` CIDRs.
  - Safe, non-destructive banner grabber on service ports.
- **Pure-Python PCAP Packet Analysis**:
  - Zero external dependency parser supporting `.pcap` and `.pcapng` capture files.
  - Layer-2 to Layer-7 header decoding (Ethernet, IPv4, TCP, UDP, ICMP, ARP, DNS, HTTP).
  - Protocol volume breakdown, top talkers, and conversation streams.
  - Anomaly & Incident Detection Engine: Flags TCP SYN port scans, plaintext HTTP passwords, and HTTP Basic Auth credentials.
  - Pre-loaded lab sample PCAP for instant 1-click testing.
  - Interactive Wireshark display filter cheatsheet with 1-click clipboard copy.
- **Web Security (Burp Suite & OWASP ZAP)**:
  - Live proxy status probes for PortSwigger Burp Suite (port 8080) and OWASP ZAP (port 8090).
  - Step-by-step lab setup instructions for CA certificates, target scope, and request tampering.
  - Automated HTTP response security header auditor (audits HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and server banner disclosures).
- **Vulnerability & Findings Management**:
  - Centralized SQLite findings tracker with full CRUD capabilities.
  - Filterable by Severity (Critical, High, Medium, Low, Informational) and Status (Open, In Progress, Remediated, False Positive).
- **Scan History**:
  - Audit trail of past scans with duration, target, status, and raw terminal log modal viewer.
- **Professional PDF Assessment Report Generator**:
  - Compiles comprehensive security reports using ReportLab with executive summaries, scope declarations, port tables, PCAP analysis highlights, finding cards, and hardening roadmaps.

---

## Security Architecture & Scope Guardrails

The Controlled Reconnaissance Lab implements defensive safeguards:

1. **Strict Target Scope Authorization**:
   - Only `127.0.0.1` (localhost), `::1`, and private **RFC 1918** networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`) or authorized lab suffixes (`.local`, `.test`, `.lab`, `.internal`) are accepted.
   - Any attempt to scan arbitrary public IP addresses (e.g. `8.8.8.8` or cloud hosts) is intercepted and rejected with an explicit security violation error.
2. **Command Injection Prevention**:
   - Target strings are sanitized against command chaining characters (`;`, `&`, `|`, `` ` ``, `$`, `>`, `<`, newlines).
   - All subprocess calls pass arguments as explicit Python lists with `shell=False`.
   - Strict execution timeouts (35s default) prevent long-running hanging processes.
3. **Non-Destructive Testing**:
   - Only non-intrusive TCP connect probes and passive inspection methods are performed.
   - No destructive exploitation payloads or denial-of-service tests are executed.

---

## Technology Stack

- **Backend**: Python 3.10+ / 3.13, Flask 3.1, SQLite3
- **PDF Generation**: ReportLab 5.1
- **Networking & Packets**: Python standard library (`socket`, `struct`, `ipaddress`, `subprocess`, `concurrent.futures`) + `requests`
- **Frontend**: HTML5, CSS3 (Modern Dark Theme), Vanilla JavaScript (ES6+), FontAwesome Icons

---

## Project Structure

```
Controlled_Reconnaissance_Lab/
├── app.py                      # Main Flask application and REST API endpoints
├── requirements.txt            # Python dependencies
├── run.bat                     # Windows one-click startup batch script
├── run.sh                      # Linux / Kali startup shell script
├── README.md                   # Comprehensive documentation
├── core/
│   ├── config.py               # Paths, security scope whitelists, tool paths
│   ├── db.py                   # SQLite schema, queries, migrations, and seeding
│   ├── target_validator.py     # Strict RFC1918/localhost scope enforcement
│   ├── nmap_scanner.py         # Nmap execution wrapper + socket scanner fallback
│   ├── dns_recon.py            # DNS query resolver & subdomain discovery
│   ├── net_enum.py             # Network interfaces, subnet sweep & banner grabber
│   ├── pcap_analyzer.py        # Pure-Python PCAP/PCAPNG decoder & alert engine
│   ├── web_security.py         # Burp/ZAP proxy detector & HTTP header auditor
│   ├── linux_fundamentals.py   # Linux guides, permission calculator & quiz
│   └── pdf_reporter.py         # ReportLab PDF report generation engine
├── templates/
│   └── index.html              # Responsive single-page cybersecurity dashboard
├── static/
│   ├── css/
│   │   └── styles.css          # Dark cybersecurity stylesheet
│   ├── js/
│   │   └── app.js              # Frontend controller and interactive AJAX logic
│   └── samples/
│       └── recon_lab_sample.pcap # Pre-generated sample multi-protocol PCAP
├── uploads/                    # Directory for user-uploaded PCAP files
├── reports/                    # Directory storing generated PDF reports
└── tests/
    ├── test_validator.py       # Scope boundary and injection prevention tests
    ├── test_nmap_scanner.py    # Nmap parsing and finding analysis tests
    ├── test_dns_recon.py       # DNS lookup tests
    ├── test_pcap_analyzer.py   # PCAP decoding and anomaly alert tests
    ├── test_pdf_reporter.py    # ReportLab PDF compilation tests
    └── test_api.py             # Flask REST API integration tests
```

---

## Installation & Setup

### Prerequisites
- Python 3.10 or higher (Python 3.13 tested and verified)
- Nmap (optional but automatically detected if installed)

### Windows Installation
1. Open PowerShell or Command Prompt in the project directory:
   ```powershell
   cd Controlled_Reconnaissance_Lab
   ```
2. Install Python dependencies:
   ```powershell
   py -m pip install -r requirements.txt
   ```
   *(or `python -m pip install -r requirements.txt`)*

### Kali Linux / Debian Installation
1. Open terminal and navigate to the repository:
   ```bash
   cd Controlled_Reconnaissance_Lab
   ```
2. Install dependencies:
   ```bash
   python3 -m pip install -r requirements.txt
   ```
3. Make the Linux launcher executable:
   ```bash
   chmod +x run.sh
   ```

---

## Launching the Application

### Option 1: Direct Python Execution
```bash
# Windows
py app.py
# or
python app.py

# Linux / Kali
python3 app.py
```

### Option 2: Using Provided Startup Scripts
- **On Windows**: Double-click `run.bat` or run `.\run.bat` in PowerShell.
- **On Linux / Kali**: Run `./run.sh`

Once started, open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## Running the Test Suite

The project includes unit and integration tests covering scope boundaries, parsers, security engines, and API endpoints.

Execute tests using `pytest`:
```bash
# Windows
py -m pytest -v

# Linux / Kali
python3 -m pytest -v
```

Expected result:
```
tests/test_api.py::test_index_route PASSED
tests/test_api.py::test_api_overview PASSED
tests/test_api.py::test_api_scan_scope_protection PASSED
tests/test_api.py::test_api_dns_recon PASSED
tests/test_api.py::test_api_pcap_sample PASSED
tests/test_api.py::test_api_linux_calc_perms PASSED
tests/test_api.py::test_api_findings_crud PASSED
tests/test_api.py::test_api_reports_generation PASSED
tests/test_nmap_scanner.py::test_parse_nmap_text_output PASSED
tests/test_nmap_scanner.py::test_analyze_port_security_implications PASSED
tests/test_nmap_scanner.py::test_nmap_blocks_public_target PASSED
tests/test_pcap_analyzer.py::test_pcap_generation_and_parsing PASSED
tests/test_pdf_reporter.py::test_generate_pdf_report PASSED
tests/test_validator.py::test_allowed_localhost_targets PASSED
tests/test_validator.py::test_allowed_private_ips PASSED
tests/test_validator.py::test_blocked_public_ips PASSED
tests/test_validator.py::test_command_injection_rejection PASSED
tests/test_validator.py::test_allowed_lab_domains PASSED
tests/test_validator.py::test_validate_ports PASSED

============================= 19 passed in 1.01s ==============================
```

---

## Module Walkthrough

### 1. Overview Dashboard
- Displays key lab metrics: total scans, active vulnerabilities, and critical/high ratio.
- Shows live integration status indicators for Nmap, Wireshark/PCAP, Burp Suite, and OWASP ZAP.
- Summarizes recent scan history and discovered findings.

### 2. Linux Fundamentals
- **FHS Navigation**: Guide to critical directories (`/etc/passwd`, `/etc/shadow`, `/var/log`, `/proc`).
- **Interactive Permission Calculator**: Select checkboxes for Read/Write/Execute across User, Group, and Others + SUID/SGID/Sticky bits to see real-time calculated octal, symbolic notations, and risk levels.
- **Linux Command Sandbox**: Run simulated reconnaissance commands (`ls -la /etc/passwd`, `id`, `ps aux`, `ufw status`, SUID search) and inspect security annotations.
- **Knowledge Assessment Quiz**: Test your mastery with immediate scoring and explanations.

### 3. DNS Reconnaissance
- Enter an authorized lab domain (e.g. `lab.local`, `internal.test`, `localhost`).
- Resolves A, AAAA, MX, NS, TXT, SOA, and PTR records.
- Discovers active subdomains and checks for missing SPF/DMARC records.

### 4. Nmap Port Scanning
- Run quick, service version, comprehensive, or custom port scans on authorized targets (`127.0.0.1`).
- Auto-detects installed `nmap.exe` or utilizes the pure-Python socket engine fallback.
- Auto-flags common insecure exposures (FTP, Telnet, unencrypted HTTP, exposed databases).

### 5. Network Enumeration
- Inspect local network adapters, MAC addresses, and IP bindings.
- Sweep private lab CIDRs (e.g. `127.0.0.1/32` or `192.168.1.0/24`) to identify responsive hosts.
- Perform safe banner grabbing on open ports to identify running software versions.

### 6. PCAP Packet Capture Analysis
- Drag and drop any `.pcap` or `.pcapng` capture file, or click **"Analyze Pre-loaded Lab Sample PCAP"** for instant inspection.
- Decodes protocol distribution, top talkers, and individual packet headers.
- Built-in Threat Engine alerts on TCP SYN port scans, HTTP Basic Authentication headers, and unencrypted password parameters.
- Review and copy Wireshark display filters from the filter cheatsheet.

### 7. Web Security (Burp Suite & OWASP ZAP)
- Check whether Burp Suite (`127.0.0.1:8080`) or OWASP ZAP (`127.0.0.1:8090`) proxy listeners are running.
- Follow structured step-by-step guides for proxy listeners, CA certificates, target scope, and parameter tampering.
- Audit web response security headers on authorized web services (checks HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and server banner leaks).

### 8. Security Findings Tracker
- View, filter, add, edit, or delete findings.
- Color-coded badges for Critical, High, Medium, Low, and Informational risks.
- Update remediation statuses directly from dropdown controls.

### 9. Scan History
- Full audit log of all reconnaissance activities.
- Click **"Output"** on any record to view the raw terminal or parsed JSON output.

### 10. Formalized PDF Security Reports
- Generate clean, professional cybersecurity assessment reports with a single click.
- Features executive summaries, scope boundaries, port tables, PCAP analysis highlights, risk matrix, finding remediation cards, and defensive hardening roadmaps.
- Download directly to your local workstation.

---

## License & Ethics

This project is built strictly for educational, defensive, and authorized laboratory security testing. It enforces guardrails prohibiting unauthorized scanning of external public systems. Always ensure you have explicit written permission before performing security evaluations.
