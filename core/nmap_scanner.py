"""
Nmap Scanner module for Controlled Reconnaissance Lab.
Executes safe port and service reconnaissance using Nmap binary when present,
with an internal pure-Python socket scanner fallback.
Enforces strict target scope validation and safe subprocess execution.
"""
import subprocess
import time
import socket
import re
from typing import Dict, Any, List
from core.config import NMAP_PATH, DEFAULT_SCAN_TIMEOUT
from core.target_validator import validate_target, validate_ports

SCAN_PROFILES = {
    "quick": {
        "name": "Quick Port Scan",
        "description": "Fast TCP Connect scan of top 20 common ports without host ping probe",
        "nmap_args": ["-sT", "-Pn", "--top-ports", "20", "--open"]
    },
    "service_version": {
        "name": "Service Version Detection",
        "description": "Probes top 50 ports to determine service and version banner details",
        "nmap_args": ["-sT", "-Pn", "-sV", "--top-ports", "50", "--open", "--version-light"]
    },
    "comprehensive": {
        "name": "Standard Well-Known Ports",
        "description": "Connect scan covering ports 1 through 1024",
        "nmap_args": ["-sT", "-Pn", "-p", "1-1024", "--open"]
    },
    "custom": {
        "name": "Custom Port Range",
        "description": "Scans user-specified port list or range",
        "nmap_args": ["-sT", "-Pn", "--open"]
    }
}

COMMON_PORT_NAMES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    9000: "cslistener",
    27017: "mongodb"
}

def parse_nmap_text_output(output: str) -> List[Dict[str, Any]]:
    """Parse human-readable Nmap table output into structured port records."""
    ports = []
    # Pattern: 80/tcp  open  http  Apache httpd 2.4.41
    port_line_regex = re.compile(
        r"^(\d+)/(tcp|udp)\s+(\w+)\s+([\w\-\?]+)(?:\s+(.*))?$",
        re.MULTILINE
    )

    for match in port_line_regex.finditer(output):
        port_num = int(match.group(1))
        protocol = match.group(2)
        state = match.group(3)
        service = match.group(4)
        version = match.group(5).strip() if match.group(5) else ""

        ports.append({
            "port": port_num,
            "protocol": protocol,
            "state": state,
            "service": service,
            "version": version
        })

    return ports

def fallback_socket_scan(target: str, ports: List[int], timeout: float = 0.5) -> List[Dict[str, Any]]:
    """Safe pure-Python socket scanner fallback if Nmap is unavailable."""
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((target, port))
                if result == 0:
                    service_name = COMMON_PORT_NAMES.get(port, "unknown")
                    # Try banner grab
                    banner = ""
                    try:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n" if port in (80, 8080, 8000) else b"\r\n")
                        raw_banner = s.recv(256)
                        banner = raw_banner.decode("utf-8", errors="ignore").splitlines()[0][:50]
                    except Exception:
                        pass

                    open_ports.append({
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": service_name,
                        "version": banner
                    })
        except Exception:
            continue
    return open_ports

def analyze_port_security_implications(ports: List[Dict[str, Any]], target: str) -> List[Dict[str, str]]:
    """Inspect discovered ports and generate actionable security findings."""
    findings = []
    for item in ports:
        port = item["port"]
        service = item.get("service", "").lower()

        if port == 21 or service == "ftp":
            findings.append({
                "title": f"Insecure Cleartext Service: FTP on Port {port}",
                "severity": "High",
                "category": "Cleartext Protocol",
                "description": f"FTP transmits credentials and payload data in unencrypted plaintext on {target}:{port}.",
                "evidence": f"Port {port}/tcp open ftp ({item.get('version', 'N/A')})",
                "remediation": "Migrate to SFTP (SSH File Transfer Protocol) on port 22 or enforce TLS (FTPS)."
            })
        elif port == 23 or service == "telnet":
            findings.append({
                "title": f"Obsolete Insecure Protocol: Telnet on Port {port}",
                "severity": "Critical",
                "category": "Cleartext Protocol",
                "description": f"Telnet sends all terminal session keystrokes including passwords in plaintext on {target}:{port}.",
                "evidence": f"Port {port}/tcp open telnet",
                "remediation": "Immediately replace Telnet with SSH (Secure Shell) on port 22 and disable the Telnet daemon."
            })
        elif port == 80 or (service == "http" and port != 443):
            findings.append({
                "title": f"Unencrypted HTTP Service on Port {port}",
                "severity": "Medium",
                "category": "Web Security",
                "description": f"Web server on {target}:{port} is listening over unencrypted HTTP.",
                "evidence": f"Port {port}/tcp open http ({item.get('version', 'N/A')})",
                "remediation": "Enforce HTTPS (port 443) with valid TLS certificates and redirect HTTP traffic with HSTS."
            })
        elif port in (445, 139):
            findings.append({
                "title": f"Exposed SMB/NetBIOS Service on Port {port}",
                "severity": "Medium",
                "category": "Network Exposure",
                "description": f"File sharing SMB service is exposed on {target}:{port}.",
                "evidence": f"Port {port}/tcp open microsoft-ds/smb",
                "remediation": "Block SMB ports from untrusted networks. Ensure SMBv1 is disabled and enforce SMB signing."
            })
        elif port == 3389:
            findings.append({
                "title": f"Exposed Remote Desktop (RDP) on Port {port}",
                "severity": "Medium",
                "category": "Remote Access Exposure",
                "description": f"RDP service is accessible on {target}:{port}.",
                "evidence": f"Port {port}/tcp open ms-wbt-server (RDP)",
                "remediation": "Enforce Network Level Authentication (NLA), mandate MFA, and restrict access via VPN/bastion."
            })
        elif port in (3306, 5432, 1433, 27017, 6379):
            findings.append({
                "title": f"Database / Cache Service Exposed on Port {port}",
                "severity": "High",
                "category": "Database Security",
                "description": f"Database port {port} ({service}) is exposed. Direct network exposure increases risk of brute-force and remote attacks.",
                "evidence": f"Port {port}/tcp open {service} ({item.get('version', 'N/A')})",
                "remediation": "Bind database service strictly to localhost (127.0.0.1) or restrict via host firewall to application tier only."
            })

    return findings

def execute_scan(target: str, profile: str = "quick", custom_ports: str = "") -> Dict[str, Any]:
    """
    Main entry point for scanning. Validates targets, executes Nmap (or fallback),
    parses results, and generates findings.
    """
    is_valid, sanitized_target, err_msg = validate_target(target)
    if not is_valid:
        return {
            "success": False,
            "error": err_msg,
            "target": target,
            "raw_output": "",
            "ports": [],
            "duration": 0.0
        }

    profile_config = SCAN_PROFILES.get(profile, SCAN_PROFILES["quick"])
    start_time = time.time()

    # Determine ports to scan
    ports_to_scan = []
    if profile == "custom":
        if not custom_ports:
            return {"success": False, "error": "Custom profile requires a valid port specification."}
        p_valid, port_list, p_err = validate_ports(custom_ports)
        if not p_valid:
            return {"success": False, "error": p_err}
        ports_to_scan = port_list
    elif profile == "quick":
        ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
    elif profile == "comprehensive":
        ports_to_scan = list(range(1, 1025))

    # Check if Nmap binary is available
    if NMAP_PATH:
        cmd = [NMAP_PATH]
        # Copy profile args
        args = list(profile_config["nmap_args"])
        if profile == "custom":
            args.extend(["-p", ",".join(str(p) for p in ports_to_scan)])
        
        cmd.extend(args)
        cmd.append(sanitized_target)

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=DEFAULT_SCAN_TIMEOUT,
                shell=False
            )
            raw_stdout = res.stdout
            raw_stderr = res.stderr
            duration = round(time.time() - start_time, 2)

            parsed_ports = parse_nmap_text_output(raw_stdout)
            auto_findings = analyze_port_security_implications(parsed_ports, sanitized_target)

            return {
                "success": True,
                "engine": "nmap",
                "engine_version": "Nmap 7.992",
                "target": sanitized_target,
                "profile": profile,
                "duration": duration,
                "raw_output": raw_stdout or raw_stderr,
                "ports": parsed_ports,
                "open_count": len(parsed_ports),
                "findings": auto_findings
            }

        except subprocess.TimeoutExpired:
            duration = round(time.time() - start_time, 2)
            return {
                "success": False,
                "error": f"Nmap scan timed out after {DEFAULT_SCAN_TIMEOUT} seconds.",
                "duration": duration,
                "target": sanitized_target,
                "ports": []
            }
        except Exception as e:
            # Fall back to socket scanner
            pass

    # Pure Python Socket Scanner Fallback
    parsed_ports = fallback_socket_scan(sanitized_target, ports_to_scan)
    duration = round(time.time() - start_time, 2)
    auto_findings = analyze_port_security_implications(parsed_ports, sanitized_target)

    raw_output = f"Controlled Reconnaissance Lab - Built-in Socket Scanner Engine\nTarget: {sanitized_target}\nScanned {len(ports_to_scan)} ports in {duration}s\n"
    if parsed_ports:
        raw_output += f"PORT\tSTATE\tSERVICE\tVERSION\n"
        for p in parsed_ports:
            raw_output += f"{p['port']}/tcp\t{p['state']}\t{p['service']}\t{p.get('version', '')}\n"
    else:
        raw_output += "No open ports found on scanned targets.\n"

    return {
        "success": True,
        "engine": "socket_fallback",
        "engine_version": "Internal Python 3.13 Socket Scanner",
        "target": sanitized_target,
        "profile": profile,
        "duration": duration,
        "raw_output": raw_output,
        "ports": parsed_ports,
        "open_count": len(parsed_ports),
        "findings": auto_findings
    }
