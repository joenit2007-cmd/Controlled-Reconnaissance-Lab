"""
Unit tests for Nmap parsing and security finding generation.
"""
import pytest
from core.nmap_scanner import parse_nmap_text_output, analyze_port_security_implications, execute_scan

SAMPLE_NMAP_OUTPUT = """
Starting Nmap 7.992 ( https://nmap.org )
Nmap scan report for 127.0.0.1
Host is up (0.00012s latency).
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 8.9p1
80/tcp   open  http    Apache httpd 2.4.52
3306/tcp open  mysql   MySQL 8.0.32

Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
"""

def test_parse_nmap_text_output():
    ports = parse_nmap_text_output(SAMPLE_NMAP_OUTPUT)
    assert len(ports) == 4

    p21 = next(p for p in ports if p["port"] == 21)
    assert p21["service"] == "ftp"
    assert "vsftpd 3.0.3" in p21["version"]

    p80 = next(p for p in ports if p["port"] == 80)
    assert p80["service"] == "http"

def test_analyze_port_security_implications():
    ports = [
        {"port": 21, "service": "ftp", "version": "vsftpd"},
        {"port": 23, "service": "telnet", "version": ""},
        {"port": 80, "service": "http", "version": "nginx"},
        {"port": 3306, "service": "mysql", "version": "8.0"}
    ]
    findings = analyze_port_security_implications(ports, "127.0.0.1")
    assert len(findings) == 4

    severities = {f["severity"] for f in findings}
    assert "Critical" in severities  # Telnet
    assert "High" in severities      # FTP / MySQL
    assert "Medium" in severities    # HTTP unencrypted

def test_nmap_blocks_public_target():
    res = execute_scan("8.8.8.8", "quick")
    assert res["success"] is False
    assert "Scope Violation" in res["error"]
