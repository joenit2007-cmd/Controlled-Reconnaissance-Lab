"""
DNS Reconnaissance module for Controlled Reconnaissance Lab.
Performs passive and active DNS analysis, reverse DNS resolution,
subdomain enumeration simulation, and security checks for DNS misconfigurations.
"""
import socket
import time
from typing import Dict, Any, List
from core.target_validator import validate_target

COMMON_SUBDOMAINS = [
    "admin", "api", "auth", "backup", "corp", "db", "dev", "dns",
    "ftp", "git", "internal", "lab", "mail", "portal", "proxy",
    "router", "secure", "staging", "test", "vpn", "web", "www"
]

# Simulated lab DNS records for educational offline testing
OFFLINE_LAB_DNS_DATABASE = {
    "lab.local": {
        "A": ["192.168.1.10", "192.168.1.11"],
        "AAAA": ["fe80::1ff:fe23:4567"],
        "MX": ["10 mail.lab.local"],
        "NS": ["ns1.lab.local", "ns2.lab.local"],
        "TXT": ["lab-verification=7f93a1c", "v=spf1 ip4:192.168.1.0/24 -all"],
        "SOA": "ns1.lab.local hostmaster.lab.local 2026112001 7200 3600 1209600 3600",
        "subdomains": {
            "admin": "192.168.1.5",
            "api": "192.168.1.20",
            "dev": "192.168.1.50",
            "internal": "192.168.1.100",
            "mail": "192.168.1.25",
            "vpn": "192.168.1.1",
            "www": "192.168.1.10"
        }
    },
    "internal.test": {
        "A": ["10.0.0.10"],
        "AAAA": ["::1"],
        "MX": ["10 mx.internal.test"],
        "NS": ["ns.internal.test"],
        "TXT": ["test-environment=true"],
        "SOA": "ns.internal.test admin.internal.test 2026010101 3600 1800 604800 86400",
        "subdomains": {
            "auth": "10.0.0.2",
            "db": "10.0.0.3",
            "portal": "10.0.0.4",
            "staging": "10.0.0.5"
        }
    },
    "localhost": {
        "A": ["127.0.0.1"],
        "AAAA": ["::1"],
        "PTR": ["localhost"],
        "TXT": ["v=spf1 -all"],
        "subdomains": {
            "app": "127.0.0.1",
            "api": "127.0.0.1",
            "test": "127.0.0.1"
        }
    }
}

def resolve_record_types(domain: str) -> Dict[str, List[str]]:
    """Attempt resolution of common DNS record types."""
    records = {
        "A": [],
        "AAAA": [],
        "PTR": [],
        "MX": [],
        "TXT": [],
        "NS": [],
        "SOA": []
    }

    # Check offline simulated database first
    if domain in OFFLINE_LAB_DNS_DATABASE:
        sim = OFFLINE_LAB_DNS_DATABASE[domain]
        for k in records.keys():
            if k in sim:
                val = sim[k]
                records[k] = val if isinstance(val, list) else [val]
        return records

    # Standard system resolver lookups
    try:
        # A records
        addr_info = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        for item in addr_info:
            ip = item[4][0]
            if ip not in records["A"]:
                records["A"].append(ip)
    except Exception:
        pass

    try:
        # AAAA records
        addr_info_v6 = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
        for item in addr_info_v6:
            ipv6 = item[4][0]
            if ipv6 not in records["AAAA"]:
                records["AAAA"].append(ipv6)
    except Exception:
        pass

    # Reverse DNS (PTR)
    if records["A"]:
        for ip in records["A"]:
            try:
                host, _, _ = socket.gethostbyaddr(ip)
                if host and host not in records["PTR"]:
                    records["PTR"].append(f"{ip} -> {host}")
            except Exception:
                pass

    return records

def enumerate_subdomains(domain: str) -> List[Dict[str, Any]]:
    """Discover active subdomains via simulated dictionary and system resolution."""
    found = []

    # Check simulated lab database
    if domain in OFFLINE_LAB_DNS_DATABASE:
        sim_subs = OFFLINE_LAB_DNS_DATABASE[domain].get("subdomains", {})
        for sub, ip in sim_subs.items():
            found.append({
                "subdomain": f"{sub}.{domain}",
                "ip": ip,
                "status": "Active (Lab Simulation)",
                "record_type": "A"
            })
        return found

    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            found.append({
                "subdomain": fqdn,
                "ip": ip,
                "status": "Resolved",
                "record_type": "A"
            })
        except socket.gaierror:
            continue
        except Exception:
            continue

    return found

def analyze_dns_security(domain: str, records: Dict[str, List[str]], subdomains: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Evaluate DNS hygiene and surface security findings."""
    findings = []

    # Check SPF presence in TXT
    has_spf = any("v=spf1" in txt.lower() for txt in records.get("TXT", []))
    if not has_spf and records.get("A"):
        findings.append({
            "title": f"Missing SPF Record for Domain '{domain}'",
            "severity": "Low",
            "category": "DNS Misconfiguration",
            "description": f"Domain '{domain}' does not publish an SPF (Sender Policy Framework) TXT record, making domain spoofing possible.",
            "evidence": "No TXT record starting with 'v=spf1' discovered.",
            "remediation": "Add an authorized SPF TXT record (e.g. 'v=spf1 mx -all') to specify authorized mail sending servers."
        })

    # Sensitive subdomains exposure
    sensitive_prefixes = {"admin", "internal", "dev", "staging", "backup", "db"}
    for sub in subdomains:
        prefix = sub["subdomain"].split(".")[0].lower()
        if prefix in sensitive_prefixes:
            findings.append({
                "title": f"Sensitive Subdomain Discovered: '{sub['subdomain']}'",
                "severity": "Medium",
                "category": "Information Disclosure",
                "description": f"Subdomain '{sub['subdomain']}' resolves to {sub['ip']}. Sensitive environments exposed to DNS reconnaissance increase attack surface.",
                "evidence": f"{sub['subdomain']} -> {sub['ip']}",
                "remediation": "Restrict sensitive subdomains behind an internal corporate VPN or zero-trust reverse proxy."
            })

    return findings

def execute_dns_recon(domain: str) -> Dict[str, Any]:
    """Execute complete DNS reconnaissance workflow on target."""
    is_valid, sanitized_domain, err_msg = validate_target(domain)
    if not is_valid:
        return {
            "success": False,
            "error": err_msg,
            "domain": domain,
            "records": {},
            "subdomains": [],
            "duration": 0.0
        }

    start_time = time.time()
    records = resolve_record_types(sanitized_domain)
    subdomains = enumerate_subdomains(sanitized_domain)
    duration = round(time.time() - start_time, 2)

    findings = analyze_dns_security(sanitized_domain, records, subdomains)

    raw_output = f"DNS Reconnaissance Report for: {sanitized_domain}\n"
    raw_output += f"Query Duration: {duration}s\n\n"
    raw_output += "[+] DNS Records Discovered:\n"
    for rtype, values in records.items():
        if values:
            raw_output += f"  - {rtype}: {', '.join(values)}\n"

    raw_output += f"\n[+] Discovered Subdomains ({len(subdomains)}):\n"
    for s in subdomains:
        raw_output += f"  - {s['subdomain']} ({s['ip']})\n"

    return {
        "success": True,
        "domain": sanitized_domain,
        "records": records,
        "subdomains": subdomains,
        "subdomain_count": len(subdomains),
        "duration": duration,
        "raw_output": raw_output,
        "findings": findings
    }
