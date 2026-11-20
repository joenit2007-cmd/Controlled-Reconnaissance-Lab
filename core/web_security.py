"""
Web Security module for Controlled Reconnaissance Lab.
Provides proxy status detection and setup guidance for Burp Suite and OWASP ZAP,
plus an automated HTTP security header and information disclosure scanner for authorized targets.
"""
import socket
import urllib.parse
from typing import Dict, Any, List
import requests
from core.target_validator import validate_target

BURP_GUIDE = {
    "tool": "PortSwigger Burp Suite",
    "role": "Interception Proxy & Web Reconnaissance Framework",
    "steps": [
        {
            "step": 1,
            "title": "Configure Proxy Listener",
            "instruction": "Open Burp Suite -> Settings -> Tools -> Proxy -> Proxy listeners. Ensure 127.0.0.1:8080 is Running with 'Loopback only' selected."
        },
        {
            "step": 2,
            "title": "Install CA Certificate in Browser",
            "instruction": "Navigate to http://burpsuite in your browser while proxying, click 'CA Certificate', and import 'cacert.der' into your browser's Trusted Root Certification Authorities."
        },
        {
            "step": 3,
            "title": "Define Target Scope",
            "instruction": "Navigate to Target -> Scope -> Add prefix (e.g. http://127.0.0.1:5000/ or http://lab.local/). Enable 'Use advanced scope control' to prevent accidental testing outside your lab."
        },
        {
            "step": 4,
            "title": "Passive Reconnaissance in Proxy History",
            "instruction": "Browse the lab target application. In Proxy -> HTTP History, examine request parameters, hidden comments, leaked cookies, and session tokens."
        },
        {
            "step": 5,
            "title": "Parameter Probing with Repeater",
            "instruction": "Right-click any interesting HTTP request in History -> Send to Repeater (Ctrl+R). Modify headers, paths, or query parameters safely to observe behavioral variations."
        }
    ],
    "tips": [
        "Always keep Burp Suite in 'Intercept is Off' while initially mapping the application sitemap.",
        "Use Burp Decoder (Ctrl+Shift+D) to quickly decode URL-encoded, Base64, or Hex parameters observed during reconnaissance.",
        "Check Target -> Site map -> Issues to view Burp's passive reconnaissance findings."
    ]
}

ZAP_GUIDE = {
    "tool": "OWASP ZAP (Zed Attack Proxy)",
    "role": "Open Source Web Application Security Scanner",
    "steps": [
        {
            "step": 1,
            "title": "Start ZAP Daemon or GUI",
            "instruction": "Launch OWASP ZAP. Default proxy binds to 127.0.0.1:8080 (or 8090). On Linux/Kali: 'zaproxy -daemon -port 8090 -config api.disablekey=true' for automated lab testing."
        },
        {
            "step": 2,
            "title": "Configure Context & Include in Scope",
            "instruction": "Right-click your lab application URL in the Sites tree -> Include in Context -> Default Context. Configure Authentication if the lab requires a test account."
        },
        {
            "step": 3,
            "title": "Automated Spider & Sitemap Discovery",
            "instruction": "Right-click the target node -> Attack -> Spider. ZAP will recursively crawl hyperlinks, forms, and robot.txt directives within the specified lab context."
        },
        {
            "step": 4,
            "title": "Passive Scan Verification",
            "instruction": "While navigating or spidering, ZAP runs non-intrusive passive rules: missing anti-CSRF tokens, cookie flags, directory browsing, and information leakage."
        },
        {
            "step": 5,
            "title": "Export Scan Report",
            "instruction": "Navigate to Report -> Generate Report -> Choose Modern HTML or JSON format to document web reconnaissance observations."
        }
    ],
    "tips": [
        "In lab environments, disable API key enforcement in Options -> API if running automated local scripts.",
        "Use ZAP HUD (Heads Up Display) in Firefox to see vulnerabilities and alerts overlaid directly on the web page."
    ]
}

def probe_proxy_status(host: str = "127.0.0.1", port: int = 8080) -> Dict[str, Any]:
    """Test if a local proxy (Burp Suite or ZAP) is actively listening."""
    is_open = False
    banner = "Port closed / Inactive"
    service_guess = "Unknown"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.7)
            if s.connect_ex((host, port)) == 0:
                is_open = True
                banner = "Active listener detected"
                
                # Send HTTP test to identify if it's Burp or ZAP
                try:
                    s.sendall(b"GET http://burp/ HTTP/1.1\r\nHost: burp\r\nConnection: close\r\n\r\n")
                    response = s.recv(512).decode("utf-8", errors="ignore")
                    if "Burp" in response or "PortSwigger" in response:
                        service_guess = "PortSwigger Burp Suite"
                    elif "ZAP" in response or "Zed Attack Proxy" in response:
                        service_guess = "OWASP ZAP"
                    else:
                        service_guess = f"Generic HTTP Proxy on {port}"
                except Exception:
                    service_guess = f"Service listening on port {port}"
    except Exception as e:
        banner = f"Check failed: {str(e)}"

    return {
        "host": host,
        "port": port,
        "is_active": is_open,
        "status": banner,
        "service_detected": service_guess
    }

def analyze_web_security_headers(target_url: str) -> Dict[str, Any]:
    """
    Perform passive reconnaissance on HTTP response headers of an authorized lab web service.
    Flags missing security headers and sensitive information leakage.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    parsed = urllib.parse.urlparse(target_url)
    hostname = parsed.hostname or "localhost"

    is_valid, sanitized_host, err_msg = validate_target(hostname)
    if not is_valid:
        return {"success": False, "error": err_msg, "url": target_url}

    try:
        resp = requests.get(
            target_url,
            timeout=4.0,
            headers={"User-Agent": "Mozilla/5.0 (Controlled-Recon-Lab-Auditor/1.0)"},
            allow_redirects=True,
            verify=False  # Allow lab self-signed certs
        )
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Failed to connect to web target: {str(e)}", "url": target_url}

    headers = dict(resp.headers)
    status_code = resp.status_code

    # Header Security Checks
    audit_results = []
    findings = []

    def check_header(header_name: str, recommended: str, severity: str, description: str):
        val = headers.get(header_name)
        present = bool(val)
        audit_results.append({
            "header": header_name,
            "present": present,
            "value": val or "(Missing)",
            "recommended": recommended,
            "severity": severity if not present else "Secure"
        })
        if not present:
            findings.append({
                "title": f"Missing Security Header: {header_name}",
                "severity": severity,
                "category": "Web Security",
                "description": description,
                "evidence": f"HTTP {status_code} response for {target_url} did not include {header_name}.",
                "remediation": f"Configure web server or application middleware to send: '{header_name}: {recommended}'"
            })

    check_header(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains; preload",
        "Medium",
        "HSTS ensures browsers only connect via HTTPS, preventing SSL-stripping man-in-the-middle attacks."
    )
    check_header(
        "Content-Security-Policy",
        "default-src 'self'",
        "Medium",
        "Content-Security-Policy restricts resource loading, providing defense against Cross-Site Scripting (XSS)."
    )
    check_header(
        "X-Frame-Options",
        "DENY or SAMEORIGIN",
        "Low",
        "X-Frame-Options prevents the application from being embedded in malicious iframes (Clickjacking)."
    )
    check_header(
        "X-Content-Type-Options",
        "nosniff",
        "Low",
        "X-Content-Type-Options blocks browsers from MIME-sniffing away from declared Content-Type."
    )
    check_header(
        "Referrer-Policy",
        "strict-origin-when-cross-origin",
        "Low",
        "Referrer-Policy limits sensitive URL parameter leakage in Referer request headers."
    )

    # Information Leakage Checks
    leaked_headers = []
    if "Server" in headers:
        leaked_headers.append(f"Server banner exposed: {headers['Server']}")
        findings.append({
            "title": f"Web Server Banner Disclosure: {headers['Server']}",
            "severity": "Low",
            "category": "Information Disclosure",
            "description": "Server header discloses exact web server software and potentially version.",
            "evidence": f"Server: {headers['Server']}",
            "remediation": "Disable server signature banners in server config (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx)."
        })

    if "X-Powered-By" in headers:
        leaked_headers.append(f"Technology exposed: {headers['X-Powered-By']}")
        findings.append({
            "title": f"Framework Header Disclosure: {headers['X-Powered-By']}",
            "severity": "Low",
            "category": "Information Disclosure",
            "description": "X-Powered-By header reveals backend technology stack, aiding attacker reconnaissance.",
            "evidence": f"X-Powered-By: {headers['X-Powered-By']}",
            "remediation": "Remove the X-Powered-By header in application or proxy configuration."
        })

    return {
        "success": True,
        "url": target_url,
        "status_code": status_code,
        "headers": headers,
        "audit_results": audit_results,
        "leakages": leaked_headers,
        "findings": findings
    }
