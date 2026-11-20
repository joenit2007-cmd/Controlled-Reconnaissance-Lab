"""
Configuration module for Controlled Reconnaissance Lab.
Centralizes paths, security boundaries, database location, and tool detection.
"""
import os
import shutil
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"
UPLOADS_DIR = BASE_DIR / "uploads"
REPORTS_DIR = BASE_DIR / "reports"
SAMPLES_DIR = STATIC_DIR / "samples"
DATABASE_PATH = BASE_DIR / "recon_lab.db"

# Ensure directories exist
for directory in [UPLOADS_DIR, REPORTS_DIR, SAMPLES_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Application Settings
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "controlled-recon-lab-secret-key-cyber-2026")
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

# Security Boundaries: Only allow Localhost and RFC 1918 Private Lab Networks
ALLOWED_PRIVATE_NETWORKS = [
    "127.0.0.0/8",      # Loopback IPv4
    "10.0.0.0/8",       # RFC 1918 Class A
    "172.16.0.0/12",    # RFC 1918 Class B
    "192.168.0.0/16",   # RFC 1918 Class C
    "169.254.0.0/16",   # Link-Local
    "::1/128",          # Loopback IPv6
    "fe80::/10",        # Link-Local IPv6
]

ALLOWED_HOSTNAMES = {
    "localhost",
    "127.0.0.1",
    "::1",
    "ip6-localhost",
    "ip6-loopback"
}

ALLOWED_DOMAINS_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".test",
    ".lab",
    ".home"
)

# Subprocess & Scanning Limits
DEFAULT_SCAN_TIMEOUT = 35  # seconds
MAX_SCAN_TIMEOUT = 60      # seconds
MAX_PORTS_PER_SCAN = 1000

# Security Tools Detection
def find_nmap_path() -> str | None:
    """Locate Nmap executable on Windows or Linux."""
    candidates = [
        shutil.which("nmap"),
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        "/usr/bin/nmap",
        "/usr/local/bin/nmap"
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None

def find_tshark_path() -> str | None:
    """Locate TShark executable for optional advanced pcap queries."""
    candidates = [
        shutil.which("tshark"),
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        "/usr/bin/tshark",
        "/usr/local/bin/tshark"
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None

NMAP_PATH = find_nmap_path()
TSHARK_PATH = find_tshark_path()
BURP_DEFAULT_PROXY = "http://127.0.0.1:8080"
ZAP_DEFAULT_PROXY = "http://127.0.0.1:8090"
