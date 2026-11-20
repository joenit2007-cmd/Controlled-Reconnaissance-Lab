"""
Network Enumeration module for Controlled Reconnaissance Lab.
Gathers host interface details, performs safe private subnet live-host sweeps,
and executes non-destructive banner grabbing on discovered services.
"""
import socket
import uuid
import time
import ipaddress
import concurrent.futures
from typing import Dict, Any, List
from core.target_validator import validate_target, is_ip_in_allowed_scope

def get_local_interfaces() -> List[Dict[str, Any]]:
    """Enumerate local system network interfaces safely."""
    interfaces = []
    hostname = socket.gethostname()
    
    # Primary host information
    try:
        primary_ip = socket.gethostbyname(hostname)
    except Exception:
        primary_ip = "127.0.0.1"

    # MAC Address representation
    mac_num = uuid.getnode()
    mac_hex = ':'.join(['{:02x}'.format((mac_num >> elements) & 0xff) for elements in range(0, 8*6, 8)][::-1])

    interfaces.append({
        "interface": "Primary Interface",
        "hostname": hostname,
        "ipv4": primary_ip,
        "mac": mac_hex,
        "scope": "Local Host"
    })

    # Loopback Interface
    interfaces.append({
        "interface": "Loopback (lo0)",
        "hostname": "localhost",
        "ipv4": "127.0.0.1",
        "mac": "00:00:00:00:00:00",
        "scope": "Loopback / Internal"
    })

    # Discover additional addresses bound to host
    try:
        _, _, ip_list = socket.gethostbyname_ex(hostname)
        for ip in ip_list:
            if ip not in [primary_ip, "127.0.0.1"]:
                interfaces.append({
                    "interface": f"Adapter-{len(interfaces)}",
                    "hostname": hostname,
                    "ipv4": ip,
                    "mac": mac_hex,
                    "scope": "Private Subnet" if is_ip_in_allowed_scope(ip) else "External"
                })
    except Exception:
        pass

    return interfaces

def probe_host(ip: str, check_ports: List[int] = [80, 443, 22, 135, 445, 8080], timeout: float = 0.25) -> Dict[str, Any] | None:
    """Check if an individual host in the private range is responding on common ports."""
    start = time.time()
    for port in check_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    latency_ms = round((time.time() - start) * 1000, 1)
                    return {
                        "ip": ip,
                        "status": "Online",
                        "active_port": port,
                        "latency_ms": latency_ms
                    }
        except Exception:
            continue
    return None

def sweep_subnet(cidr: str, max_hosts: int = 64) -> Dict[str, Any]:
    """Perform a fast concurrent sweep across a private IPv4 lab subnet."""
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as e:
        return {"success": False, "error": f"Invalid CIDR notation: {str(e)}", "hosts": []}

    # Verify that the network is in authorized scope
    if not is_ip_in_allowed_scope(str(net.network_address)):
        return {
            "success": False,
            "error": "Scope Violation: Subnet must belong to private RFC 1918 space (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or 127.0.0.0/8).",
            "hosts": []
        }

    # Limit max hosts to prevent resource exhaustion
    host_ips = [str(ip) for ip in list(net.hosts())[:max_hosts]]
    start_time = time.time()
    discovered = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(probe_host, ip): ip for ip in host_ips}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                discovered.append(res)

    duration = round(time.time() - start_time, 2)
    discovered.sort(key=lambda x: [int(p) for p in x["ip"].split(".")])

    raw_output = f"Network Sweep on {cidr}\nHosts Scanned: {len(host_ips)}\nDuration: {duration}s\nLive Hosts Discovered: {len(discovered)}\n"
    for h in discovered:
        raw_output += f"  - {h['ip']} (Responding on port {h['active_port']}, {h['latency_ms']}ms)\n"

    return {
        "success": True,
        "subnet": str(net),
        "total_probed": len(host_ips),
        "live_count": len(discovered),
        "duration": duration,
        "hosts": discovered,
        "raw_output": raw_output
    }

def grab_service_banner(target: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """Connect to a port and retrieve raw service greeting banner."""
    is_valid, sanitized_target, err_msg = validate_target(target)
    if not is_valid:
        return {"success": False, "error": err_msg}

    if port < 1 or port > 65535:
        return {"success": False, "error": "Port out of range (1-65535)."}

    start_time = time.time()
    banner_text = ""
    status = "Closed / Unresponsive"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((sanitized_target, port))
            status = "Open"
            
            # Send HTTP probe for web ports, newline for others
            if port in (80, 8080, 8000, 8888, 5000):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + sanitized_target.encode() + b"\r\n\r\n")
            else:
                s.sendall(b"\r\n")

            data = s.recv(1024)
            banner_text = data.decode("utf-8", errors="replace").strip()
    except socket.timeout:
        status = "Timeout"
    except ConnectionRefusedError:
        status = "Connection Refused"
    except Exception as e:
        status = f"Error: {str(e)}"

    duration = round(time.time() - start_time, 3)

    return {
        "success": True,
        "target": sanitized_target,
        "port": port,
        "status": status,
        "banner": banner_text or "(No banner transmitted by service)",
        "duration": duration
    }
