"""
Target Validator module for Controlled Reconnaissance Lab.
Enforces strict scope boundaries: only localhost and RFC 1918 private lab addresses.
Prevents command injection and blocks scanning of arbitrary public internet targets.
"""
import re
import socket
import ipaddress
from typing import Tuple, List
from core.config import (
    ALLOWED_HOSTNAMES,
    ALLOWED_DOMAINS_SUFFIXES,
    ALLOWED_PRIVATE_NETWORKS,
    MAX_PORTS_PER_SCAN
)

HOSTNAME_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*$"
)

# Parsed IP networks for containment check
_PARSED_NETWORKS = [ipaddress.ip_network(net) for net in ALLOWED_PRIVATE_NETWORKS]

def is_ip_in_allowed_scope(ip_str: str) -> bool:
    """Check if an IP string belongs to private RFC1918, loopback, or link-local."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return any(ip in net for net in _PARSED_NETWORKS) or ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

def validate_target(target: str, allow_dns_resolution: bool = True) -> Tuple[bool, str, str]:
    """
    Validate target input for security compliance.
    Returns: (is_valid: bool, sanitized_target: str, error_message: str)
    """
    if not target or not isinstance(target, str):
        return False, "", "Target cannot be empty."

    sanitized = target.strip().lower()

    # Block common command injection characters
    illegal_chars = set(";&|`$><()[]{}\\'\" \t\r\n")
    if any(c in illegal_chars for c in sanitized):
        return False, "", "Invalid target: Disallowed characters detected."

    # 1. Check if direct IP address
    try:
        ip_obj = ipaddress.ip_address(sanitized)
        if is_ip_in_allowed_scope(sanitized):
            return True, str(ip_obj), ""
        else:
            return (
                False,
                "",
                f"Scope Violation: IP address '{sanitized}' is outside authorized lab scope. "
                "Only localhost (127.0.0.1) and private RFC 1918 networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are permitted."
            )
    except ValueError:
        pass  # Not a raw IP, proceed to hostname check

    # 2. Check if valid hostname format
    if not HOSTNAME_REGEX.match(sanitized):
        return False, "", f"Invalid hostname format: '{sanitized}'"

    # Whitelisted local hostnames
    if sanitized in ALLOWED_HOSTNAMES:
        return True, sanitized, ""

    # Check allowed private domain suffixes
    has_allowed_suffix = any(sanitized.endswith(suffix) for suffix in ALLOWED_DOMAINS_SUFFIXES)

    # 3. Resolve hostname to verify the underlying IP is in private scope
    if allow_dns_resolution:
        try:
            # Safe local resolution with 2-second timeout
            addrinfo = socket.getaddrinfo(sanitized, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            resolved_ips = [info[4][0] for info in addrinfo if info[4]]
            
            if not resolved_ips:
                if has_allowed_suffix:
                    return True, sanitized, ""  # Unresolved lab domain allowed for lab test
                return False, "", f"Unable to resolve hostname '{sanitized}'."

            # Verify every resolved IP is in private/loopback scope
            for resolved_ip in resolved_ips:
                if not is_ip_in_allowed_scope(resolved_ip):
                    return (
                        False,
                        "",
                        f"Scope Violation: Hostname '{sanitized}' resolves to public IP '{resolved_ip}'. "
                        "Scanning public infrastructure is strictly prohibited."
                    )
            return True, sanitized, ""
        except socket.gaierror:
            if has_allowed_suffix:
                return True, sanitized, ""
            return (
                False,
                "",
                f"Hostname '{sanitized}' could not be resolved and is not an authorized lab domain suffix ({', '.join(ALLOWED_DOMAINS_SUFFIXES)})."
            )
        except Exception as e:
            return False, "", f"Resolution error: {str(e)}"

    if has_allowed_suffix:
        return True, sanitized, ""

    return (
        False,
        "",
        f"Domain '{sanitized}' is not permitted. Only authorized local lab domains ({', '.join(ALLOWED_DOMAINS_SUFFIXES)}) or localhost are permitted."
    )

def validate_ports(port_input: str) -> Tuple[bool, List[int], str]:
    """
    Validate and parse port specifications (e.g. '80', '80,443,8080', '1-100').
    Returns: (is_valid: bool, port_list: List[int], error_message: str)
    """
    if not port_input or not isinstance(port_input, str):
        return True, [], ""  # Empty means default profile ports

    sanitized = port_input.strip()
    if not re.match(r"^[0-9,\-\s]+$", sanitized):
        return False, [], "Invalid port specification. Only digits, commas, and hyphens are allowed."

    ports = set()
    parts = sanitized.split(",")

    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            sub = part.split("-")
            if len(sub) != 2:
                return False, [], f"Invalid port range '{part}'."
            try:
                start = int(sub[0].strip())
                end = int(sub[1].strip())
                if start < 1 or end > 65535 or start > end:
                    return False, [], f"Port range {start}-{end} out of bounds (1-65535)."
                if (end - start + 1) + len(ports) > MAX_PORTS_PER_SCAN:
                    return False, [], f"Total ports exceed limit of {MAX_PORTS_PER_SCAN} ports per scan."
                for p in range(start, end + 1):
                    ports.add(p)
            except ValueError:
                return False, [], f"Invalid number in port range '{part}'."
        else:
            try:
                p = int(part)
                if p < 1 or p > 65535:
                    return False, [], f"Port {p} out of bounds (1-65535)."
                ports.add(p)
            except ValueError:
                return False, [], f"Invalid port number '{part}'."

    if len(ports) > MAX_PORTS_PER_SCAN:
        return False, [], f"Total ports ({len(ports)}) exceed maximum permitted ({MAX_PORTS_PER_SCAN})."

    sorted_ports = sorted(list(ports))
    return True, sorted_ports, ""
