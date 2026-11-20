"""
Unit tests for target validation and safety boundaries.
"""
import pytest
from core.target_validator import validate_target, validate_ports, is_ip_in_allowed_scope

def test_allowed_localhost_targets():
    valid, target, err = validate_target("127.0.0.1")
    assert valid is True
    assert target == "127.0.0.1"
    assert err == ""

    valid, target, err = validate_target("localhost")
    assert valid is True
    assert target == "localhost"

def test_allowed_private_ips():
    assert is_ip_in_allowed_scope("10.0.0.1") is True
    assert is_ip_in_allowed_scope("172.16.5.10") is True
    assert is_ip_in_allowed_scope("192.168.1.1") is True
    assert is_ip_in_allowed_scope("169.254.1.1") is True

    valid, target, err = validate_target("192.168.1.50")
    assert valid is True
    assert target == "192.168.1.50"

def test_blocked_public_ips():
    assert is_ip_in_allowed_scope("8.8.8.8") is False
    assert is_ip_in_allowed_scope("1.1.1.1") is False

    valid, target, err = validate_target("8.8.8.8")
    assert valid is False
    assert "Scope Violation" in err

    valid, target, err = validate_target("93.184.216.34")
    assert valid is False
    assert "Scope Violation" in err

def test_command_injection_rejection():
    malicious_inputs = [
        "127.0.0.1; whoami",
        "127.0.0.1 && dir",
        "127.0.0.1 | cat /etc/passwd",
        "127.0.0.1`id`",
        "127.0.0.1$(whoami)",
        "127.0.0.1\ncat /etc/shadow"
    ]
    for bad in malicious_inputs:
        valid, target, err = validate_target(bad)
        assert valid is False
        assert "Disallowed characters" in err

def test_allowed_lab_domains():
    valid, target, err = validate_target("lab.local", allow_dns_resolution=False)
    assert valid is True
    assert target == "lab.local"

    valid, target, err = validate_target("internal.test", allow_dns_resolution=False)
    assert valid is True

def test_validate_ports():
    valid, ports, err = validate_ports("80")
    assert valid is True
    assert ports == [80]

    valid, ports, err = validate_ports("21, 22, 80, 443")
    assert valid is True
    assert ports == [21, 22, 80, 443]

    valid, ports, err = validate_ports("1-5")
    assert valid is True
    assert ports == [1, 2, 3, 4, 5]

    # Out of bounds
    valid, ports, err = validate_ports("70000")
    assert valid is False
    assert "out of bounds" in err

    # Bad chars
    valid, ports, err = validate_ports("80; rm -rf")
    assert valid is False
