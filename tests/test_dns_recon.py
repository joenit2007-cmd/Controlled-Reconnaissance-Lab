"""
Unit tests for DNS reconnaissance module.
"""
import pytest
from core.dns_recon import execute_dns_recon

def test_dns_recon_lab_domain():
    res = execute_dns_recon("lab.local")
    assert res["success"] is True
    assert res["domain"] == "lab.local"
    assert "A" in res["records"]
    assert len(res["records"]["A"]) > 0
    assert len(res["subdomains"]) > 0

    sub_names = [s["subdomain"] for s in res["subdomains"]]
    assert any("admin.lab.local" in s for s in sub_names)
    assert any("mail.lab.local" in s for s in sub_names)

def test_dns_recon_localhost():
    res = execute_dns_recon("localhost")
    assert res["success"] is True
    assert "127.0.0.1" in res["records"].get("A", [])

def test_dns_recon_rejects_disallowed_target():
    res = execute_dns_recon("8.8.8.8")
    assert res["success"] is False
    assert "Scope Violation" in res["error"]
