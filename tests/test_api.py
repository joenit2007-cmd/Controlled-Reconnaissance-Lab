"""
Integration tests for Flask application API endpoints.
"""
import pytest
from app import app
from core.db import init_db

@pytest.fixture
def client():
    app.config["TESTING"] = True
    init_db()
    with app.test_client() as client:
        yield client

def test_index_route(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"RECON LAB" in res.data
    assert b"Controlled Reconnaissance Lab" in res.data

def test_api_overview(client):
    res = client.get("/api/overview")
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["success"] is True
    assert "metrics" in json_data
    assert "tools" in json_data
    assert "nmap" in json_data["tools"]

def test_api_scan_scope_protection(client):
    # Try public IP
    res = client.post("/api/scan/nmap", json={"target": "8.8.8.8", "profile": "quick"})
    json_data = res.get_json()
    assert json_data["success"] is False
    assert "Scope Violation" in json_data["error"]

def test_api_dns_recon(client):
    res = client.post("/api/scan/dns", json={"domain": "lab.local"})
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["success"] is True
    assert "records" in json_data
    assert len(json_data["subdomains"]) > 0

def test_api_pcap_sample(client):
    res = client.get("/api/pcap/sample")
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data["success"] is True
    analysis = json_data["analysis"]
    assert analysis["total_packets"] == 9
    assert analysis["protocols"]["TCP"] == 7
    assert analysis["protocols"]["UDP"] == 1
    assert analysis["protocols"]["ARP"] == 1
    assert analysis["protocols"]["DNS"] == 1
    assert analysis["protocols"]["HTTP"] == 1
    assert len(analysis["packets"]) == 9
    assert len(analysis["security_alerts"]) >= 2
    assert len(analysis["top_talkers"]) > 0
    assert len(analysis["top_ports"]) > 0

def test_api_linux_calc_perms(client):
    res = client.post("/api/linux/calc-perms", json={
        "user_r": True, "user_w": True, "user_x": True,
        "group_r": True, "group_w": False, "group_x": True,
        "other_r": True, "other_w": False, "other_x": True
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["result"]["octal"] == "755"
    assert data["result"]["symbolic"] == "-rwxr-xr-x"

def test_api_findings_crud(client):
    # Create finding
    create_res = client.post("/api/findings", json={
        "title": "Automated Unit Test Finding",
        "severity": "High",
        "category": "Testing",
        "target": "127.0.0.1",
        "description": "Test description",
        "evidence": "Test evidence",
        "remediation": "Test remediation",
        "status": "Open"
    })
    assert create_res.status_code == 200
    created = create_res.get_json()
    finding_id = created["finding_id"]

    # Read findings
    get_res = client.get("/api/findings")
    assert get_res.status_code == 200
    findings = get_res.get_json()["findings"]
    assert any(f["id"] == finding_id for f in findings)

    # Update finding
    put_res = client.put(f"/api/findings/{finding_id}", json={"status": "Remediated"})
    assert put_res.status_code == 200

    # Delete finding
    del_res = client.delete(f"/api/findings/{finding_id}")
    assert del_res.status_code == 200

def test_api_reports_generation(client):
    res = client.post("/api/reports/generate", json={
        "target": "127.0.0.1",
        "title": "API Automated Assessment Report"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "filename" in data
    assert "download_url" in data
