"""
Unit tests for ReportLab PDF report generation.
"""
import os
from pathlib import Path
from core.pdf_reporter import generate_security_report

def test_generate_pdf_report(tmp_path):
    target = "127.0.0.1"
    findings = [
        {
            "title": "Cleartext HTTP Service",
            "severity": "Medium",
            "category": "Web Security",
            "target": target,
            "description": "Port 80 unencrypted",
            "evidence": "HTTP 200 OK",
            "remediation": "Enable HTTPS with TLS 1.3",
            "status": "Open"
        },
        {
            "title": "Default Credentials on FTP",
            "severity": "Critical",
            "category": "Cleartext Protocol",
            "target": target,
            "description": "Anonymous FTP allowed",
            "evidence": "vsftpd 3.0.3",
            "remediation": "Disable anonymous logins",
            "status": "Open"
        }
    ]
    scans_summary = {
        "ports": [
            {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp", "version": "vsftpd 3.0.3"},
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache 2.4.52"}
        ]
    }
    pcap_summary = {
        "file_name": "test_traffic.pcap",
        "total_packets": 120,
        "alerts_count": 1,
        "security_alerts": [
            {
                "title": "SYN Scan Detected",
                "severity": "High",
                "details": "Port scan from 192.168.1.50",
                "recommendation": "Rate limit ingress"
            }
        ]
    }

    pdf_file = generate_security_report(
        target=target,
        findings=findings,
        scans_summary=scans_summary,
        pcap_summary=pcap_summary,
        output_filename="test_assessment_output.pdf"
    )

    assert os.path.exists(pdf_file)
    assert os.path.getsize(pdf_file) > 1000
