"""
Unit tests for PCAP packet parsing and security anomaly detection.
"""
import os
import pytest
from core.pcap_analyzer import PcapAnalyzer, generate_sample_pcap
from core.config import SAMPLES_DIR

def test_pcap_generation_and_parsing(tmp_path):
    test_pcap = tmp_path / "test_capture.pcap"
    generate_sample_pcap(str(test_pcap))
    assert os.path.exists(test_pcap)

    analyzer = PcapAnalyzer(str(test_pcap))
    summary = analyzer.parse()

    assert summary["total_packets"] == 9
    assert summary["total_bytes"] > 0
    assert "protocols" in summary
    assert summary["protocols"]["TCP"] == 7
    assert summary["protocols"]["UDP"] == 1
    assert summary["protocols"]["ARP"] == 1
    assert summary["protocols"]["DNS"] == 1
    assert summary["protocols"]["HTTP"] == 1

    # Verify packet list length and packet details
    packets = summary["packets"]
    assert len(packets) == 9
    for p in packets:
        assert "no" in p
        assert "timestamp" in p
        assert "src" in p
        assert "dst" in p
        assert "protocol" in p
        assert "length" in p
        assert "info" in p
        assert len(p["info"]) > 0

    # Verify specific protocol decodes
    arp_pkt = next(p for p in packets if p["protocol"] == "ARP")
    assert "192.168.1.50" in arp_pkt["src"]

    dns_pkt = next(p for p in packets if p["protocol"] == "DNS")
    assert "internal.lab.local" in dns_pkt["info"]

    http_pkt = next(p for p in packets if p["protocol"] == "HTTP")
    assert "POST /api/login" in http_pkt["info"]
    assert "Basic" in http_pkt["payload_preview"]
    assert "password=" in http_pkt["payload_preview"]

    # Verify security alerts triggered
    alerts = summary["security_alerts"]
    assert len(alerts) >= 2

    alert_titles = [a["title"] for a in alerts]
    assert any("SYN Scan" in t for t in alert_titles)
    assert any("Cleartext" in t for t in alert_titles)

def test_pcap_truncated_file_rejection(tmp_path):
    bad_pcap = tmp_path / "truncated.pcap"
    with open(bad_pcap, "wb") as f:
        f.write(b"PKT")
    
    analyzer = PcapAnalyzer(str(bad_pcap))
    with pytest.raises(ValueError) as exc:
        analyzer.parse()
    assert "too small" in str(exc.value)

def test_pcap_invalid_magic_header(tmp_path):
    invalid_pcap = tmp_path / "invalid.pcap"
    with open(invalid_pcap, "wb") as f:
        f.write(b"INVALID_HEADER_BYTES_FOR_PCAP_TESTING_1234")

    analyzer = PcapAnalyzer(str(invalid_pcap))
    with pytest.raises(ValueError) as exc:
        analyzer.parse()
    assert "Unsupported capture file format" in str(exc.value)
