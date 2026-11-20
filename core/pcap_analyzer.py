"""
PCAP & PCAPNG Packet Analysis module for Controlled Reconnaissance Lab.
Provides pure-Python packet decoding, protocol breakdown, conversation tracking,
Wireshark display filter guidance, and cybersecurity anomaly detection.
"""
import struct
import socket
import base64
import os
import re
from typing import Dict, Any, List, Tuple
from pathlib import Path

# Wireshark Display Filters Reference
WIRESHARK_FILTERS = [
    {
        "category": "Reconnaissance & Scans",
        "name": "TCP SYN Packets (Port Scan Detection)",
        "filter": "tcp.flags.syn == 1 && tcp.flags.ack == 0",
        "description": "Filters half-open SYN scan packets used in stealth port scanning."
    },
    {
        "category": "Reconnaissance & Scans",
        "name": "TCP RST Packets (Closed Ports)",
        "filter": "tcp.flags.reset == 1",
        "description": "Locates RST packets returned by closed ports or firewall rejections."
    },
    {
        "category": "Web Security",
        "name": "HTTP POST Requests (Potential Form Submissions)",
        "filter": "http.request.method == \"POST\"",
        "description": "Displays form submissions, login attempts, and API POST calls."
    },
    {
        "category": "Web Security",
        "name": "HTTP Basic Authentication",
        "filter": "http.authorization",
        "description": "Isolates HTTP requests transmitting base64 encoded credentials in Authorization header."
    },
    {
        "category": "Web Security",
        "name": "HTTP Cleartext Passwords in Payload",
        "filter": "frame contains \"password\" || frame contains \"passwd\"",
        "description": "Case-sensitive frame search for unencrypted password strings."
    },
    {
        "category": "DNS Reconnaissance",
        "name": "DNS Standard Queries",
        "filter": "dns.flags.response == 0",
        "description": "Shows outbound domain queries sent to DNS resolvers."
    },
    {
        "category": "DNS Reconnaissance",
        "name": "Failed DNS Lookups (NXDOMAIN)",
        "filter": "dns.flags.rcode == 3",
        "description": "Identifies queries for non-existent domains, common in brute-force subdomain recon."
    },
    {
        "category": "Network Enumeration",
        "name": "ARP Broadcast Requests",
        "filter": "arp.opcode == 1",
        "description": "Tracks local host ARP discovery sweeps across the subnet."
    },
    {
        "category": "Network Enumeration",
        "name": "ICMP Ping Probes",
        "filter": "icmp.type == 8 || icmp.type == 0",
        "description": "Captures ICMP Echo Request and Echo Reply messages."
    }
]

def parse_mac(mac_bytes: bytes) -> str:
    """Format 6 bytes into colon-separated hex MAC."""
    if len(mac_bytes) < 6:
        return "00:00:00:00:00:00"
    return ":".join(f"{b:02x}" for b in mac_bytes[:6])

def parse_ipv4_packet(data: bytes) -> Tuple[Dict[str, Any], bytes]:
    """Parse IPv4 packet header."""
    if len(data) < 20:
        return {}, b""

    ver_ihl = data[0]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4

    if len(data) < ihl or ihl < 20:
        return {}, b""

    total_len = struct.unpack("!H", data[2:4])[0]
    ttl, proto = data[8], data[9]
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])

    # Bound payload according to total_len if valid
    if total_len >= ihl and len(data) >= total_len:
        payload = data[ihl:total_len]
    else:
        payload = data[ihl:]

    return {
        "version": version,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": proto,
        "ttl": ttl,
        "ihl": ihl
    }, payload

def parse_ipv6_packet(data: bytes) -> Tuple[Dict[str, Any], bytes]:
    """Parse IPv6 packet header (40 bytes fixed)."""
    if len(data) < 40:
        return {}, b""

    next_header = data[6]
    hop_limit = data[7]
    try:
        src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
    except Exception:
        src_ip = "::1"
        dst_ip = "::1"

    payload = data[40:]
    return {
        "version": 6,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": next_header,
        "ttl": hop_limit
    }, payload

def parse_tcp_segment(data: bytes) -> Tuple[Dict[str, Any], bytes]:
    """Parse TCP header and extract flags."""
    if len(data) < 20:
        return {}, b""

    src_port, dst_port, seq, ack, offset_reserved = struct.unpack("!HHIIB", data[:13])
    data_offset = (offset_reserved >> 4) * 4
    if data_offset < 20:
        data_offset = 20

    flags_byte = data[13]

    flags = {
        "FIN": bool(flags_byte & 0x01),
        "SYN": bool(flags_byte & 0x02),
        "RST": bool(flags_byte & 0x04),
        "PSH": bool(flags_byte & 0x08),
        "ACK": bool(flags_byte & 0x10),
        "URG": bool(flags_byte & 0x20),
    }

    payload = data[data_offset:] if len(data) >= data_offset else b""
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "flags": flags,
        "seq": seq,
        "ack": ack,
        "data_offset": data_offset
    }, payload

def parse_udp_segment(data: bytes) -> Tuple[Dict[str, Any], bytes]:
    """Parse UDP header."""
    if len(data) < 8:
        return {}, b""
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length
    }, data[8:]

def parse_dns_query(payload: bytes) -> str:
    """Extract first question domain name from raw DNS payload."""
    try:
        if len(payload) < 12:
            return ""
        idx = 12
        domain_parts = []
        while idx < len(payload):
            length = payload[idx]
            if length == 0:
                break
            idx += 1
            if idx + length > len(payload):
                break
            domain_parts.append(payload[idx:idx+length].decode("utf-8", errors="ignore"))
            idx += length
        return ".".join(domain_parts)
    except Exception:
        return ""

class PcapAnalyzer:
    """Pure-Python PCAP parser and security evaluation engine."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.packets: List[Dict[str, Any]] = []
        self.stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "DNS": 0, "HTTP": 0, "Other": 0},
            "top_talkers": {},
            "top_ports": {},
            "conversations": {}
        }
        self.security_alerts: List[Dict[str, Any]] = []

    def parse(self) -> Dict[str, Any]:
        """Read and decode the capture file."""
        if not os.path.isfile(self.file_path):
            raise FileNotFoundError(f"PCAP file not found: {self.file_path}")

        file_size = os.path.getsize(self.file_path)
        if file_size < 24:
            raise ValueError("Capture file is too small or truncated (under 24 bytes).")

        with open(self.file_path, "rb") as f:
            magic = f.read(4)
            f.seek(0)

            # Check PCAP vs PCAPNG magic numbers
            if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
                self._parse_classic_pcap(f, magic)
            elif magic == b"\x0a\x0d\x0d\x0a":
                self._parse_pcapng(f)
            else:
                raise ValueError("Unsupported capture file format. Expected standard PCAP (0xa1b2c3d4/0xd4c3b2a1) or PCAPNG (0x0a0d0d0a).")

        self._evaluate_security_threats()
        return self.get_summary()

    def _parse_classic_pcap(self, f, magic: bytes) -> None:
        """Parse standard libpcap format."""
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        global_header = f.read(24)
        if len(global_header) < 24:
            return

        _, _, _, _, snaplen, linktype = struct.unpack(f"{endian}HHIIII", global_header[4:])

        pkt_num = 1
        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
            if incl_len <= 0 or incl_len > 65535:
                break
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            self._process_packet(pkt_num, ts_sec, ts_usec, pkt_data, linktype)
            pkt_num += 1

    def _parse_pcapng(self, f) -> None:
        """Parse standard PCAPNG blocks."""
        pkt_num = 1

        while True:
            block_hdr = f.read(8)
            if len(block_hdr) < 8:
                break
            block_type, block_len = struct.unpack("<II", block_hdr)
            if block_len < 12:
                break
            body_len = block_len - 12
            body = f.read(body_len)
            tail = f.read(4)  # trailing length

            # Enhanced Packet Block (Type 0x00000006)
            if block_type == 0x00000006 and len(body) >= 20:
                interface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack("<IIIII", body[:20])
                if cap_len > 0 and len(body) >= 20 + cap_len:
                    pkt_data = body[20:20+cap_len]
                    ts_sec = (ts_high << 32 | ts_low) // 1000000
                    ts_usec = (ts_high << 32 | ts_low) % 1000000
                    self._process_packet(pkt_num, ts_sec, ts_usec, pkt_data, linktype=1)
                    pkt_num += 1
            # Simple Packet Block (Type 0x00000002)
            elif block_type == 0x00000002 and len(body) >= 4:
                orig_len = struct.unpack("<I", body[:4])[0]
                pkt_data = body[4:]
                self._process_packet(pkt_num, 0, 0, pkt_data, linktype=1)
                pkt_num += 1

    def _process_packet(self, pkt_num: int, ts_sec: int, ts_usec: int, data: bytes, linktype: int) -> None:
        """Decode packet layers according to link layer type."""
        self.stats["total_packets"] += 1
        self.stats["total_bytes"] += len(data)

        record = {
            "no": pkt_num,
            "timestamp": f"{ts_sec}.{ts_usec:06d}",
            "src": "-",
            "dst": "-",
            "protocol": "Raw",
            "info": f"Captured Frame ({len(data)} bytes)",
            "length": len(data),
            "payload_preview": ""
        }

        ethertype = 0
        l3_data = b""

        # 1. Determine Link Layer Offset & EtherType
        # Ethernet (LinkType 1)
        if linktype == 1:
            if len(data) < 14:
                return
            dst_mac = parse_mac(data[0:6])
            src_mac = parse_mac(data[6:12])
            record["src"] = src_mac
            record["dst"] = dst_mac
            ethertype = struct.unpack("!H", data[12:14])[0]

            # 802.1Q VLAN Tagged
            if ethertype == 0x8100 and len(data) >= 18:
                ethertype = struct.unpack("!H", data[16:18])[0]
                l3_data = data[18:]
            else:
                l3_data = data[14:]

        # Linux Cooked Capture (LinkType 113)
        elif linktype == 113:
            if len(data) < 16:
                return
            ethertype = struct.unpack("!H", data[14:16])[0]
            record["src"] = "linux-cooked"
            record["dst"] = "linux-cooked"
            l3_data = data[16:]

        # Raw IP (LinkType 12 or 101)
        elif linktype in (12, 101):
            ethertype = 0x0800
            record["src"] = "raw-ip"
            record["dst"] = "raw-ip"
            l3_data = data

        # Null / Loopback (LinkType 0)
        elif linktype == 0:
            if len(data) < 4:
                return
            family = struct.unpack("!I", data[:4])[0]
            ethertype = 0x0800 if family in (2, 28) else 0
            l3_data = data[4:]
        else:
            # Fallback assumption: Ethernet
            if len(data) >= 14:
                ethertype = struct.unpack("!H", data[12:14])[0]
                l3_data = data[14:]

        # 2. Layer 3 & Layer 4 Decoding
        # ARP (0x0806)
        if ethertype == 0x0806 and len(l3_data) >= 28:
            self.stats["protocols"]["ARP"] += 1
            op = struct.unpack("!H", l3_data[6:8])[0]
            s_ip = socket.inet_ntoa(l3_data[14:18])
            t_ip = socket.inet_ntoa(l3_data[24:28])
            record["protocol"] = "ARP"
            record["src"] = s_ip
            record["dst"] = t_ip
            record["info"] = f"Who has {t_ip}? Tell {s_ip}" if op == 1 else f"{s_ip} is at {record['src']}"

        # IPv4 (0x0800)
        elif ethertype == 0x0800 and len(l3_data) >= 20:
            ip_info, ip_payload = parse_ipv4_packet(l3_data)
            if ip_info:
                record["src"] = ip_info["src_ip"]
                record["dst"] = ip_info["dst_ip"]
                self._tally_talker(ip_info["src_ip"], ip_info["dst_ip"])

                proto_num = ip_info["protocol"]
                self._decode_l4_protocols(record, proto_num, ip_payload, ip_info)

        # IPv6 (0x86DD)
        elif ethertype == 0x86DD and len(l3_data) >= 40:
            ip6_info, ip6_payload = parse_ipv6_packet(l3_data)
            if ip6_info:
                record["src"] = ip6_info["src_ip"]
                record["dst"] = ip6_info["dst_ip"]
                self._tally_talker(ip6_info["src_ip"], ip6_info["dst_ip"])
                proto_num = ip6_info["protocol"]
                self._decode_l4_protocols(record, proto_num, ip6_payload, ip6_info)

        if len(self.packets) < 500:  # store up to 500 packets for detailed UI inspection
            self.packets.append(record)

    def _decode_l4_protocols(self, record: Dict[str, Any], proto_num: int, payload: bytes, ip_info: Dict[str, Any]) -> None:
        """Decode transport protocols: TCP, UDP, ICMP."""
        # TCP (Protocol 6)
        if proto_num == 6:
            self.stats["protocols"]["TCP"] += 1
            tcp_info, tcp_payload = parse_tcp_segment(payload)
            if tcp_info:
                record["src_port"] = tcp_info["src_port"]
                record["dst_port"] = tcp_info["dst_port"]
                self._tally_port(tcp_info["src_port"], tcp_info["dst_port"])

                flags_str = ",".join(k for k, v in tcp_info["flags"].items() if v)
                record["protocol"] = "TCP"
                record["info"] = f"{tcp_info['src_port']} -> {tcp_info['dst_port']} [{flags_str}] Seq={tcp_info['seq']}"

                # Check HTTP (Common ports 80, 8080, 8000, 8443, 5000, 3000)
                if tcp_info["dst_port"] in (80, 8080, 8000, 8443, 5000, 3000) or tcp_info["src_port"] in (80, 8080, 8000, 8443, 5000, 3000):
                    is_http = any(tcp_payload.startswith(m) for m in (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"HTTP/1.", b"HTTP/2."))
                    if is_http:
                        self.stats["protocols"]["HTTP"] += 1
                        record["protocol"] = "HTTP"
                        try:
                            first_line = tcp_payload.split(b"\r\n")[0].decode("utf-8", errors="ignore")
                            record["info"] = first_line[:90]
                            record["payload_preview"] = tcp_payload[:512].decode("utf-8", errors="ignore")
                        except Exception:
                            pass

        # UDP (Protocol 17)
        elif proto_num == 17:
            self.stats["protocols"]["UDP"] += 1
            udp_info, udp_payload = parse_udp_segment(payload)
            if udp_info:
                record["src_port"] = udp_info["src_port"]
                record["dst_port"] = udp_info["dst_port"]
                self._tally_port(udp_info["src_port"], udp_info["dst_port"])
                record["protocol"] = "UDP"
                record["info"] = f"UDP {udp_info['src_port']} -> {udp_info['dst_port']} Len={udp_info['length']}"

                # DNS (Port 53)
                if udp_info["dst_port"] == 53 or udp_info["src_port"] == 53:
                    self.stats["protocols"]["DNS"] += 1
                    record["protocol"] = "DNS"
                    query_domain = parse_dns_query(udp_payload)
                    if query_domain:
                        record["info"] = f"Standard query A {query_domain}"

        # ICMP (Protocol 1)
        elif proto_num == 1:
            self.stats["protocols"]["ICMP"] += 1
            record["protocol"] = "ICMP"
            if len(payload) >= 2:
                itype, icode = payload[0], payload[1]
                type_str = "Echo Request" if itype == 8 else ("Echo Reply" if itype == 0 else f"Type {itype}")
                record["info"] = f"ICMP {type_str} (id=0x{ip_info.get('ttl', 64):02x})"
        else:
            self.stats["protocols"]["Other"] += 1

    def _tally_talker(self, src: str, dst: str) -> None:
        """Accumulate conversation matrix."""
        self.stats["top_talkers"][src] = self.stats["top_talkers"].get(src, 0) + 1
        conv_key = f"{min(src, dst)} <-> {max(src, dst)}"
        self.stats["conversations"][conv_key] = self.stats["conversations"].get(conv_key, 0) + 1

    def _tally_port(self, src_port: int, dst_port: int) -> None:
        """Accumulate port counts."""
        self.stats["top_ports"][dst_port] = self.stats["top_ports"].get(dst_port, 0) + 1

    def _evaluate_security_threats(self) -> None:
        """Heuristically inspect captured packets for security incidents."""
        syn_scan_tracker = {}
        plaintext_creds = []

        for pkt in self.packets:
            # Detect SYN Scan
            if pkt.get("protocol") == "TCP" and "info" in pkt:
                if "[SYN]" in pkt["info"] and "ACK" not in pkt["info"]:
                    src = pkt.get("src", "")
                    dst_port = pkt.get("dst_port")
                    if src and dst_port:
                        syn_scan_tracker.setdefault(src, set()).add(dst_port)

            # Detect Plaintext Credential Exposure
            preview = pkt.get("payload_preview", "")
            if preview:
                # HTTP Basic Auth: Authorization: Basic dXNlcjpwYXNz
                basic_auth_match = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", preview, re.IGNORECASE)
                if basic_auth_match:
                    encoded = basic_auth_match.group(1)
                    try:
                        decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
                        plaintext_creds.append(f"HTTP Basic Auth: '{decoded}' from {pkt.get('src')}")
                    except Exception:
                        plaintext_creds.append(f"HTTP Basic Auth Header from {pkt.get('src')}")

                # Unencrypted form submission password fields
                if re.search(r"(?:password|passwd|pwd|pass)=([^&\s]+)", preview, re.IGNORECASE):
                    plaintext_creds.append(f"Unencrypted Password parameter observed in HTTP body from {pkt.get('src')}")

        # Add Alerts
        for src, scanned_ports in syn_scan_tracker.items():
            if len(scanned_ports) >= 3:
                self.security_alerts.append({
                    "title": "Port Reconnaissance Activity Detected (SYN Scan)",
                    "severity": "High",
                    "details": f"Source {src} initiated half-open TCP SYN probes across {len(scanned_ports)} distinct ports ({', '.join(str(p) for p in sorted(list(scanned_ports))[:10])}...).",
                    "recommendation": "Investigate source host for automated scanner activity (Nmap/Masscan). Enable rate limiting on gateway."
                })

        for cred in plaintext_creds:
            self.security_alerts.append({
                "title": "Cleartext Authentication Credentials Transmitted",
                "severity": "Critical",
                "details": f"Sensitive credentials observed in plaintext over unencrypted HTTP: {cred}",
                "recommendation": "Enforce HTTPS (TLS 1.3) across all endpoints and deprecate plain HTTP authentication."
            })

        # DNS anomaly alert if high volume
        if self.stats["protocols"]["DNS"] > 50:
            self.security_alerts.append({
                "title": "High DNS Query Volume (Potential Enumeration)",
                "severity": "Medium",
                "details": f"Observed {self.stats['protocols']['DNS']} DNS queries in capture file.",
                "recommendation": "Inspect query names for DNS tunneling or aggressive subdomain dictionary enumeration."
            })

    def get_summary(self) -> Dict[str, Any]:
        """Return formatted analysis dictionary."""
        sorted_talkers = sorted(self.stats["top_talkers"].items(), key=lambda x: x[1], reverse=True)[:5]
        sorted_ports = sorted(self.stats["top_ports"].items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            "file_name": Path(self.file_path).name,
            "total_packets": self.stats["total_packets"],
            "total_bytes": self.stats["total_bytes"],
            "protocols": self.stats["protocols"],
            "top_talkers": [{"ip": item[0], "count": item[1]} for item in sorted_talkers],
            "top_ports": [{"port": item[0], "count": item[1]} for item in sorted_ports],
            "packets": self.packets[:100],  # UI table view
            "security_alerts": self.security_alerts,
            "alerts_count": len(self.security_alerts)
        }

def generate_sample_pcap(output_path: str) -> None:
    """
    Generate an authentic, multi-protocol PCAP file for out-of-the-box lab testing.
    Contains SYN scan probes, HTTP GET/POST with credentials, DNS query, and ARP.
    """
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # PCAP Global Header: magic 0xa1b2c3d4, v2.4, thiszone=0, sigfigs=0, snaplen=65535, linktype=1 (Ethernet)
    global_hdr = struct.pack(">IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    packets_raw = []

    # Helper: Build Ethernet + IPv4 + TCP packet
    def build_tcp(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b""):
        # Eth
        eth = bytes.fromhex(src_mac.replace(":", "")) + bytes.fromhex(dst_mac.replace(":", "")) + b"\x08\x00"
        # IPv4
        ip_total_len = 20 + 20 + len(payload)
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total_len, 0x1234, 0x4000, 64, 6, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        # TCP
        tcp_hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, (5 << 4), flags, 8192, 0, 0)
        return eth + ip_hdr + tcp_hdr + payload

    # 1. ARP Packet (Who has 192.168.1.1? Tell 192.168.1.50)
    arp_pkt = (
        bytes.fromhex("ffffffffffff") + bytes.fromhex("000c294f8e1a") + b"\x08\x06" +
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) +
        bytes.fromhex("000c294f8e1a") + socket.inet_aton("192.168.1.50") +
        bytes.fromhex("000000000000") + socket.inet_aton("192.168.1.1")
    )
    packets_raw.append(arp_pkt)

    # 2. DNS Query for internal.lab.local (UDP port 53)
    def build_dns(domain="internal.lab.local"):
        eth = bytes.fromhex("005056c00001") + bytes.fromhex("000c294f8e1a") + b"\x08\x00"
        # DNS query payload
        dns_body = struct.pack("!HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0)
        for part in domain.split("."):
            dns_body += bytes([len(part)]) + part.encode()
        dns_body += b"\x00\x00\x01\x00\x01"  # Type A, Class IN
        udp_len = 8 + len(dns_body)
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + udp_len, 0x2233, 0, 64, 17, 0, socket.inet_aton("192.168.1.50"), socket.inet_aton("192.168.1.1"))
        udp_hdr = struct.pack("!HHHH", 49152, 53, udp_len, 0)
        return eth + ip_hdr + udp_hdr + dns_body

    packets_raw.append(build_dns("internal.lab.local"))

    # 3. SYN Scan Probes on Ports 21, 22, 23, 80, 443, 3306
    for idx, target_port in enumerate([21, 22, 23, 80, 443, 3306]):
        syn_pkt = build_tcp(
            "005056c00001", "000c294f8e1a",
            "192.168.1.50", "192.168.1.10",
            40000 + idx, target_port,
            1000 + idx, 0, 0x02  # SYN flag
        )
        packets_raw.append(syn_pkt)

    # 4. HTTP Cleartext Basic Auth Request (Port 80)
    auth_header = base64.b64encode(b"admin:LabSecret2026!").decode()
    http_payload = (
        f"POST /api/login HTTP/1.1\r\n"
        f"Host: 192.168.1.10\r\n"
        f"Authorization: Basic {auth_header}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 32\r\n\r\n"
        f"username=admin&password=LabSecret2026!"
    ).encode()

    http_pkt = build_tcp(
        "005056c00001", "000c294f8e1a",
        "192.168.1.50", "192.168.1.10",
        51234, 80,
        2000, 1, 0x18,  # PSH + ACK
        http_payload
    )
    packets_raw.append(http_pkt)

    # Write PCAP file
    with open(output_path, "wb") as f:
        f.write(global_hdr)
        base_sec = 1732104000
        for i, pkt in enumerate(packets_raw):
            pkt_len = len(pkt)
            pkt_hdr = struct.pack(">IIII", base_sec + i, i * 150000, pkt_len, pkt_len)
            f.write(pkt_hdr)
            f.write(pkt)
