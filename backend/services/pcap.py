"""PCAP analysis service (extracted from the upload-pcap route)."""

import os
import re
from collections import Counter

from scapy.all import rdpcap

ALLOWED_PCAP_EXT = {".pcap", ".pcapng", ".cap"}
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")


def safe_filename(filename):
    """Strip path components and unsafe characters from an upload name."""
    return _SAFE_NAME_RE.sub("_", os.path.basename(filename or ""))


def is_allowed_pcap(filename):
    return os.path.splitext(filename)[1].lower() in ALLOWED_PCAP_EXT


def analyze_pcap(filepath):
    """Parse a PCAP file and return summary statistics."""
    packets = rdpcap(filepath)

    protocols = set()
    suspicious = 0
    src_ips = []
    dst_ports = []
    ip_port_map = {}

    for pkt in packets:
        try:
            if pkt.haslayer("IP"):
                src = pkt["IP"].src
                src_ips.append(src)
            else:
                continue

            if pkt.haslayer("TCP"):
                protocols.add("TCP")
                port = pkt["TCP"].dport
                dst_ports.append(port)
                ip_port_map.setdefault(src, set()).add(port)

            if pkt.haslayer("UDP"):
                protocols.add("UDP")
                port = pkt["UDP"].dport
                dst_ports.append(port)

            if pkt.haslayer("Raw"):
                payload = str(pkt["Raw"].load)
                if "SELECT" in payload or "<script>" in payload:
                    suspicious += 1
        except Exception:
            continue

    return {
        "total_packets": len(packets),
        "protocols": list(protocols),
        "suspicious": suspicious,
        "top_ips": Counter(src_ips).most_common(5),
        "top_ports": Counter(dst_ports).most_common(5),
        "possible_scanners": [ip for ip, ports in ip_port_map.items() if len(ports) > 20],
    }
