"""PCAP streaming reader — PcapReader generator + size gate + port filter.

OOM HARDENING (per spec):
  - NEVER uses rdpcap() — only PcapReader() as a streaming generator.
  - 50MB hard file-size gate at entry.
  - Port filter at read layer: only UDP/53 (DNS) + TCP/443 (TLS SNI) pass through.
    All other packets are dropped immediately, saving ~90% processing time.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator, Optional

# Suppress scapy's verbose runtime warnings (keeps LLM output clean)
logging.getLogger("scapy").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.inet import TCP, UDP  # noqa: E402
from scapy.utils import PcapReader  # noqa: E402

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB hard gate
_DNS_PORT = 53
_TLS_PORT = 443


def check_file_size(path: str) -> Optional[str]:
    """Return error message if file exceeds 50MB gate, else None."""
    try:
        size = Path(path).stat().st_size
    except OSError as exc:
        return f"❌ Cannot read file: {exc}"
    if size > MAX_FILE_SIZE:
        return (
            f"❌ File too large for local triage ({size // 1024 // 1024}MB > 50MB limit). "
            "Please pre-filter with Wireshark/tshark (e.g. tshark -r input.pcap -Y "
            "'udp.port==53 or tcp.port==443' -w filtered.pcap) and retry."
        )
    return None


def _is_relevant(packet) -> bool:
    """Port filter: keep only UDP/53 (DNS) or TCP/443 (TLS SNI)."""
    if packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        return sport == _DNS_PORT or dport == _DNS_PORT
    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        return sport == _TLS_PORT or dport == _TLS_PORT
    return False


def iter_filtered_packets(path: str) -> Iterator[tuple]:
    """Stream packets one-by-one via PcapReader, yielding only DNS/TLS packets.

    Yields tuples of (packet, layer_kind) where layer_kind is 'dns' or 'tls'.
    NEVER loads the full capture into memory.
    """
    with PcapReader(path) as reader:
        for packet in reader:
            if not _is_relevant(packet):
                continue
            if packet.haslayer(UDP):
                yield packet, "dns"
            else:
                yield packet, "tls"
