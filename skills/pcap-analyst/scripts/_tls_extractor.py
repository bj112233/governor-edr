"""TLS SNI collector — extracts Server Name Indication from ClientHello.

Uses raw byte parsing of TCP payload (NOT scapy.layers.tls) to avoid
importing the heavy TLS layer. Only parses ClientHello (handshake type 0x01)
and the SNI extension (type 0x0000).

Dedup at collection layer: uses set() — never list().
"""

from __future__ import annotations

from typing import Any


class SniCollector:
    """Stateful collector — feed() each TLS packet, call result() when done."""

    def __init__(self) -> None:
        self.sni_values: set[str] = set()
        self.client_hello_count: int = 0
        self.packet_count: int = 0

    def feed(self, packet) -> None:
        """Extract SNI from a TCP/443 packet's raw payload."""
        self.packet_count += 1
        try:
            raw = bytes(packet["TCP"].payload)
        except Exception:
            return
        if not raw:
            return
        sni = _parse_sni_from_client_hello(raw)
        if sni:
            self.sni_values.add(sni)
            self.client_hello_count += 1

    def result(self) -> dict[str, Any]:
        """Return deduplicated SNI summary."""
        return {
            "sni": self.sni_values,
            "client_hello_count": self.client_hello_count,
            "packet_count": self.packet_count,
            "unique_sni": len(self.sni_values),
        }


def _parse_sni_from_client_hello(data: bytes) -> str | None:
    """Parse SNI hostname from a TLS ClientHello raw byte payload.

    Returns the hostname string or None if not a ClientHello / no SNI.
    Robust against truncated/malformed records — returns None on any error.
    """
    try:
        # TLS Record Header: content_type(1) + version(2) + length(2)
        if len(data) < 5 or data[0] != 0x16:  # 0x16 = Handshake
            return None

        # Handshake Header: type(1) + length(3)
        hs_offset = 5
        if len(data) < hs_offset + 4 or data[hs_offset] != 0x01:  # 0x01 = ClientHello
            return None

        # ClientHello: version(2) + random(32) + session_id_len(1)
        ch_offset = hs_offset + 4
        if len(data) < ch_offset + 35:
            return None
        session_id_len = data[ch_offset + 34]
        offset = ch_offset + 35 + session_id_len

        # Cipher suites: length(2) + data
        if len(data) < offset + 2:
            return None
        cs_len = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2 + cs_len

        # Compression methods: length(1) + data
        if len(data) < offset + 1:
            return None
        comp_len = data[offset]
        offset += 1 + comp_len

        # Extensions: total_length(2) + data
        if len(data) < offset + 2:
            return None
        ext_total_len = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        ext_end = offset + ext_total_len

        # Iterate extensions looking for SNI (type 0x0000)
        while offset + 4 <= ext_end and offset + 4 <= len(data):
            ext_type = int.from_bytes(data[offset : offset + 2], "big")
            ext_data_len = int.from_bytes(data[offset + 2 : offset + 4], "big")
            ext_data_start = offset + 4
            ext_data = data[ext_data_start : ext_data_start + ext_data_len]

            if ext_type == 0x0000:  # server_name extension
                return _parse_sni_extension(ext_data)

            offset = ext_data_start + ext_data_len

        return None
    except (IndexError, ValueError):
        return None


def _parse_sni_extension(ext_data: bytes) -> str | None:
    """Parse the SNI extension payload — returns the first host_name or None."""
    if len(ext_data) < 5:
        return None
    # SNI list: total_length(2) + entries
    list_offset = 2  # skip list length
    while list_offset + 3 <= len(ext_data):
        name_type = ext_data[list_offset]
        name_len = int.from_bytes(ext_data[list_offset + 1 : list_offset + 3], "big")
        name_start = list_offset + 3
        if name_type == 0 and name_start + name_len <= len(ext_data):  # host_name
            return ext_data[name_start : name_start + name_len].decode("utf-8", errors="replace")
        list_offset = name_start + name_len
    return None
