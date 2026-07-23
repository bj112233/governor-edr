"""DNS collector — extracts unique query names + answer records from UDP/53.

Dedup at collection layer: uses set() — never list().
The same domain (api.microsoft.com) seen 500 times counts as 1 entry.
"""

from __future__ import annotations

from typing import Any

from scapy.layers.dns import DNS, DNSRR


class DnsCollector:
    """Stateful collector — feed() each DNS packet, call result() when done."""

    def __init__(self) -> None:
        self.queries: set[str] = set()
        self.answers: set[str] = set()
        self.packet_count: int = 0

    def feed(self, packet) -> None:
        """Extract query names + answer records from a single DNS packet."""
        if not packet.haslayer(DNS):
            return
        self.packet_count += 1
        dns = packet[DNS]

        # ── Query name ──
        if dns.qd:
            try:
                qname = dns.qd.qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace")
                qname = str(qname).rstrip(".")
                if qname:
                    self.queries.add(qname)
            except Exception:
                pass  # malformed packet — skip silently

        # ── Answer records (iterate all DNSRR layers) ──
        if dns.an:
            layer: Any = dns.an
            while layer is not None and isinstance(layer, DNSRR):
                try:
                    rdata = str(layer.rdata).rstrip(".")
                    if rdata and rdata != ";":
                        self.answers.add(rdata)
                except Exception:
                    pass
                layer = layer.payload

    def result(self) -> dict[str, Any]:
        """Return deduplicated DNS summary."""
        return {
            "queries": self.queries,
            "answers": self.answers,
            "packet_count": self.packet_count,
            "unique_queries": len(self.queries),
            "unique_answers": len(self.answers),
        }
