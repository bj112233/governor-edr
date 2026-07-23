# services/net_parser.py
"""Network address parsing utilities — robust IPv4/IPv6 IP:Port extraction.
All new files < 300 lines (SRP).
"""

import ipaddress
from typing import Optional


def parse_ip_port(addr_str: str) -> tuple[str | None, int | None]:
    """Parse an address string into (ip, port).

    Strict RFC 3986 enforcement:
      - IPv6 with port MUST be bracketed: "[::1]:8080"
      - IPv4 with port: "192.168.1.1:8080"
      - Bare IP (no port): "2a04:4e42::684" or "192.168.1.1"
    """
    if not addr_str:
        return (None, None)

    clean = addr_str.strip()

    # 1. Bracket Enforced IPv6
    if clean.startswith("["):
        bracket_end = clean.find("]")
        if bracket_end == -1:
            return (addr_str, None)
        ip_str = clean[1:bracket_end]
        try:
            ipaddress.ip_address(ip_str)
        except ValueError:
            return (addr_str, None)
        remainder = clean[bracket_end + 1 :]
        if remainder.startswith(":"):
            try:
                port = int(remainder[1:])
                return (ip_str, port)
            except ValueError:
                return (addr_str, None)
        return (ip_str, None)

    # 2. Standard IPv4 with Port (exactly one colon, no brackets)
    if clean.count(":") == 1:
        ip_part, port_part = clean.split(":", 1)
        try:
            ipaddress.ip_address(ip_part)
            port = int(port_part)
            return (ip_part, port)
        except ValueError:
            return (addr_str, None)

    # 3. Bare IP (Fallback) — no brackets, multiple or zero colons
    try:
        ipaddress.ip_address(clean)
        return (clean, None)
    except ValueError:
        return (addr_str, None)


def is_ipv6(ip: str) -> bool:
    """Check if string is a valid IPv6 address."""
    try:
        addr = ipaddress.ip_address(ip)
        return isinstance(addr, ipaddress.IPv6Address)
    except ValueError:
        return False


def get_subnet(ip: str, prefix_v4: int = 24, prefix_v6: int = 64) -> str:
    """Return subnet string for aggregation (e.g., '192.168.1.0/24')."""
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address):
            net6 = ipaddress.IPv6Network(ip + f"/{prefix_v6}", strict=False)
            return str(net6.network_address) + f"/{prefix_v6}"
        net4 = ipaddress.IPv4Network(ip + f"/{prefix_v4}", strict=False)
        return str(net4.network_address) + f"/{prefix_v4}"
    except ValueError:
        return ip


def extract_ip_from_conn_string(line: str) -> str | None:
    """Extract IP from connection strings like 'ip:port (proc:pid)'."""
    if not line or " " not in line:
        return None
    ip_part = line.split(" ")[0]
    ip, _ = parse_ip_port(ip_part)
    return ip
