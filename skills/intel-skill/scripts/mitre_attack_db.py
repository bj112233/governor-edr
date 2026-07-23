"""MITRE ATT&CK static database — pure data, zero I/O, zero dependencies.

Technique IDs, signal-to-technique mappings, and known CVE associations.
Designed for O(1) lookups. Extend SIGNAL_MAP / TAG_MAP / CVE_TECHNIQUE_MAP
without changing mapping logic.
"""

from __future__ import annotations

from typing import Dict, NamedTuple


class Technique(NamedTuple):
    id: str
    name: str
    tactic: str
    description: str
    max_signals: int  # denominator for confidence calculation


TECHNIQUES: dict[str, Technique] = {
    "T1059": Technique(
        "T1059", "Command and Scripting Interpreter", "Execution",
        "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        3,
    ),
    "T1071": Technique(
        "T1071", "Application Layer Protocol", "Command and Control",
        "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering.",
        3,
    ),
    "T1090": Technique(
        "T1090", "Proxy", "Command and Control",
        "Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary.",
        3,
    ),
    "T1090.003": Technique(
        "T1090.003", "Tor", "Command and Control",
        "Adversaries may use the Tor network to hide the routing of network traffic.",
        2,
    ),
    "T1021.001": Technique(
        "T1021.001", "Remote Desktop Protocol", "Lateral Movement",
        "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP).",
        2,
    ),
    "T1021.002": Technique(
        "T1021.002", "SMB/Windows Admin Shares", "Lateral Movement",
        "Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB).",
        2,
    ),
    "T1021.004": Technique(
        "T1021.004", "SSH", "Lateral Movement",
        "Adversaries may use Valid Accounts to log into remote machines via SSH.",
        2,
    ),
    "T1048": Technique(
        "T1048", "Exfiltration Over Alternative Protocol", "Exfiltration",
        "Adversaries may steal data by exfiltrating it over a different protocol than the existing C2 channel.",
        2,
    ),
    "T1566": Technique(
        "T1566", "Phishing", "Initial Access",
        "Adversaries may send phishing messages to gain access to victim systems.",
        3,
    ),
    "T1190": Technique(
        "T1190", "Exploit Public-Facing Application", "Initial Access",
        "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program.",
        2,
    ),
    "T1055": Technique(
        "T1055", "Process Injection", "Defense Evasion",
        "Adversaries may inject code into processes to evade process-based defenses or elevate privileges.",
        2,
    ),
    "T1496": Technique(
        "T1496", "Resource Hijacking", "Impact",
        "Adversaries may leverage resources of co-opted systems for resource-intensive tasks (e.g. crypto-mining).",
        2,
    ),
    "T1046": Technique(
        "T1046", "Network Service Discovery", "Discovery",
        "Adversaries may attempt to get a listing of services running on remote hosts.",
        2,
    ),
}

# ── Signal Maps: raw OSINT signals → MITRE technique IDs ──

PORT_MAP: dict[int, str] = {
    3389: "T1021.001",  # RDP
    445: "T1021.002",   # SMB
    139: "T1021.002",   # SMB (NetBIOS)
    22: "T1021.004",    # SSH
    21: "T1021.004",    # FTP
    23: "T1021.004",    # Telnet
}

TAG_MAP: dict[str, str] = {
    "proxy": "T1090",
    "tor": "T1090.003",
    "vpn": "T1090",
    "botnet": "T1071",
    "c2": "T1071",
    "phishing": "T1566",
    "backdoor": "T1090",
    "miner": "T1496",
    "malicious": "T1055",
    "trojan": "T1055",
    "rat": "T1071",
    "worm": "T1055",
}

CVE_TECHNIQUE_MAP: dict[str, str] = {
    "CVE-2021-44228": "T1190",   # Log4Shell
    "CVE-2021-26855": "T1190",   # ProxyLogon
    "CVE-2023-23397": "T1566",   # Outlook elevation of privilege
    "CVE-2024-3094": "T1055",    # XZ Utils backdoor
    "CVE-2017-0144": "T1190",    # EternalBlue
    "CVE-2019-0708": "T1021.001", # BlueKeep (RDP)
}
