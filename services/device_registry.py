# services/device_registry.py
"""
Level 150: Device Registry — LAN Discovery + Persistent Trust Store
JSON-backed registry of known network devices with hostname resolution.
"""

import asyncio
import json
import logging
import re
import socket
import subprocess
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

_REGISTRY_PATH = str(Path(__file__).parent.parent / "config" / "trusted_devices.json")


def load_registry() -> dict[str, dict]:
    """טוען את רשימת המכשירים המוכרים מ-JSON."""
    try:
        with open(_REGISTRY_PATH, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(
            "[DeviceRegistry] trusted_devices.json not found at %s — "
            "copy config/trusted_devices.example.json to config/trusted_devices.json and edit it",
            _REGISTRY_PATH,
        )
        return {}
    except json.JSONDecodeError as exc:
        logger.error("[DeviceRegistry] Invalid JSON in %s: %s", _REGISTRY_PATH, exc)
        return {}


def save_registry(registry: dict[str, dict]) -> None:
    """שומר את הרשימה ל-JSON."""
    with open(_REGISTRY_PATH, "w", encoding="utf-8") as f:
        json.dump(registry, f, ensure_ascii=False, indent=2)


def resolve_hostname(ip: str) -> str:
    """Reverse DNS — מחזיר שם מארח או את ה-IP אם נכשל."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return ip


async def resolve_hostname_async(ip: str) -> str:
    """גרסה אסינכרונית של Reverse DNS — לא חוסמת את ה-event loop."""
    return await asyncio.to_thread(resolve_hostname, ip)


def scan_arp_table() -> list[tuple[str, str]]:
    """
    מנתח את טבלת ה-ARP של Windows (arp -a).
    מחזיר רשימה של (ip, mac) לכל מכשיר ב-LAN.
    מסנן broadcast ו-multicast.
    """
    results = []
    try:
        output = subprocess.check_output(
            ["arp", "-a"],
            text=True,
            timeout=5,
            creationflags=0x08000000,
        )
        for line in output.splitlines():
            match = re.search(
                r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\da-f\-]{17})",
                line.lower(),
            )
            if match:
                ip, mac = match.group(1), match.group(2)
                if not ip.endswith(".255") and not ip.startswith("224."):
                    results.append((ip, mac))
    except Exception as e:
        logger.error(f"[DeviceRegistry] ARP scan failed: {e}")
    return results


async def auto_discover_lan() -> int:
    """
    סורק את ה-ARP table, מזהה שמות וממלא את ה-registry אוטומטית.
    מכשירים שכבר ברשימה לא נדרסים.
    מחזיר מספר מכשירים חדשים שנרשמו.
    """
    devices = await asyncio.to_thread(scan_arp_table)
    registry = load_registry()
    new_count = 0
    for ip, mac in devices:
        if ip not in registry:
            name = await resolve_hostname_async(ip)
            registry[ip] = {
                "name": name,
                "mac": mac,
                "added": datetime.now().strftime("%d/%m/%Y %H:%M"),
                "auto": True,
            }
            new_count += 1
            logger.info(f"[DeviceRegistry] Auto-discovered: {ip} → {name}")
    if new_count:
        save_registry(registry)
    logger.info(f"[DeviceRegistry] Scan complete: {len(devices)} devices, {new_count} new.")
    return new_count
