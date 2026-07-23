"""Firewall skill backends — FirewallBackend ABC, NetshBackend, NetSecurityBackend.

Extracted from firewall.py (SRP).
"""
from __future__ import annotations

import abc

from firewall_state import _FW_LOG, _NETSH_TIMEOUT, _run


class FirewallBackend(abc.ABC):
    """Abstract firewall backend for block/unblock/list operations."""

    @property
    @abc.abstractmethod
    def name(self) -> str: ...

    @abc.abstractmethod
    def add_rule(
        self, name: str, direction: str, action: str, remoteip: str,
        *, localport: str | None = None, protocol: str = "TCP",
    ) -> tuple[int, str, str]:
        """Return (rc, stdout, stderr). If localport is set, blocks by port instead of IP."""
        ...

    @abc.abstractmethod
    def delete_rule(self, name: str) -> tuple[int, str, str]: ...

    @abc.abstractmethod
    def list_rules(self) -> tuple[int, str, str]: ...

    @abc.abstractmethod
    def log_path(self) -> str: ...


class NetshBackend(FirewallBackend):
    """Legacy netsh advfirewall backend."""

    @property
    def name(self) -> str:
        return "netsh"

    def add_rule(
        self, name: str, direction: str, action: str, remoteip: str,
        *, localport: str | None = None, protocol: str = "TCP",
    ) -> tuple[int, str, str]:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f'name="{name}"', f"dir={direction}", f"action={action}",
        ]
        if localport:
            cmd += [f"protocol={protocol}", f"localport={localport}"]
        else:
            cmd += [f"remoteip={remoteip}"]
        return _run(cmd)

    def delete_rule(self, name: str) -> tuple[int, str, str]:
        return _run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f'name="{name}"']
        )

    def list_rules(self) -> tuple[int, str, str]:
        return _run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
            timeout=20,
        )

    def log_path(self) -> str:
        return _FW_LOG


class NetSecurityBackend(FirewallBackend):
    """PowerShell NetSecurity module backend (Windows 8+ / Server 2012+)."""

    @property
    def name(self) -> str:
        return "powershell"

    @staticmethod
    def _ps(cmd: str, timeout: int = _NETSH_TIMEOUT) -> tuple[int, str, str]:
        full = f"Import-Module NetSecurity; {cmd}"
        return _run(
            ["powershell.exe", "-NoProfile", "-Command", full],
            timeout=timeout,
        )

    def add_rule(
        self, name: str, direction: str, action: str, remoteip: str,
        *, localport: str | None = None, protocol: str = "TCP",
    ) -> tuple[int, str, str]:
        dir_map = {"in": "Inbound", "out": "Outbound"}
        ps_dir = dir_map.get(direction, direction)
        if localport:
            rc, out, err = self._ps(
                f"New-NetFirewallRule -Name '{name}' -DisplayName '{name}' "
                f"-Direction {ps_dir} -Action {action.capitalize()} "
                f"-Protocol {protocol} -LocalPort {localport} -Enabled True"
            )
        else:
            rc, out, err = self._ps(
                f"New-NetFirewallRule -Name '{name}' -DisplayName '{name}' "
                f"-Direction {ps_dir} -Action {action.capitalize()} "
                f"-RemoteAddress {remoteip} -Enabled True"
            )
        return rc, out, err

    def delete_rule(self, name: str) -> tuple[int, str, str]:
        return self._ps(
            f"Get-NetFirewallRule -Name '{name}' "
            f"-ErrorAction SilentlyContinue | Remove-NetFirewallRule"
        )

    def list_rules(self) -> tuple[int, str, str]:
        rc, out, err = self._ps(
            "Get-NetFirewallRule | Where-Object {{ $_.Name -like 'SENTINEL_BLOCK_*' }} | "
            "Select-Object Name, DisplayName, Direction, Action, Enabled | ConvertTo-Json -Compress"
        )
        if rc == 0 and not out.strip():
            out = "[]"
        return rc, out, err

    def log_path(self) -> str:
        return _FW_LOG


def _get_backend(name: str) -> FirewallBackend:
    if name == "powershell":
        return NetSecurityBackend()
    return NetshBackend()
