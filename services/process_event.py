# services/process_event.py
"""ProcessEvent — unified process telemetry model.

Bridges two ingestion sources into a single dataclass:

  - **psutil polling** (existing): fills pid, name, cmdline. Sysmon-only
    fields (parent_image, sha256, signed, integrity_level, user) are None.
  - **Sysmon Event 1** (new): fills all fields — kernel-level telemetry
    richer than psutil can provide (parent chain, hash, signature, integrity).

The Sysmon source is strictly stronger: process hollowing can lie to
psutil's user-space API, but Sysmon hooks at the kernel ETW layer. See
`services/sysmon_consumer.py` for the ingestion path and
`services/agent/_provenance.py` for the trust tier (kernel-trusted > trusted).

`analyze_process_event(event)` is the wrapper that:
  1. Always runs `analyze_cmdline(event.cmdline)` (the existing regex engine,
     unchanged — 22 call sites stay valid).
  2. Adds 4 checks that require Sysmon fields (parent anomaly, hash
     reputation, integrity level, unsigned masquerading). Each check
     gracefully degrades to a skip when its required field is None
     (psutil path), so the wrapper never throws on missing data.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProcessEvent:
    """Unified process telemetry from psutil or Sysmon.

    Required fields (always present, both sources):
        pid, name, cmdline

    Sysmon-enriched fields (None when source is psutil or when Sysmon
    could not compute them — e.g. hash timeout on a very large binary):

        image            — full executable path (Sysmon: Image field)
        parent_pid       — parent process PID
        parent_image     — parent executable path (key for T1059.005)
        sha256           — file hash (Sysmon Hashes field, SHA256 algo)
        signed           — Authenticode signature present
        integrity_level  — Mandatory Integrity Level string
        user             — account SID or DOMAIN\\user

    source — "sysmon" or "psutil", used for provenance/trust tier and
        for deciding which enriched checks are eligible to run.

    All Sysmon-enriched fields default to None so a psutil-derived event
    is constructed with just `ProcessEvent(pid=..., name=..., cmdline=...)`.
    """

    pid: int
    name: str
    cmdline: str
    source: str = "psutil"
    image: str | None = None
    parent_pid: int | None = None
    parent_image: str | None = None
    sha256: str | None = None
    signed: bool | None = None
    integrity_level: str | None = None
    user: str | None = None

    @property
    def is_sysmon_sourced(self) -> bool:
        """True when this event came from Sysmon (kernel telemetry)."""
        return self.source == "sysmon"
