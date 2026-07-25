# services/sysmon_xml.py
"""Sysmon Event 1 XML → ProcessEvent adapter.

Parses Sysmon Event 1 (Process Create) XML from Windows Event Log and
converts it to a `ProcessEvent` with all enriched fields populated.

Robustness: the parser is wrapped in try/except so a single malformed
event cannot kill the consumer thread (which runs EvtSubscribe callback
on a separate thread — uncaught exceptions there don't reach the main
log handler). On parse failure, returns None and logs the error.

The XML comes from the Windows Event Log channel
`Microsoft-Windows-Sysmon/Operational`. Event 1 schema:
  EventData fields: RuleName, UtcTime, ProcessGuid, ProcessId, Image,
    FileVersion, Description, Product, Company, OriginalFileName,
    CommandLine, CurrentDirectory, User, LogonGuid, LogonId,
    TerminalSessionId, IntegrityLevel, Hashes, ParentProcessGuid,
    ParentProcessId, ParentImage, ParentCommandLine, ParentUser

Hashes field format: "SHA256=<hex>,IMPHASH=<hex>" (algorithm depends on
Sysmon config; we extract SHA256 specifically).
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Optional

from services.process_event import ProcessEvent

logger = logging.getLogger(__name__)

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _ns(tag: str) -> str:
    """Build a namespaced tag for Event XML schema."""
    return f"{{{_NS}}}{tag}"


def _extract_event_data(root: ET.Element) -> dict[str, str]:
    """Extract EventData Name→Value pairs from the Event root.

    Returns a dict mapping field names to their string values. Fields
    with value "-" (Sysmon's "no value" marker) are kept as-is; the
    caller decides whether "-" means None for its purposes.
    """
    data: dict[str, str] = {}
    event_data = root.find(f".//{_ns('EventData')}")
    if event_data is None:
        return data
    for data_elem in event_data.findall(_ns("Data")):
        name = data_elem.get("Name", "")
        if not name:
            continue
        data[name] = data_elem.text or ""
    return data


def _parse_sha256(hashes_field: str) -> str | None:
    """Extract SHA256 hash from the Hashes field.

    Format: "SHA256=<hex>,IMPHASH=<hex>" or just "SHA256=<hex>".
    Returns None if SHA256 is not present or field is empty/"-".
    """
    if not hashes_field or hashes_field == "-":
        return None
    for part in hashes_field.split(","):
        part = part.strip()
        if part.upper().startswith("SHA256="):
            hex_val = part[len("SHA256="):].strip()
            # SHA256 is 64 hex chars; validate length to catch truncation
            if len(hex_val) == 64:
                return hex_val.lower()
    return None


def _parse_integrity_level(level_field: str) -> str | None:
    """Parse IntegrityLevel field. Returns None if empty or '-'."""
    if not level_field or level_field == "-":
        return None
    return level_field.strip()


def _parse_pid(pid_field: str) -> int | None:
    """Parse a PID field. Returns None if empty/'-' or non-numeric."""
    if not pid_field or pid_field == "-":
        return None
    try:
        return int(pid_field)
    except ValueError:
        logger.warning("[sysmon_xml] non-numeric PID field: %r", pid_field)
        return None


def parse_event1_xml(xml_str: str) -> ProcessEvent | None:
    """Parse a Sysmon Event 1 XML string into a ProcessEvent.

    Returns None on any parse failure (malformed XML, missing required
    fields, unexpected schema). The caller MUST handle None by skipping
    the event — never let a None propagate silently.

    Args:
        xml_str: Raw XML string from win32evtlog.EvtRender(EventXml).

    Returns:
        ProcessEvent with source="sysmon" and all available fields, or
        None if the event could not be parsed.
    """
    if not xml_str or not xml_str.strip():
        logger.warning("[sysmon_xml] empty XML string passed to parser")
        return None

    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        # Malformed XML — log with a snippet so it's debuggable, but
        # do NOT re-raise. The consumer thread must survive this.
        snippet = xml_str[:200].replace("\n", " ")
        logger.warning("[sysmon_xml] XML parse error: %s | snippet: %s", e, snippet)
        return None

    try:
        data = _extract_event_data(root)

        # Required fields — if any missing, the event is unusable
        pid = _parse_pid(data.get("ProcessId", ""))
        cmdline = data.get("CommandLine", "")
        image = data.get("Image", "")

        if pid is None:
            logger.warning("[sysmon_xml] Event 1 missing ProcessId — skipping")
            return None

        # name: derive from Image (basename) — Sysmon Image is full path
        name = image.split("\\")[-1] if image else data.get("OriginalFileName", "")

        parent_pid = _parse_pid(data.get("ParentProcessId", ""))
        parent_image = data.get("ParentImage", "")
        if parent_image == "-":
            parent_image = ""

        sha256 = _parse_sha256(data.get("Hashes", ""))
        integrity_level = _parse_integrity_level(data.get("IntegrityLevel", ""))
        user = data.get("User", "")
        if user == "-":
            user = ""

        # signed: Sysmon Event 1 does not include signature info by default.
        # This field is populated by a different event type (Image Load, ID 7)
        # or by a Sysmon config that enables Signature tracking. For Event 1,
        # signed stays None — the wrapper's unsigned-masquerading check will
        # skip when signed is None (cannot determine).
        signed: bool | None = None

        return ProcessEvent(
            pid=pid,
            name=name,
            cmdline=cmdline,
            source="sysmon",
            image=image or None,
            parent_pid=parent_pid,
            parent_image=parent_image or None,
            sha256=sha256,
            signed=signed,
            integrity_level=integrity_level,
            user=user or None,
        )
    except Exception as e:
        # Catch-all for unexpected schema drift or field type mismatches.
        # The consumer thread's survival is more important than re-raising.
        snippet = xml_str[:200].replace("\n", " ")
        logger.exception("[sysmon_xml] unexpected error parsing Event 1: %s | snippet: %s", e, snippet)
        return None
