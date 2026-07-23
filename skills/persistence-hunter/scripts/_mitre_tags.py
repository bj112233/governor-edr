"""MITRE ATT&CK technique tags for persistence vectors."""

MITRE_TAGS: dict[str, str] = {
    "T1547.001": "Boot/Logon Autostart: Registry Run Keys",
    "T1547.004": "Boot/Logon Autostart: Startup Folders",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1546.003": "Event Triggered Execution: WMI Event Subscription",
}
