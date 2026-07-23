"""Tests for MITRE ATT&CK mapping engine + cmd_attack + renderer integration.

Validates deterministic signal-to-technique mapping, confidence scoring,
CVE associations, and Markdown rendering.
"""

import json
import sys
from pathlib import Path

_SCRIPTS = str(Path(__file__).resolve().parents[1] / "skills" / "intel-skill" / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

from datetime import UTC

from mitre_attack_db import CVE_TECHNIQUE_MAP, PORT_MAP, TAG_MAP, TECHNIQUES
from mitre_mapping import (
    MitreMatch,
    lookup_technique,
    map_cves_to_mitre,
    map_payload_to_mitre,
)

# ── Helpers ──


def _ip_payload(
    shodan_ports=None,
    shodan_vulns=None,
    ipapi_proxy=False,
    ipapi_tor=False,
    ipapi_vpn=False,
    maltiverse_tags=None,
    maltiverse_classification=None,
    vt_tags=None,
):
    """Build a realistic orchestrator-style IP payload."""
    shodan = {"available": True}
    if shodan_ports is not None:
        shodan["ports"] = shodan_ports
    if shodan_vulns is not None:
        shodan["vulns"] = shodan_vulns
    ipapi = {"available": True, "proxy": ipapi_proxy, "tor": ipapi_tor, "vpn": ipapi_vpn}
    maltiverse = {"available": True, "found": True}
    if maltiverse_tags is not None:
        maltiverse["tags"] = maltiverse_tags
    if maltiverse_classification is not None:
        maltiverse["classification"] = maltiverse_classification
    vt = {"available": True, "found": True}
    if vt_tags is not None:
        vt["tags"] = vt_tags
    return {
        "target": "1.2.3.4",
        "kind": "ip",
        "status": "success",
        "score": 50,
        "sources": {
            "shodan": shodan,
            "ipapi_co": ipapi,
            "maltiverse": maltiverse,
            "virustotal": vt,
        },
    }


def _domain_payload(rdap_registered=None, maltiverse_classification=None, vt_tags=None):
    """Build a realistic orchestrator-style domain payload."""
    rdap = {"available": True}
    if rdap_registered is not None:
        rdap["registered"] = rdap_registered
    maltiverse = {"available": True, "found": True}
    if maltiverse_classification is not None:
        maltiverse["classification"] = maltiverse_classification
    vt = {"available": True, "found": True}
    if vt_tags is not None:
        vt["tags"] = vt_tags
    return {
        "target": "evil.org",
        "kind": "domain",
        "status": "success",
        "score": 40,
        "sources": {"rdap": rdap, "maltiverse": maltiverse, "virustotal": vt},
    }


def _hash_payload(maltiverse_classification=None, vt_tags=None):
    """Build a realistic orchestrator-style hash payload."""
    maltiverse = {"available": True, "found": True}
    if maltiverse_classification is not None:
        maltiverse["classification"] = maltiverse_classification
    vt = {"available": True, "found": True}
    if vt_tags is not None:
        vt["tags"] = vt_tags
    return {
        "target": "a" * 64,
        "kind": "hash",
        "status": "success",
        "score": 90,
        "sources": {"maltiverse": maltiverse, "virustotal": vt},
    }


# ── Database tests ──


class TestDatabase:
    def test_techniques_populated(self):
        assert "T1059" in TECHNIQUES
        assert "T1071" in TECHNIQUES
        assert "T1090" in TECHNIQUES

    def test_port_map(self):
        assert PORT_MAP[3389] == "T1021.001"
        assert PORT_MAP[445] == "T1021.002"
        assert PORT_MAP[22] == "T1021.004"

    def test_tag_map(self):
        assert TAG_MAP["proxy"] == "T1090"
        assert TAG_MAP["tor"] == "T1090.003"
        assert TAG_MAP["phishing"] == "T1566"

    def test_cve_map(self):
        assert CVE_TECHNIQUE_MAP["CVE-2021-44228"] == "T1190"

    def test_lookup_technique_case_insensitive(self):
        tech = lookup_technique("t1059")
        assert tech is not None
        assert tech.id == "T1059"

    def test_lookup_unknown(self):
        assert lookup_technique("T9999") is None


# ── Mapping engine: IP signals ──


class TestIPMapping:
    def test_rdp_port_maps_to_lateral_movement(self):
        payload = _ip_payload(shodan_ports=[3389])
        matches = map_payload_to_mitre(payload)
        ids = [m.technique_id for m in matches]
        assert "T1021.001" in ids

    def test_proxy_flag_maps_to_proxy_technique(self):
        payload = _ip_payload(ipapi_proxy=True)
        matches = map_payload_to_mitre(payload)
        ids = [m.technique_id for m in matches]
        assert "T1090" in ids

    def test_tor_flag_maps_to_tor_subtechnique(self):
        payload = _ip_payload(ipapi_tor=True)
        matches = map_payload_to_mitre(payload)
        ids = [m.technique_id for m in matches]
        assert "T1090.003" in ids

    def test_vpn_flag_maps_to_proxy(self):
        payload = _ip_payload(ipapi_vpn=True)
        matches = map_payload_to_mitre(payload)
        ids = [m.technique_id for m in matches]
        assert "T1090" in ids

    def test_c2_tag_maps_to_app_layer_protocol(self):
        payload = _ip_payload(vt_tags=["c2", "botnet"])
        matches = map_payload_to_mitre(payload)
        ids = [m.technique_id for m in matches]
        assert "T1071" in ids

    def test_malicious_classification_maps_to_process_injection(self):
        payload = _ip_payload(maltiverse_classification="malicious")
        matches = map_payload_to_mitre(payload)
        ids = [m.technique_id for m in matches]
        assert "T1055" in ids

    def test_shodan_vulns_map_to_exploit_public_app(self):
        payload = _ip_payload(shodan_vulns=["CVE-2024-9999"])
        matches = map_payload_to_mitre(payload)
        ids = [m.technique_id for m in matches]
        assert "T1190" in ids

    def test_multiple_signals_produce_multiple_matches(self):
        payload = _ip_payload(
            shodan_ports=[3389, 445],
            ipapi_proxy=True,
            vt_tags=["c2"],
        )
        matches = map_payload_to_mitre(payload)
        ids = {m.technique_id for m in matches}
        assert "T1021.001" in ids
        assert "T1021.002" in ids
        assert "T1090" in ids
        assert "T1071" in ids

    def test_clean_ip_no_matches(self):
        payload = _ip_payload(shodan_ports=[80, 443])
        matches = map_payload_to_mitre(payload)
        assert matches == []


# ── Mapping engine: Domain signals ──


class TestDomainMapping:
    def test_new_domain_maps_to_phishing(self):
        from datetime import datetime, timedelta, timezone

        recent = (datetime.now(UTC) - timedelta(days=5)).isoformat()
        payload = _domain_payload(rdap_registered=recent)
        matches = map_payload_to_mitre(payload)
        ids = [m.technique_id for m in matches]
        assert "T1566" in ids

    def test_old_domain_no_phishing_signal(self):
        from datetime import datetime, timedelta, timezone

        old = (datetime.now(UTC) - timedelta(days=365)).isoformat()
        payload = _domain_payload(rdap_registered=old)
        matches = map_payload_to_mitre(payload)
        ids = [m.technique_id for m in matches]
        assert "T1566" not in ids

    def test_phishing_tag_maps_to_phishing(self):
        payload = _domain_payload(vt_tags=["phishing"])
        matches = map_payload_to_mitre(payload)
        ids = [m.technique_id for m in matches]
        assert "T1566" in ids


# ── Mapping engine: Hash signals ──


class TestHashMapping:
    def test_malicious_hash_maps_to_process_injection(self):
        payload = _hash_payload(maltiverse_classification="malicious")
        matches = map_payload_to_mitre(payload)
        ids = [m.technique_id for m in matches]
        assert "T1055" in ids

    def test_trojan_tag_maps_to_process_injection(self):
        payload = _hash_payload(vt_tags=["trojan"])
        matches = map_payload_to_mitre(payload)
        ids = [m.technique_id for m in matches]
        assert "T1055" in ids


# ── CVE mapping ──


class TestCVEMapping:
    def test_known_cve_maps_to_technique(self):
        matches = map_cves_to_mitre(["CVE-2021-44228"])
        assert len(matches) == 1
        assert matches[0].technique_id == "T1190"
        assert matches[0].confidence == 1.0

    def test_unknown_cve_no_match(self):
        matches = map_cves_to_mitre(["CVE-2099-9999"])
        assert matches == []

    def test_multiple_cves_same_technique_merged(self):
        matches = map_cves_to_mitre(["CVE-2021-44228", "CVE-2017-0144"])
        tech_ids = {m.technique_id for m in matches}
        assert "T1190" in tech_ids


# ── Confidence scoring ──


class TestConfidence:
    def test_single_signal_low_confidence(self):
        payload = _ip_payload(ipapi_proxy=True)
        matches = map_payload_to_mitre(payload)
        proxy_match = [m for m in matches if m.technique_id == "T1090"][0]
        # T1090 max_signals=3, 1 signal → 1/3 ≈ 0.33
        assert 0.0 < proxy_match.confidence <= 0.34

    def test_multiple_signals_higher_confidence(self):
        payload = _ip_payload(ipapi_proxy=True, ipapi_vpn=True, vt_tags=["backdoor"])
        matches = map_payload_to_mitre(payload)
        proxy_match = [m for m in matches if m.technique_id == "T1090"][0]
        # 3 signals (proxy, vpn, backdoor) → 3/3 = 1.0
        assert proxy_match.confidence == 1.0

    def test_confidence_capped_at_1(self):
        payload = _ip_payload(
            shodan_ports=[3389],
            ipapi_proxy=True,
            ipapi_tor=True,
            ipapi_vpn=True,
            vt_tags=["c2", "botnet", "backdoor"],
        )
        matches = map_payload_to_mitre(payload)
        for m in matches:
            assert m.confidence <= 1.0

    def test_results_sorted_by_confidence_desc(self):
        payload = _ip_payload(
            ipapi_proxy=True,
            ipapi_vpn=True,
            vt_tags=["backdoor"],
            shodan_ports=[3389],
        )
        matches = map_payload_to_mitre(payload)
        confidences = [m.confidence for m in matches]
        assert confidences == sorted(confidences, reverse=True)


# ── cmd_attack ──


class TestCmdAttack:
    def test_known_technique_markdown(self):
        from intel_commands import cmd_attack

        output = cmd_attack("T1059", "markdown")
        assert "T1059" in output
        assert "Command and Scripting Interpreter" in output
        assert "Execution" in output

    def test_known_technique_json(self):
        from intel_commands import cmd_attack

        output = cmd_attack("T1071", "json")
        parsed = json.loads(output)
        assert parsed["available"] is True
        assert parsed["technique_id"] == "T1071"
        assert "trigger_signals" in parsed

    def test_unknown_technique(self):
        from intel_commands import cmd_attack

        output = cmd_attack("T9999", "markdown")
        # Unknown techniques return JSON (skill sandbox requires JSON output).
        parsed = json.loads(output)
        assert parsed["available"] is False
        assert "Unknown technique: T9999" in parsed["error"]

    def test_attack_shows_trigger_signals(self):
        from intel_commands import cmd_attack

        output = cmd_attack("T1021.001", "markdown")
        assert "3389" in output  # RDP port in trigger signals


# ── Renderer integration ──


class TestRenderer:
    def test_mitre_section_appears_in_markdown(self):
        from renderer import IntelRenderer

        payload = _ip_payload(shodan_ports=[3389], ipapi_proxy=True)
        payload["mitre_techniques"] = [m.__dict__ for m in map_payload_to_mitre(payload)]
        renderer = IntelRenderer()
        output = renderer.render(payload)
        assert "MITRE ATT&CK Mapping" in output
        assert "T1021.001" in output
        assert "T1090" in output

    def test_no_mitre_section_when_empty(self):
        from renderer import IntelRenderer

        payload = _ip_payload(shodan_ports=[80, 443])
        payload["mitre_techniques"] = []
        renderer = IntelRenderer()
        output = renderer.render(payload)
        assert "MITRE ATT&CK Mapping" not in output

    def test_confidence_bar_rendered(self):
        from renderer import IntelRenderer

        payload = _ip_payload(ipapi_proxy=True, ipapi_vpn=True, vt_tags=["backdoor"])
        payload["mitre_techniques"] = [m.__dict__ for m in map_payload_to_mitre(payload)]
        renderer = IntelRenderer()
        output = renderer.render(payload)
        # Confidence bar uses █ and ░ characters
        assert "█" in output or "░" in output
