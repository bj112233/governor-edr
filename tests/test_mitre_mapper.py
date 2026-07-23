"""Tests for services/mitre_mapper.py -- MITRE ATT&CK mapping engine."""

from datetime import UTC, datetime, timedelta

from services.mitre_mapper import (
    MitreMatch,
    format_mitre_section,
    lookup_technique,
    map_cves_to_mitre,
    map_payload_to_mitre,
    serialize_mitre,
)


class TestMapCvesToMitre:
    def test_known_cve_maps(self):
        matches = map_cves_to_mitre(["CVE-2021-44228"])
        assert len(matches) == 1
        assert matches[0].technique_id == "T1190"
        assert matches[0].confidence == 1.0

    def test_unknown_cve_no_match(self):
        matches = map_cves_to_mitre(["CVE-2099-9999"])
        assert len(matches) == 0

    def test_multiple_cves_same_technique(self):
        matches = map_cves_to_mitre(["CVE-2021-44228", "CVE-2017-0144"])
        assert len(matches) == 1
        assert matches[0].technique_id == "T1190"
        assert len(matches[0].signals) == 2


class TestMapPayloadToMitre:
    def test_threatfox_feed_hit_maps_to_t1071(self):
        payload = {
            "threat_feeds": {"matched": True, "threatfox": True, "threat_type": "botnet_cc", "malware": "Emotet"}
        }
        matches = map_payload_to_mitre(payload)
        tech_ids = [m.technique_id for m in matches]
        assert "T1071" in tech_ids

    def test_urlhaus_feed_hit_maps_to_t1566(self):
        payload = {"threat_feeds": {"matched": True, "urlhaus": True, "malware": "phishing_loader"}}
        matches = map_payload_to_mitre(payload)
        tech_ids = [m.technique_id for m in matches]
        assert "T1566" in tech_ids

    def test_port_3389_maps_to_rdp(self):
        payload = {"sources": {"shodan": {"available": True, "ports": [3389]}}}
        matches = map_payload_to_mitre(payload)
        assert any(m.technique_id == "T1021.001" for m in matches)

    def test_tor_flag_maps_to_t1090_003(self):
        payload = {"sources": {"ipapi_co": {"available": True, "tor": True}}}
        matches = map_payload_to_mitre(payload)
        assert any(m.technique_id == "T1090.003" for m in matches)

    def test_newly_registered_domain_maps_to_t1566(self):
        recent = (datetime.now(UTC) - timedelta(days=5)).strftime("%Y-%m-%dT00:00:00Z")
        payload = {"sources": {"rdap": {"available": True, "registered": recent}}}
        matches = map_payload_to_mitre(payload)
        assert any(m.technique_id == "T1566" for m in matches)

    def test_old_domain_no_t1566(self):
        payload = {"sources": {"rdap": {"available": True, "registered": "2020-01-01T00:00:00Z"}}}
        matches = map_payload_to_mitre(payload)
        assert not any(m.technique_id == "T1566" for m in matches)

    def test_shodan_vulns_map_to_t1190(self):
        payload = {"sources": {"shodan": {"available": True, "vulns": ["CVE-2021-44228"]}}}
        matches = map_payload_to_mitre(payload)
        assert any(m.technique_id == "T1190" for m in matches)

    def test_empty_payload_no_matches(self):
        matches = map_payload_to_mitre({})
        assert len(matches) == 0

    def test_results_sorted_by_confidence(self):
        payload = {
            "threat_feeds": {"matched": True, "threatfox": True, "urlhaus": True, "threat_type": "botnet_cc"},
            "sources": {"shodan": {"available": True, "ports": [3389]}},
        }
        matches = map_payload_to_mitre(payload)
        confidences = [m.confidence for m in matches]
        assert confidences == sorted(confidences, reverse=True)

    def test_intel_enricher_format_tags(self):
        """Top-level keys (intel_enricher format) should also be scanned for tags."""
        payload = {"virustotal": {"tags": ["trojan", "backdoor"]}}
        matches = map_payload_to_mitre(payload)
        tech_ids = {m.technique_id for m in matches}
        assert "T1055" in tech_ids  # trojan -> T1055
        assert "T1090" in tech_ids  # backdoor -> T1090


class TestFormatMitreSection:
    def test_empty_returns_empty(self):
        assert format_mitre_section([]) == ""

    def test_formats_technique(self):
        matches = [MitreMatch("T1071", "Application Layer Protocol", "Command and Control", 0.67, ["signal1"])]
        text = format_mitre_section(matches)
        assert "T1071" in text
        assert "Application Layer Protocol" in text
        assert "0.67" in text
        assert "signal1" in text

    def test_caps_signals_at_3(self):
        matches = [MitreMatch("T1071", "C2", "C2", 1.0, ["s1", "s2", "s3", "s4", "s5"])]
        text = format_mitre_section(matches)
        assert "s4" not in text
        assert "s5" not in text


class TestSerializeMitre:
    def test_serializes_to_dicts(self):
        matches = [MitreMatch("T1071", "C2", "Command and Control", 0.5, ["sig"])]
        dicts = serialize_mitre(matches)
        assert len(dicts) == 1
        assert dicts[0]["technique_id"] == "T1071"
        assert dicts[0]["name"] == "C2"
        assert dicts[0]["confidence"] == 0.5
        assert dicts[0]["signals"] == ["sig"]

    def test_empty_list(self):
        assert serialize_mitre([]) == []


class TestLookupTechnique:
    def test_case_insensitive(self):
        tech = lookup_technique("t1071")
        assert tech is not None
        assert tech.id == "T1071"

    def test_unknown_returns_none(self):
        assert lookup_technique("T9999") is None
