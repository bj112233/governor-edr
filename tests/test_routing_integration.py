# tests/test_routing_integration.py
"""Integration smoke tests — verify full pipeline: pre-compute → visibility → flat args.

These tests verify the end-to-end flow without requiring a live LLM:
1. IOC query → pre-compute enriches + intent detected + OSINT tools filtered
2. Non-IOC query → no enrichment + OSINT tools hidden
3. CVE query → CVE bypass + OSINT intent mode
4. Process query → system intent + OSINT hidden
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from services.agent.routing.intent_routers import detect_intent
from services.pre_compute_router import format_pre_compute_facts, pre_compute
from services.tools.flat_args import get_flat_schema, is_flat_tool, normalize_flat_args
from services.tools.tool_visibility import filter_tools_by_intent


def _make_tool(name: str) -> dict:
    return {"type": "function", "function": {"name": name, "description": f"tool {name}", "parameters": {}}}


class TestPipelineIOCQuery:
    """IOC query → pre-compute enriches + intent=osint + visibility filters."""

    @pytest.mark.asyncio
    async def test_ioc_query_full_pipeline(self):
        # 1. Intent detection (pure IOC)
        intent = detect_intent("8.8.8.8")
        assert intent["intent"] == "ioc"

        # 2. Pre-compute (with mocked enrichment) — IOC extraction finds IP in sentence
        mock_data = {
            "score": 95,
            "abuse": {"country": "US"},
            "virustotal": {"available": True, "found": True, "malicious": 10},
        }
        with patch("services.pre_compute_router.enrich_ip", new_callable=AsyncMock) as mock_enrich:
            mock_enrich.return_value = mock_data
            report = await pre_compute("check 8.8.8.8 reputation")

        assert "8.8.8.8" in report.enriched
        # Intent may be None for sentence queries (detect_intent matches pure patterns)
        # but IOC extraction + enrichment still fires

        # 3. Hard facts injected
        facts = format_pre_compute_facts(report)
        assert "8.8.8.8" in facts
        assert "MALICIOUS" in facts

        # 4. Tool visibility — use pure IOC intent for visibility test
        tools = [
            _make_tool("final_answer"),
            _make_tool("osint_hunt"),
            _make_tool("get_process_list"),
            _make_tool("block_ip"),
            _make_tool("scan_infrastructure"),
        ]
        filtered = filter_tools_by_intent(tools, "ioc")
        names = [t["function"]["name"] for t in filtered]
        assert "osint_hunt" in names
        assert "get_process_list" not in names
        assert "block_ip" not in names
        assert "scan_infrastructure" not in names  # engine-in-engine: only osint_hunt


class TestPipelineNonIOCQuery:
    """Non-IOC query → no enrichment + OSINT tools hidden."""

    @pytest.mark.asyncio
    async def test_general_query_no_enrichment(self):
        with patch("services.pre_compute_router.enrich_ip", new_callable=AsyncMock) as mock_enrich:
            report = await pre_compute("what is the weather today")
        assert not report.enriched
        mock_enrich.assert_not_called()

        # OSINT tools hidden in general mode
        tools = [_make_tool("final_answer"), _make_tool("osint_hunt"), _make_tool("get_process_list")]
        filtered = filter_tools_by_intent(tools, None)
        names = [t["function"]["name"] for t in filtered]
        assert "osint_hunt" not in names
        assert "get_process_list" in names


class TestPipelineCVEQuery:
    """CVE query → CVE intent + OSINT mode."""

    def test_cve_intent_detected(self):
        intent = detect_intent("CVE-2024-3094")
        assert intent["intent"] == "cve"
        assert intent["tool"] == "osint_hunt"

    def test_cve_visibility_osint_mode(self):
        tools = [
            _make_tool("final_answer"),
            _make_tool("osint_hunt"),
            _make_tool("get_process_list"),
            _make_tool("block_ip"),
        ]
        filtered = filter_tools_by_intent(tools, "cve")
        names = [t["function"]["name"] for t in filtered]
        assert "osint_hunt" in names
        assert "get_process_list" not in names
        assert "block_ip" not in names


class TestPipelineProcessQuery:
    """Process query → system/security intent + OSINT hidden."""

    def test_process_list_intent(self):
        intent = detect_intent("show running processes")
        assert intent["intent"] == "process_list"

    def test_process_list_visibility_hides_osint(self):
        tools = [
            _make_tool("final_answer"),
            _make_tool("get_process_list"),
            _make_tool("osint_hunt"),
            _make_tool("block_ip"),
        ]
        filtered = filter_tools_by_intent(tools, "process_list")
        names = [t["function"]["name"] for t in filtered]
        assert "get_process_list" in names
        assert "osint_hunt" not in names
        assert "block_ip" not in names


class TestPipelineFlatArgs:
    """Flat args: schema flattened + normalization works for model-emitted args."""

    def test_manage_service_flat_schema(self):
        original = {
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "start|stop|restart"},
                "name": {"type": "string", "description": "Service name"},
            },
            "required": ["action", "name"],
        }
        flat = get_flat_schema("manage_service", original)
        assert set(flat["properties"].keys()) == {"action", "name"}

    def test_manage_service_normalize_synonyms(self):
        """Model emits service_name instead of name → normalized."""
        args = {"action": "stop", "service_name": "wuauserv"}
        result = normalize_flat_args("manage_service", args)
        assert result == {"action": "stop", "name": "wuauserv"}

    def test_non_flat_tool_unchanged(self):
        assert not is_flat_tool("get_process_list")
        assert get_flat_schema("get_process_list", {"x": 1}) == {"x": 1}
