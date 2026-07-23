"""Test hybrid routing: semantic + keyword merge (CVE-2025-53000 routing fix)."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import services.agent.routing.embeddings as _emb_mod
import services.agent.routing.skill_router as _skill_mod
import services.embedding_service as embed_mod
from services.agent import routing


def _make_skill(name: str) -> dict:
    return {"type": "function", "function": {"name": name}}


async def test_keyword_ocr_triggers_file_analyst():
    """When semantic is OFF, keyword 'ocr' must return file-analyst."""
    orig_semantic_ready = _emb_mod._SEMANTIC_READY
    _emb_mod._SEMANTIC_READY = False

    try:
        skills = [
            _make_skill("skill_file-analyst"),
            _make_skill("skill_translator-skill"),
            _make_skill("skill_currency-skill"),
        ]
        result = await routing._filter_relevant_skills("תריץ עליה ocr", skills, max_skills=12)
        names = [s["function"]["name"] for s in result]
        assert "skill_file-analyst" in names, f"Expected file-analyst in {names}"
        print("PASS: keyword 'ocr' -> file-analyst")
    finally:
        _emb_mod._SEMANTIC_READY = orig_semantic_ready


async def test_hybrid_merge_dedup():
    """Semantic returns translator; keyword returns file-analyst. Merge must have both."""
    orig_semantic_ready = _emb_mod._SEMANTIC_READY
    orig_embeddings = _emb_mod._SKILL_EMBEDDINGS
    _emb_mod._SEMANTIC_READY = True
    _emb_mod._SKILL_EMBEDDINGS = {
        "skill_translator-skill": [0.1, 0.2, 0.3],
        "skill_currency-skill": [0.4, 0.5, 0.6],
    }

    # Mock cosine_similarity to return deterministic scores
    orig_cosine = _skill_mod.cosine_similarity
    _skill_mod.cosine_similarity = lambda a, b: 0.95 if b == [0.1, 0.2, 0.3] else 0.85

    # Mock embed service — imported locally inside function
    class FakeEmbed:
        async def embed(self, texts):
            return [[0.1, 0.2, 0.3]]

    orig_get_svc = embed_mod.get_embedding_service
    embed_mod.get_embedding_service = FakeEmbed

    try:
        skills = [
            _make_skill("skill_file-analyst"),
            _make_skill("skill_translator-skill"),
            _make_skill("skill_currency-skill"),
        ]
        result = await routing._filter_relevant_skills("תריץ עליה ocr", skills, max_skills=12)
        names = [s["function"]["name"] for s in result]

        assert "skill_translator-skill" in names, f"Expected translator from semantic: {names}"
        assert "skill_file-analyst" in names, f"Expected file-analyst from keyword 'ocr': {names}"
        assert len(names) == len(set(names)), f"Duplicates found: {names}"
        print(f"PASS: hybrid merge -> {names}")
    finally:
        _emb_mod._SEMANTIC_READY = orig_semantic_ready
        _emb_mod._SKILL_EMBEDDINGS = orig_embeddings
        _skill_mod.cosine_similarity = orig_cosine
        embed_mod.get_embedding_service = orig_get_svc


def test_merge_interleave_prevents_semantic_starvation():
    """Keyword over-match must not shut out semantically relevant tools.

    Reproduces the 2026-06-25 night-run bug: a threat-hunt query matched 9
    tools via keywords, filling all 5 slots (max_tools=5). get_firewall_drops
    — semantically relevant but lacking exact keyword match — was starved out.
    Interleaving guarantees semantic hits get ~40% of slots.
    """
    from services.agent.routing.tool_router import _merge_tool_results

    keyword_hits = [
        "get_system_snapshot",
        "get_process_list",
        "get_external_connections",
        "get_disk_details",
        "terminate_process",
        "get_event_log",
        "get_services",
        "get_listening_ports",
        "get_local_users",
    ]
    semantic_hits = [
        "get_firewall_drops",
        "get_system_snapshot",
        "get_process_list",
        "get_external_connections",
        "get_disk_details",
        "terminate_process",
        "get_event_log",
        "get_services",
        "get_listening_ports",
        "get_local_users",
    ]
    result = _merge_tool_results(keyword_hits, semantic_hits, max_tools=5)

    assert "get_firewall_drops" in result, f"Semantic hit get_firewall_drops starved by keyword over-match: {result}"
    assert len(result) == 5, f"Expected 5 tools, got {len(result)}: {result}"
    assert len(result) == len(set(result)), f"Duplicates: {result}"
    # Keyword primacy: first tool must be the top keyword hit
    assert result[0] == "get_system_snapshot"
    print(f"PASS: interleave prevents semantic starvation -> {result}")


if __name__ == "__main__":
    asyncio.run(test_keyword_ocr_triggers_file_analyst())
    asyncio.run(test_hybrid_merge_dedup())
    test_merge_interleave_prevents_semantic_starvation()
    print("\nAll routing tests passed.")
