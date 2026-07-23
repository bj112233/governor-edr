"""Compare full vs truncated system prompts for tool calling accuracy."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Temporarily patch the system prompt
import services.agent as agent_module
from services.agent import run_agent

TEST_QUERIES = [
    "מזג אוויר בתל אביב",
    "100 דולר לשקל",
    "מחיר NVDA",
    "חדשות ארציות",
    "דוח יומי על המערכת",
]


async def test_with_prompt(_prompt_name: str, prompt_text: str) -> list[dict]:
    """Test all queries with a specific system prompt."""
    original = agent_module._AGENT_SYSTEM
    agent_module._AGENT_SYSTEM = prompt_text + "\n\n" + agent_module._load_context_files()

    results = []
    for q in TEST_QUERIES:
        try:
            response = await run_agent(q)
            results.append(
                {
                    "query": q,
                    "success": True,
                    "response_preview": str(response)[:150],
                    "has_tool_call": "skill_" in str(response) or "get_" in str(response),
                }
            )
        except Exception as e:
            results.append(
                {
                    "query": q,
                    "success": False,
                    "error": str(e)[:100],
                    "has_tool_call": False,
                }
            )

    agent_module._AGENT_SYSTEM = original
    return results


async def main():
    # Load truncated prompt
    from services.agent_truncated_prompt import _AGENT_SYSTEM_TRUNCATED

    print("Testing with FULL prompt (127 lines)...")
    full_results = await test_with_prompt("FULL", agent_module._AGENT_SYSTEM)

    print("\nTesting with TRUNCATED prompt (40 lines)...")
    trunc_results = await test_with_prompt("TRUNCATED", _AGENT_SYSTEM_TRUNCATED)

    # Compare
    comparison = []
    for i, (f, t) in enumerate(zip(full_results, trunc_results)):
        comparison.append(
            {
                "query": f["query"],
                "full_success": f["success"],
                "trunc_success": t["success"],
                "full_has_tool": f.get("has_tool_call", False),
                "trunc_has_tool": t.get("has_tool_call", False),
                "identical": f["success"] == t["success"] and f.get("has_tool_call") == t.get("has_tool_call"),
            }
        )

    # Summary
    full_tool_calls = sum(1 for r in full_results if r.get("has_tool_call"))
    trunc_tool_calls = sum(1 for r in trunc_results if r.get("has_tool_call"))

    print("\n=== SUMMARY ===")
    print(f"Full prompt: {full_tool_calls}/{len(TEST_QUERIES)} tool calls")
    print(f"Truncated prompt: {trunc_tool_calls}/{len(TEST_QUERIES)} tool calls")
    print(f"Identical behavior: {sum(1 for c in comparison if c['identical'])}/{len(comparison)}")

    with open("state/prompt_comparison_results.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "full_results": full_results,
                "trunc_results": trunc_results,
                "comparison": comparison,
                "summary": {
                    "full_tool_calls": full_tool_calls,
                    "trunc_tool_calls": trunc_tool_calls,
                    "identical_behavior": sum(1 for c in comparison if c["identical"]),
                },
            },
            f,
            ensure_ascii=False,
            indent=2,
        )

    print("\nSaved to state/prompt_comparison_results.json")


if __name__ == "__main__":
    asyncio.run(main())
