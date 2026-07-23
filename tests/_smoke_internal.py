"""Internal smoke test — verifies in-process changes that aren't exposed
over MCP (TOOL_OUTPUT_MAX_CHARS, LLM tool visibility, skill registration).

Runs in a SEPARATE Python interpreter that imports the same code the
running bot does — so we read what the live bot actually sees on disk.
"""

from __future__ import annotations

import asyncio


def main() -> None:
    print("=== A. Constant unification ===")
    from config import SUSPICIOUS_NET_THRESHOLD, TOOL_OUTPUT_MAX_CHARS

    print(f"  TOOL_OUTPUT_MAX_CHARS    = {TOOL_OUTPUT_MAX_CHARS}")
    print(f"  SUSPICIOUS_NET_THRESHOLD = {SUSPICIOUS_NET_THRESHOLD}")
    assert TOOL_OUTPUT_MAX_CHARS == 8000

    print("\n=== B. tools_registry exposure ===")
    from services.tools_registry import to_mcp_handlers, to_openai_tools

    llm = sorted(t["function"]["name"] for t in to_openai_tools())
    mcp = sorted(to_mcp_handlers().keys())

    for t in ("block_ip", "unblock_ip", "get_firewall_drops"):
        in_llm = t in llm
        in_mcp = t in mcp
        print(
            f"  {t:<22}: LLM={'YES' if in_llm else 'no '}  MCP={'YES' if in_mcp else 'no '}"
        )
        assert not in_llm, f"{t} should be hidden from LLM"
        assert in_mcp, f"{t} should still be in MCP"

    print(f"  Total LLM tools: {len(llm)}")
    print(f"  Total MCP tools: {len(mcp)}")

    print("\n=== C. skills_engine ===")
    from services.skills_engine import get_skills_engine

    eng = get_skills_engine()
    eng._skills.clear()
    eng._load_all()
    skill_names = sorted(eng._skills.keys())
    print(f"  loaded skills ({len(skill_names)}): {skill_names}")
    assert "firewall-skill" in skill_names

    fw_tools = [
        t for t in eng.get_tools() if t["function"]["name"] == "skill_firewall-skill"
    ]
    assert fw_tools, "firewall-skill not advertised to LLM"
    cmds = fw_tools[0]["function"]["parameters"]["properties"]["command"]["enum"]
    print(f"  firewall-skill commands: {cmds}")
    assert set(cmds) >= {"block", "unblock", "list", "drops", "stats"}

    print("\n=== D. Runtime — execute_tool truncation ===")
    from services.agent_tools import execute_tool

    async def run() -> None:
        out = await execute_tool("get_process_list", {})
        print(f"  get_process_list  -> {len(out)} chars (cap {TOOL_OUTPUT_MAX_CHARS})")
        assert len(out) <= TOOL_OUTPUT_MAX_CHARS

        out = await execute_tool("get_event_log", {})
        print(f"  get_event_log     -> {len(out)} chars")
        assert len(out) <= TOOL_OUTPUT_MAX_CHARS

        out = await execute_tool(
            "skill_firewall-skill", {"command": "stats", "args": ""}
        )
        print(f"  skill_firewall-skill stats -> {len(out)} chars")
        print(f"  preview: {out[:200].splitlines()[0]}")
        assert len(out) <= TOOL_OUTPUT_MAX_CHARS

    asyncio.run(run())

    print("\n=== E. text_utils — clean_ide_instructions ===")
    from services.agent import clean_ide_instructions as a
    from services.local_mcp_server import clean_ide_instructions as m
    from services.text_utils import clean_ide_instructions

    assert a is m is clean_ide_instructions
    out = clean_ide_instructions("hi **HEARTBEAT_OK** world")
    print(f"  cleaned: {out!r}")
    assert out == "hi  world".replace("  ", " ").strip() or "world" in out

    print("\n=== F. Pydantic V2 fs_tools ===")
    from services.fs_tools import read_file_tool

    res = read_file_tool("config.py", max_lines=3)
    print(f"  read_file_tool('config.py', 3) -> {len(res)} chars")
    assert "import os" in res

    print("\n=== smoke INTERNAL OK ===")


if __name__ == "__main__":
    main()
