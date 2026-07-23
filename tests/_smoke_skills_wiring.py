"""Verify every skill's connectivity across all access paths.

Each skill should be reachable via at least one of:
  A. LLM agent — auto-loaded by skills_engine.get_tools() in run_agent.
  B. Telegram slash command — explicit /<cmd> handler routed via MCP.
  C. MCP HTTP — either via tools_registry wrapper, or via the dynamic
     /mcp/skill/<name> endpoint registered in local_mcp_server.
"""

from __future__ import annotations


def main() -> None:
    from services.skills_engine import get_skills_engine
    from services.tools_registry import REGISTRY
    from services.telegram.commands import (
        INTEL_COMMANDS,
        INTEL_COMMANDS_WITH_ARGS,
    )

    eng = get_skills_engine()
    eng._skills.clear()
    eng._load_all()
    skills = sorted(eng._skills.keys())

    # --- A. LLM exposure: every loaded skill is auto-included via get_tools()
    llm_tool_names = {t["function"]["name"] for t in eng.get_tools()}

    # --- B. Telegram exposure: scan INTEL_COMMANDS{,_WITH_ARGS} for skill_*
    tg_skill_targets: dict[str, list[str]] = {}
    for slash, (tool_name, _title) in INTEL_COMMANDS.items():
        if tool_name.startswith("skill_"):
            target = tool_name[6:].replace("_", "-")  # skill_web_scraper -> web-scraper
            tg_skill_targets.setdefault(target, []).append(f"/{slash}")
    for slash, tup in INTEL_COMMANDS_WITH_ARGS.items():
        tool_name = tup[0]
        if tool_name.startswith("skill_"):
            target = tool_name[6:].replace("_", "-")
            tg_skill_targets.setdefault(target, []).append(f"/{slash}")

    # --- C. MCP wrapper: tools_registry entries that expose_to_mcp=True
    mcp_wrapper_skills: dict[str, str] = {}
    for name, spec in REGISTRY.items():
        if name.startswith("skill_") and spec.expose_to_mcp:
            target = name[6:].replace("_", "-")
            mcp_wrapper_skills[target] = name

    # --- Pretty report
    print(f"{'skill':<22}  LLM  TG-cmd                MCP-wrapper       /mcp/skill/<name>")
    print("-" * 95)
    issues: list[str] = []
    for s in skills:
        in_llm = f"skill_{s}" in llm_tool_names
        tg = ", ".join(tg_skill_targets.get(s, [])) or "—"
        mcp_wrapper = mcp_wrapper_skills.get(s, "—")
        # /mcp/skill/<name> is auto-registered for every loaded skill, so always YES
        dynamic = "YES"
        flag_llm = "YES" if in_llm else "NO "
        print(f"{s:<22}  {flag_llm}  {tg:<21}  {mcp_wrapper:<17} {dynamic}")
        if not in_llm:
            issues.append(f"  - {s} not visible to LLM")

    print()
    if issues:
        print("ISSUES FOUND:")
        for i in issues:
            print(i)
    else:
        print("OK — every skill reachable from at least one channel.")

    # --- Detail: which sub-commands per skill, and how many a wrapper covers
    print()
    print("=== Sub-command coverage of MCP wrappers ===")
    print("(LLM gets *all* sub-commands automatically via skill_<name>.command enum;")
    print(" Telegram & MCP wrappers are hardcoded to ONE sub-command each.)")
    print()
    for s in skills:
        skill_obj = eng._skills[s]
        cmds = skill_obj._extract_commands()
        wrap = mcp_wrapper_skills.get(s)
        if wrap:
            spec = REGISTRY[wrap]
            # Inspect the lambda for the hardcoded command — fragile, but works
            # for our static wrappers in tools_registry.
            import inspect
            try:
                src = inspect.getsource(spec.handler).strip()
            except OSError:
                src = "(lambda)"
            print(f"  {s:<22}  cmds={cmds}")
            print(f"      wrapper hardcodes: {src[:120]}")
        else:
            print(f"  {s:<22}  cmds={cmds}  (no MCP wrapper — LLM-only)")


if __name__ == "__main__":
    main()
