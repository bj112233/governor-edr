"""Planner and DAG utilities — task decomposition and topological sorting."""

import json
import logging
import re
from collections import deque

logger = logging.getLogger(__name__)


def _topological_sort(tasks: list[dict]) -> list[dict]:
    """Topological sort (Kahn's Algorithm). Flattens a DAG into a linear list.

    Raises ValueError on cycle or dangling dependency.
    """
    task_dict = {str(t.get("id", i)): t for i, t in enumerate(tasks)}
    in_degree = {tid: 0 for tid in task_dict}
    adj: dict[str, list[str]] = {tid: [] for tid in task_dict}

    for tid, t in task_dict.items():
        deps = t.get("depends_on", [])
        if not isinstance(deps, list):
            deps = []
        for dep in deps:
            dep_id = str(dep)
            if dep_id not in task_dict:
                raise ValueError(f"Dangling dependency: Task '{tid}' depends on non-existent '{dep_id}'")
            adj[dep_id].append(tid)
            in_degree[tid] += 1

    queue = deque(tid for tid, deg in in_degree.items() if deg == 0)
    sorted_tasks: list[dict] = []

    while queue:
        curr = queue.popleft()
        sorted_tasks.append(task_dict[curr])
        for neighbor in adj[curr]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)

    if len(sorted_tasks) != len(tasks):
        raise ValueError("Cycle detected in DAG (Circular Dependency)")

    return sorted_tasks


def _build_recovery_task(failed_task_id: str, failed_tool: str, error_msg: str, user_question: str) -> dict:
    """Build a recovery subtask with in-degree 0 (no depends_on).

    Injected into the DAG after a tool failure. Runs immediately
    because it has no dependencies. Sprint 6: error_msg replaces
    static fallback_cmd — the LLM chooses the alternative dynamically.
    """
    return {
        "id": f"{failed_task_id}_recovery",
        "description": (
            f"Recovery: Task '{failed_task_id}' failed because tool "
            f"'{failed_tool}' repeatedly failed with error: {error_msg[:150]}. "
            f"Choose a DIFFERENT available tool to gather equivalent data. "
            f"Then call final_answer with the result."
        ),
        "depends_on": [],  # in-degree 0 — runs next
    }


def _should_decompose(user_question: str) -> bool:
    """Lightweight heuristic: decompose only if question looks multi-step."""
    q = user_question.lower()
    # Action verbs in EN/HE
    action_words = [
        "scan",
        "check",
        "analyze",
        "create",
        "send",
        "generate",
        "run",
        "test",
        "build",
        "report",
        "export",
        "fetch",
        "query",
        "סרוק",
        "בדוק",
        "נתח",
        "צור",
        "שלח",
        "הרץ",
        "בצע",
        "בנה",
        "דווח",
        "הפק",
        "קבל",
        "חפש",
    ]
    action_count = sum(1 for w in action_words if w in q)
    # Multi-step connectors
    connectors = [
        " and ",
        " then ",
        " after ",
        " finally ",
        " also ",
        " in addition ",
        " followed by ",
        " וגם ",
        " ולאחר מכן ",
        " בסוף ",
        " ואז ",
        " ובנוסף ",
        " ואחרי ",
    ]
    has_connector = any(c in q for c in connectors)
    # Explicit stage/step patterns (strong signal, bypass length check)
    stage_patterns = [
        "stage 1",
        "stage 2",
        "stage 3",
        "step 1",
        "step 2",
        "step 3",
        "phase 1",
        "phase 2",
        "phase 3",
        "שלב 1",
        "שלב 2",
        "שלב 3",
        "צעד 1",
        "צעד 2",
        "צעד 3",
    ]
    has_explicit_stages = any(p in q for p in stage_patterns)
    if has_explicit_stages:
        return True
    # Hebrew is compact — lower threshold ( Hebrew avg ~2.5 chars/word vs EN ~5 )
    _hebrew_chars = sum(1 for c in user_question if "\u0590" <= c <= "\u05ff")
    _threshold = 30 if _hebrew_chars > 5 else 50
    return len(user_question) > _threshold and (action_count >= 2 or has_connector)


async def _decompose_task(user_question: str, active_tools: list[dict], engine) -> list[dict]:
    """Decompose a complex task into DAG subtasks via LLM.

    Injects a Tool Catalog so the Planner knows which tools are available.
    Returns a list of {id, description, depends_on, status}.
    On any failure, falls back to a single subtask.

    Uses PLAIN-TEXT format (not response_format=json_object) because the 4B model
    on KoboldCpp cannot reliably generate valid nested JSON when grammar
    enforcement is active (see lessons.md 2026-06-16). Plain-text + regex is
    the proven robust path for ALL LLM nodes on this stack.
    """
    # Build Tool Catalog from pruned active_tools (post-initializer filtering)
    catalog_lines = []
    for t in active_tools:
        # Safe extraction: supports both OpenAI nested format and flat dict
        func_data = t.get("function", t)
        name = func_data.get("name", "unknown_tool")
        desc = func_data.get("description", "No description")[:120]
        catalog_lines.append(f"- {name}: {desc}")
    tool_catalog = "\n".join(catalog_lines)

    planner_system = (
        "You are an elite autonomous Agent Planner.\n"
        "Break down the user's request into atomic, actionable subtasks.\n"
        "CRITICAL: Map execution dependencies as a Directed Acyclic Graph. "
        "If Subtask B needs the result of Subtask A, B MUST list A in DEPS.\n\n"
        "AVAILABLE TOOLS (use these strictly when planning subtasks):\n"
        f"{tool_catalog}\n\n"
        "OUTPUT FORMAT — one subtask per line, EXACTLY this format:\n"
        "TASK: <id> | <description> | DEPS: [<ids>] | TYPE: <hard|soft>\n\n"
        "RULES:\n"
        "- <id>: T1, T2, T3, ... (sequential)\n"
        "- <description>: what to do + which tool to use\n"
        "- DEPS: [] if no dependencies, or [T1,T2] if depends on T1 and T2\n"
        "- TYPE: hard (default — must wait for deps) or soft (can proceed with partial data)\n"
        "- Output ONLY task lines. No markdown, no explanation, no JSON.\n"
        "- CRITICAL: The LAST subtask MUST always use the final_answer tool to "
        "synthesize all gathered data and deliver the result. NEVER split "
        "'analysis' and 'final answer' into separate subtasks — the final "
        "subtask IS the synthesis+answer step.\n\n"
        "EXAMPLE:\n"
        "TASK: T1 | Scan LAN for active hosts using scan_lan | DEPS: [] | TYPE: hard\n"
        "TASK: T2 | Enrich found IPs with skill_intel-skill ip | DEPS: [T1] | TYPE: hard\n"
        "TASK: T3 | Analyze system snapshot using get_system_snapshot | DEPS: [] | TYPE: hard\n"
        "TASK: T4 | Synthesize findings and deliver report using final_answer | DEPS: [T2,T3] | TYPE: soft"
    )

    try:
        response = await engine.complete(
            system_prompt=planner_system,
            user_input=f"Task: {user_question}",
            temperature=0.1,
            max_tokens=800,
        )
    except Exception as exc:
        logger.debug("[PLANNER] Engine call failed: %s", exc)
        return [{"id": "T1", "description": user_question, "depends_on": [], "status": "pending"}]

    raw = response.strip()

    # Build authorized tool-name set for post-parse validation.
    # The 4B model often hallucinates tool names not in the catalog
    # (e.g. "get_event_log" when only get_system_snapshot is available),
    # causing the executor to block them as unauthorized and waste steps.
    authorized_tools = {func_data.get("name", "") for t in active_tools for func_data in [t.get("function", t)]}
    authorized_tools.add("final_answer")  # always available

    # Layer 1: Plain-text TASK line parser (primary — 4B model robust)
    parsed = _parse_plain_text_tasks(raw)
    if len(parsed) > 1:
        parsed = _filter_unauthorized_tools(parsed, authorized_tools)
        logger.info("[PLANNER] Plain-text parse OK: %d subtasks", len(parsed))
        return parsed

    # Layer 2: Legacy JSON parse (backward compat if model emits JSON anyway)
    try:
        subtasks_raw = json.loads(raw)
        if isinstance(subtasks_raw, list) and len(subtasks_raw) > 0:
            parsed = []
            for i, item in enumerate(subtasks_raw):
                if not isinstance(item, dict):
                    continue
                desc = item.get("description", "")
                if not desc:
                    continue
                raw_dep_type = item.get("dependency_type", "hard")
                safe_dep_type = "soft" if str(raw_dep_type).strip().lower() == "soft" else "hard"
                parsed.append(
                    {
                        "id": str(item.get("id", f"T{i + 1}")),
                        "description": desc,
                        "depends_on": item.get("depends_on", []) if isinstance(item.get("depends_on"), list) else [],
                        "dependency_type": safe_dep_type,
                        "status": "pending",
                    }
                )
            if len(parsed) > 1:
                parsed = _filter_unauthorized_tools(parsed, authorized_tools)
                logger.info("[PLANNER] JSON parse OK (legacy fallback): %d subtasks", len(parsed))
                return parsed
    except json.JSONDecodeError:
        logger.debug("[PLANNER] JSON parse failed, attempting regex recovery")

    # Layer 3: Regex extraction — find {"description":"..."} fragments
    _DESC_RE = re.compile(r'"description"\s*:\s*"([^"]+)"')
    matches = _DESC_RE.findall(raw)
    if len(matches) > 1:
        parsed = [
            {
                "id": f"T{i + 1}",
                "description": desc,
                "depends_on": [],
                "status": "pending",
            }
            for i, desc in enumerate(matches)
        ]
        logger.info("[PLANNER] Regex recovery: %d subtasks", len(parsed))
        parsed = _filter_unauthorized_tools(parsed, authorized_tools)
        return parsed

    # Layer 4: Single-subtask fallback (never fails)
    logger.debug("[PLANNER] All parse layers failed, falling back to single subtask")
    return [{"id": "T1", "description": user_question, "depends_on": [], "status": "pending"}]


def _filter_unauthorized_tools(subtasks: list[dict], authorized_tools: set[str]) -> list[dict]:
    """Sanitize subtask descriptions: flag hallucinated tool names.

    The 4B planner often invents tool names not in the injected catalog
    (e.g. "get_event_log" when only get_system_snapshot is available).
    The executor then blocks them as unauthorized, wasting steps and
    triggering interceptor death-loops.

    Strategy: scan each description for tool-like tokens. If a token
    is NOT in the authorized set, append an explicit UNAVAILABLE note
    to the description so the executor knows to use alternatives or
    skip gracefully — instead of attempting the blocked call.
    """
    _TOOL_TOKEN_RE = re.compile(r"\b((?:get_|scan_|skill_|defender_|sentinel_|terminate_|block_|kill_)[a-z_-]+)\b")
    filtered: list[dict] = []
    for st in subtasks:
        desc = st.get("description", "")
        mentions = set(_TOOL_TOKEN_RE.findall(desc.lower()))
        unauthorized = mentions - authorized_tools
        if not unauthorized:
            filtered.append(st)
            continue
        # STRIP the hallucinated tool name from the actionable description, then
        # append a strong anti-hallucination instruction. Merely appending a note
        # while LEAVING the tool name in the text causes the 4B model to read it
        # and fabricate its execution + output during synthesis (the critic then
        # correctly flags the hallucination and the whole run degrades). Removing
        # the literal name + an explicit "you did NOT run it" guard prevents this.
        clean_desc = desc
        for t in sorted(unauthorized):
            clean_desc = re.sub(re.escape(t), "an available tool", clean_desc, flags=re.IGNORECASE)
        note = (
            " [SYSTEM: the tool(s) originally planned for this step are UNAVAILABLE. "
            "You did NOT run them — do NOT claim, reference, or invent their output. "
            "Use an available tool or skip this step.]"
        )
        st["description"] = f"{clean_desc}{note}"
        logger.warning(
            "[PLANNER] Stripped unauthorized tool(s) %s from subtask %s",
            sorted(unauthorized),
            st.get("id", "?"),
        )
        filtered.append(st)
    return filtered


# Plain-text TASK line parser — primary path for 4B model on KoboldCpp.
# Format: TASK: <id> | <description> | DEPS: [T1,T2] | TYPE: hard|soft
_TASK_LINE_RE = re.compile(
    r"TASK:\s*(\S+)\s*\|\s*(.+?)\s*\|\s*DEPS:\s*\[([^\]]*)\]\s*(?:\|\s*TYPE:\s*(\w+))?",
    re.IGNORECASE,
)


def _parse_plain_text_tasks(raw: str) -> list[dict]:
    """Parse plain-text TASK lines into subtask dicts.

    Tolerant: DEPS and TYPE segments are optional. Lines without the full
    pipe-delimited format fall through to Layer 2/3. Returns [] if no
    valid TASK lines found (so caller falls through to legacy parsers).
    """
    parsed: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.upper().startswith("TASK:"):
            continue
        m = _TASK_LINE_RE.match(line)
        if not m:
            continue
        task_id = m.group(1).strip()
        desc = m.group(2).strip()
        deps_raw = m.group(3).strip()
        dep_type = m.group(4).strip().lower() if m.group(4) else "hard"
        if not desc:
            continue
        # Parse deps: "T1,T2" → ["T1", "T2"]
        depends_on = [d.strip() for d in deps_raw.split(",") if d.strip()] if deps_raw else []
        safe_dep_type = "soft" if dep_type == "soft" else "hard"
        parsed.append(
            {
                "id": task_id,
                "description": desc,
                "depends_on": depends_on,
                "dependency_type": safe_dep_type,
                "status": "pending",
            }
        )
    return parsed
