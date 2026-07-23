# services/osint_react_loop.py
"""Pure Python ReAct loop for autonomous OSINT threat hunting.

No LangChain. String-parsed Thought/Action/Observation cycles.
All new files < 300 lines (SRP).
"""

import json
import logging
import re

from services.ioc_extractor import extract_all
from services.llm_bridge import LLMBridge
from services.osint_search import search_threat_intel

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are an autonomous OSINT threat intelligence hunter.
Investigate cybersecurity topics, search for data, extract IOCs, and produce a consolidated report.

You MUST respond in EXACTLY one of these two formats:

FORMAT 1 — When you need more data:
Thought: <your reasoning>
Action: search
Action Input: <search query>

FORMAT 2 — When done:
Thought: <your reasoning>
Final Answer: <consolidated report with all discovered IOCs>

Available actions:
- intel: Threat-intelligence lookup for IOCs (IPs, hashes, domains). Input = IP or domain. Queries AbuseIPDB, VirusTotal, urlscan.io. Use this for concrete indicators — NOT web search.
- search: General web search (Startpage → Wikipedia → AI). Input = query string. Use for APT groups, attack techniques, news. Returns ~10 results.
- cve: NVD NIST CVE lookup. Input = CVE ID (e.g. CVE-2026-1234). Returns CVSS score, severity, attack vector, affected products, references. Use this for ANY CVE — NOT `search`.
- extract: Extract IOCs from raw text. Input = raw text to analyze.
- leaks: Scan for leaked data and infrastructure. Input = domain or IP. Queries crt.sh (subdomains/certs), Wayback Machine (archived URLs), and urlscan.io (passive scans).
- certs: Query certificate transparency logs only. Input = domain. Returns subdomains discovered via SSL certificates.

ROUTING RULES (CRITICAL):
- IP address (e.g. "1.2.3.4") → use `intel` action, NOT `search`.
- File hash (MD5/SHA256) → use `intel` action, NOT `search`.
- Bare domain (e.g. "evil.com") → use `intel` or `leaks`, NOT `search`.
- CVE ID (e.g. "CVE-2026-1234") → use `cve` action, NOT `search`.
- APT group, attack technique, news → use `search` action.

RULES:
- ONE action per response.
- After each action you receive an Observation with results.
- Continue until you have enough data, then use Final Answer.
- In Final Answer, explicitly list all discovered IOCs (IPs, domains, hashes, CVEs).
- Be concise. Do NOT output anything outside the format.
- If you receive "ALREADY SEARCHED" in an Observation, do NOT repeat that query. Try a different angle.
- If you receive "Prior investigation findings", use them as context — don't re-investigate what's already known.
- Use "leaks" when investigating a specific domain or IP for infrastructure exposure.
- Use "certs" when you need to discover subdomains of a known domain.
"""

_MAX_TOKENS = 1200


def _parse_react(text: str) -> dict[str, str]:
    """Parse Thought/Action/Action Input/Final Answer from LLM output."""
    out: dict[str, str] = {}
    m = re.search(
        r"Thought:\s*(.*?)(?=\n(?:Action|Final Answer):)",
        text,
        re.DOTALL | re.IGNORECASE,
    )
    out["thought"] = m.group(1).strip() if m else ""
    m = re.search(r"Action:\s*(\w+)", text, re.IGNORECASE)
    out["action"] = m.group(1).lower().strip() if m else ""
    m = re.search(r"Action Input:\s*(.*)", text, re.DOTALL | re.IGNORECASE)
    out["action_input"] = m.group(1).strip() if m else ""
    m = re.search(r"Final Answer:\s*(.*)", text, re.DOTALL | re.IGNORECASE)
    out["final_answer"] = m.group(1).strip() if m else ""
    return out


async def _run_intel(action_input: str) -> str:
    """Threat-intel lookup: route IPs to enrich_ip, domains to leak_scanner."""
    from services.intel_enricher import enrich_ip

    inp = action_input.strip()
    try:
        import ipaddress

        ipaddress.ip_address(inp)
        data = await enrich_ip(inp)
        if data:
            return f"Observation: Intel enrichment for {inp}:\n{json.dumps(data, ensure_ascii=False, default=str)[:2000]}"
    except ValueError:
        pass
    from services.leak_scanner import format_leak_results, scan_leaks

    leak_results = await scan_leaks(inp)
    return f"Observation:\n{format_leak_results(leak_results)}"


async def _run_search(action_input: str) -> str:
    """General web search via waterfall engines."""
    results = await search_threat_intel(action_input, max_results=15, pages=1)
    if not results:
        return "Observation: No results found. Try a different query or use `intel` action for IOC lookups."
    lines = []
    for r in results:
        engine = r.get("engine", "?")
        lines.append(f"[{engine}] {r.get('title', '')}")
        lines.append(f"URL: {r.get('url', '')}")
        lines.append(f"Snippet: {r.get('snippet', '')}")
        lines.append("---")
    return "Observation:\n" + "\n".join(lines)


async def _run_cve(action_input: str) -> str:
    """NVD NIST CVE lookup — returns hard facts observation."""
    from services.nvd_enricher import enrich_cve, format_cve_hard_facts

    cve_result = await enrich_cve(action_input.strip())
    if not cve_result.get("available"):
        return f"Observation: NVD lookup failed for {action_input}: {cve_result.get('error', 'unknown')}"
    return f"Observation:\n{format_cve_hard_facts(cve_result)}"


async def _run_tool(action: str, action_input: str) -> str:
    """Dispatch to intel, search, cve, extract, leaks, or certs tool."""
    if action == "intel":
        return await _run_intel(action_input)
    if action == "search":
        return await _run_search(action_input)
    if action == "cve":
        return await _run_cve(action_input)
    if action == "extract":
        iocs = extract_all(action_input)
        return f"Observation: Extracted IOCs = {json.dumps(iocs, ensure_ascii=False)}"
    if action == "leaks":
        from services.leak_scanner import format_leak_results, scan_leaks

        leak_results = await scan_leaks(action_input)
        text = format_leak_results(leak_results)
        return f"Observation:\n{text}"
    if action == "certs":
        from services.leak_scanner import scan_crtsh

        cert_data = await scan_crtsh(action_input)
        subs = cert_data.get("subdomains", [])
        if not subs:
            return f"Observation: No certificates or subdomains found for {action_input}."
        lines = [f"Observation: crt.sh found {len(subs)} subdomains for {action_input}:"]
        for s in subs[:20]:
            lines.append(f"  {s}")
        if len(subs) > 20:
            lines.append(f"  ... and {len(subs) - 20} more")
        return "\n".join(lines)
    return f"Observation: Unknown action '{action}'. Use: intel, search, cve, extract, leaks, certs."


def _merge_iocs(all_iocs: dict[str, list[str]], texts: tuple[str, ...]) -> None:
    """Extract IOCs from texts and merge into all_iocs (dedup, preserve order)."""
    for text in texts:
        iocs = extract_all(text)
        for key in all_iocs:
            all_iocs[key] = list(dict.fromkeys(all_iocs[key] + iocs.get(key, [])))


async def _get_investigation_memory_prefix(topic: str) -> str:
    """Retrieve prior investigation summary as a memory prefix string."""
    from services.investigation_memory import get_investigation_summary

    try:
        prior_summary = await get_investigation_summary(topic)
        if prior_summary:
            logger.info("[OSINTReAct] Injected %d chars of prior investigation memory", len(prior_summary))
            return f"\n\n--- Prior investigation findings ---\n{prior_summary}\n--- End prior findings ---\n"
    except Exception as exc:
        logger.warning("[OSINTReAct] Memory retrieval failed (non-fatal): %s", exc)
    return ""


async def _execute_action(
    topic: str,
    action: str,
    action_input: str,
) -> str:
    """Execute a tool action with loop-prevention check."""
    from services.investigation_memory import is_query_visited

    try:
        already_visited = await is_query_visited(topic, action_input)
        if already_visited:
            logger.info("[OSINTReAct] Loop prevented: query already visited")
            return (
                f"Observation: ALREADY SEARCHED — You already queried '{action_input}' "
                f"in a prior step. Try a different search angle or use Final Answer."
            )
    except Exception as exc:
        logger.warning("[OSINTReAct] Memory check failed (non-fatal): %s", exc)
    return await _run_tool(action, action_input)


async def _persist_step(topic: str, action: str, action_input: str, observation: str) -> None:
    """Persist investigation step to memory (non-fatal)."""
    from services.investigation_memory import save_step

    try:
        step_iocs = extract_all(action_input)
        step_ioc_list = [ioc for iocs in step_iocs.values() for ioc in iocs]
        await save_step(topic, action_input, action, observation, step_ioc_list)
    except Exception as exc:
        logger.warning("[OSINTReAct] Step persist failed (non-fatal): %s", exc)


def _check_early_exit(action: str, observation: str, consecutive_empty: int) -> tuple[bool, int]:
    """Check if early-exit condition is met (2 consecutive empty searches).

    Returns (should_break, updated_consecutive_empty).
    """
    if action == "search" and "No results found" in observation:
        consecutive_empty += 1
        if consecutive_empty >= 2:
            logger.warning("[OSINTReAct] Early exit: %d consecutive empty searches", consecutive_empty)
            return True, consecutive_empty
    else:
        consecutive_empty = 0
    return False, consecutive_empty


async def run_hunt(topic: str, max_iterations: int = 5) -> dict:
    """Autonomous ReAct loop. Returns dict with final_answer, iocs, history.

    Features:
    - Dynamic iteration budget (caller should use react_budget.compute_budget)
    - Investigation memory: prior findings injected as context
    - Loop prevention: repeated queries are intercepted
    """
    bridge = LLMBridge.get_instance()
    history: list[str] = []
    final_answer = ""
    all_iocs: dict[str, list[str]] = {
        "ips_v4": [],
        "ips_v6": [],
        "domains": [],
        "hashes": [],
        "cves": [],
        "urls": [],
        "cidrs": [],
        "asns": [],
        "emails": [],
    }

    memory_prefix = await _get_investigation_memory_prefix(topic)
    user_input = f"Investigate this cybersecurity topic and extract all IOCs.\n\nTopic: {topic}{memory_prefix}\n\nBegin your investigation now."

    consecutive_empty = 0
    for iteration in range(max_iterations):
        logger.info("[OSINTReAct] Iteration %d/%d topic='%s'", iteration + 1, max_iterations, topic)
        prompt = "\n\n".join(history + [f"User:\n{user_input}"]) if history else user_input
        try:
            response = await bridge.complete(
                system_prompt=_SYSTEM_PROMPT,
                user_input=prompt,
                temperature=0.2,
                max_tokens=_MAX_TOKENS,
                timeout=30.0,
            )
        except Exception as exc:
            logger.error("[OSINTReAct] LLM failed: %s", exc)
            break

        logger.info("[OSINTReAct] LLM -> %d chars", len(response))
        parsed = _parse_react(response)
        history.append(f"Assistant:\n{response}")

        if parsed.get("final_answer"):
            final_answer = parsed["final_answer"]
            _merge_iocs(all_iocs, (final_answer,))
            logger.info("[OSINTReAct] Final Answer after %d iters", iteration + 1)
            break

        action = parsed.get("action", "")
        action_input = parsed.get("action_input", "")
        if not action or not action_input:
            logger.warning("[OSINTReAct] No actionable step. Stopping.")
            break

        observation = await _execute_action(topic, action, action_input)
        logger.info("[OSINTReAct] Tool '%s' executed", action)

        await _persist_step(topic, action, action_input, observation)

        should_break, consecutive_empty = _check_early_exit(action, observation, consecutive_empty)
        if should_break:
            break

        _merge_iocs(all_iocs, (action_input, observation))
        history.append(f"User:\n{observation}")
        user_input = ""

    else:
        logger.warning("[OSINTReAct] Max iterations reached without Final Answer")

    return {
        "topic": topic,
        "final_answer": final_answer,
        "iocs": all_iocs,
        "iterations": len([h for h in history if h.startswith("Assistant:")]),
        "history": history,
        "max_iterations": max_iterations,
    }
