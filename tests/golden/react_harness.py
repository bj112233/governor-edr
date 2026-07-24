"""ReAct grammar spike harness — golden-transcript test infrastructure.

Runs saved prompts against the LLM with and without GBNF grammar,
measures parse-failure rate, latency, and thought quality.

This is NOT a throwaway script — it's the foundation for golden-transcript
regression tests. Every future prompt or model change should be validated
through this harness.

Usage:
    python tests/golden/react_harness.py --prompts tests/golden/prompts.jsonl
    python tests/golden/react_harness.py --prompts tests/golden/prompts.jsonl --grammar
"""

import argparse
import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import openai

logger = logging.getLogger(__name__)

# ── Data structures ──────────────────────────────────────────────────────────

@dataclass
class PromptCase:
    """A single saved prompt for the harness."""
    id: str
    system_prompt: str
    user_prompt: str
    expected_tool: str | None = None  # for semantic validation (optional)


@dataclass
class RunResult:
    """Result of a single LLM call."""
    prompt_id: str
    raw_output: str
    latency_ms: float
    grammar_used: bool
    parse_category: str = ""  # OK | STRUCTURAL | SCHEMA | SEMANTIC
    parsed_tool: str = ""
    parsed_args: dict = field(default_factory=dict)
    error: str = ""


# ── Prompt loading ───────────────────────────────────────────────────────────

def load_prompts(path: Path) -> list[PromptCase]:
    """Load prompts from JSONL file."""
    prompts = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            data = json.loads(line)
            prompts.append(PromptCase(
                id=data["id"],
                system_prompt=data["system_prompt"],
                user_prompt=data["user_prompt"],
                expected_tool=data.get("expected_tool"),
            ))
    return prompts


# ── ReAct parser (mirrors _react_parser.py logic for categorization) ─────────

def categorize_response(raw: str) -> tuple[str, str, dict]:
    """Categorize a raw LLM response. Returns (category, tool_name, args).

    Categories:
      OK          — parsed successfully with valid structure
      STRUCTURAL  — no ReAct structure / broken JSON
      SCHEMA      — valid JSON but missing fields
      SEMANTIC    — structure OK but tool doesn't exist (caller checks)
    """
    import re

    # Check for textual ReAct format
    has_thought = bool(re.search(r"Thought:\s*", raw, re.IGNORECASE))
    has_action = bool(re.search(r"Action:\s*", raw, re.IGNORECASE))
    has_input = bool(re.search(r"Action Input:\s*", raw, re.IGNORECASE))

    if not has_action:
        return ("STRUCTURAL", "", {})

    # Extract tool name
    action_match = re.search(r"Action:\s*(\S+)", raw, re.IGNORECASE)
    if not action_match:
        return ("STRUCTURAL", "", {})
    tool_name = action_match.group(1).strip()

    # Extract Action Input
    input_match = re.search(r"Action Input:\s*(\{.*?\})(?:\n|$)", raw, re.DOTALL | re.IGNORECASE)
    if not input_match:
        if tool_name == "final_answer":
            return ("OK", tool_name, {})
        return ("SCHEMA", tool_name, {})

    raw_args = input_match.group(1).strip()
    try:
        args = json.loads(raw_args)
    except json.JSONDecodeError:
        return ("STRUCTURAL", tool_name, {})

    return ("OK", tool_name, args)


# ── LLM runner ───────────────────────────────────────────────────────────────

def load_grammar() -> str:
    """Load the GBNF grammar file."""
    grammar_path = Path(__file__).parent / "react_grammar.gbnf"
    return grammar_path.read_text(encoding="utf-8")


async def run_single(
    client: openai.AsyncOpenAI,
    model: str,
    case: PromptCase,
    use_grammar: bool,
    temperature: float = 0.1,
    max_tokens: int = 2000,
) -> RunResult:
    """Run a single prompt case against the LLM."""
    extra_body: dict[str, Any] = {
        "top_k": 40,
        "min_p": 0.05,
        "chat_template_kwargs": {"enable_thinking": False},
    }
    if use_grammar:
        extra_body["grammar"] = load_grammar()

    t0 = time.monotonic()
    try:
        response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": case.system_prompt},
                {"role": "user", "content": case.user_prompt},
            ],
            temperature=temperature,
            top_p=0.9,
            max_tokens=max_tokens,
            presence_penalty=1.2,
            extra_body=extra_body,
        )
        raw = response.choices[0].message.content or ""
    except Exception as exc:
        return RunResult(
            prompt_id=case.id,
            raw_output="",
            latency_ms=(time.monotonic() - t0) * 1000,
            grammar_used=use_grammar,
            error=str(exc),
        )

    latency_ms = (time.monotonic() - t0) * 1000
    category, tool, args = categorize_response(raw)

    return RunResult(
        prompt_id=case.id,
        raw_output=raw,
        latency_ms=latency_ms,
        grammar_used=use_grammar,
        parse_category=category,
        parsed_tool=tool,
        parsed_args=args,
    )


# ── Batch runner ─────────────────────────────────────────────────────────────

async def run_batch(
    client: openai.AsyncOpenAI,
    model: str,
    prompts: list[PromptCase],
    use_grammar: bool,
) -> list[RunResult]:
    """Run all prompts sequentially (avoid overloading the 4B model)."""
    results = []
    for i, case in enumerate(prompts):
        logger.info("[%d/%d] Running %s (grammar=%s)", i + 1, len(prompts), case.id, use_grammar)
        result = await run_single(client, model, case, use_grammar)
        results.append(result)
        logger.info(
            "  → %s | %s | %.0fms | tool=%s",
            result.parse_category,
            "ERROR" if result.error else "OK",
            result.latency_ms,
            result.parsed_tool,
        )
    return results


# ── Report ───────────────────────────────────────────────────────────────────

def print_report(results: list[RunResult], label: str) -> None:
    """Print summary statistics for a batch of results."""
    total = len(results)
    if total == 0:
        print(f"\n{label}: no results")
        return

    categories: dict[str, int] = {}
    latencies: list[float] = []
    errors = 0

    for r in results:
        if r.error:
            errors += 1
            categories["ERROR"] = categories.get("ERROR", 0) + 1
        else:
            categories[r.parse_category] = categories.get(r.parse_category, 0) + 1
            latencies.append(r.latency_ms)

    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    p50 = sorted(latencies)[len(latencies) // 2] if latencies else 0
    p95 = sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0

    print(f"\n{'='*60}")
    print(f"  {label} ({total} prompts)")
    print(f"{'='*60}")
    print(f"  Parse results:")
    for cat in ["OK", "STRUCTURAL", "SCHEMA", "SEMANTIC", "ERROR"]:
        count = categories.get(cat, 0)
        if count:
            print(f"    {cat:12s}: {count:3d} ({count*100//total}%)")
    print(f"  Latency (ms): avg={avg_latency:.0f}  p50={p50:.0f}  p95={p95:.0f}")
    if errors:
        print(f"  Errors: {errors}")

    return categories, avg_latency


# ── Main ─────────────────────────────────────────────────────────────────────

async def main() -> None:
    parser = argparse.ArgumentParser(description="ReAct grammar spike harness")
    parser.add_argument("--prompts", type=Path, required=True, help="JSONL file with saved prompts")
    parser.add_argument("--model", default="local", help="Model name for OpenAI client")
    parser.add_argument("--base-url", default="http://localhost:5001/v1", help="KoboldCpp endpoint")
    parser.add_argument("--api-key", default="none", help="API key (KoboldCpp ignores this)")
    parser.add_argument("--grammar", action="store_true", help="Run with GBNF grammar")
    parser.add_argument("--compare", action="store_true", help="Run both with and without grammar")
    parser.add_argument("--output", type=Path, default=None, help="Save results as JSON")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    prompts = load_prompts(args.prompts)
    logger.info("Loaded %d prompts from %s", len(prompts), args.prompts)

    client = openai.AsyncOpenAI(base_url=args.base_url, api_key=args.api_key)

    if args.compare:
        logger.info("Running WITHOUT grammar...")
        results_no_grammar = await run_batch(client, args.model, prompts, use_grammar=False)
        cat_no, lat_no = print_report(results_no_grammar, "WITHOUT grammar")

        logger.info("Running WITH grammar...")
        results_with_grammar = await run_batch(client, args.model, prompts, use_grammar=True)
        cat_with, lat_with = print_report(results_with_grammar, "WITH grammar")

        # Comparison
        print(f"\n{'='*60}")
        print("  COMPARISON")
        print(f"{'='*60}")
        structural_no = cat_no.get("STRUCTURAL", 0)
        structural_with = cat_with.get("STRUCTURAL", 0)
        latency_delta = ((lat_with - lat_no) / lat_no * 100) if lat_no else 0
        print(f"  Structural failures: {structural_no} → {structural_with}")
        print(f"  Latency delta: {latency_delta:+.1f}%")
        print()
        if structural_with <= 1 and abs(latency_delta) < 15:
            print("  VERDICT: ✓ GBNF worthwhile — proceed to full implementation")
        elif structural_with <= 1 and abs(latency_delta) >= 15:
            print("  VERDICT: ✗ Grammar works but latency too high — document and stop")
        else:
            print("  VERDICT: ✗ Grammar insufficient — document and stop")

        if args.output:
            all_results = {
                "without_grammar": [r.__dict__ for r in results_no_grammar],
                "with_grammar": [r.__dict__ for r in results_with_grammar],
            }
            args.output.write_text(json.dumps(all_results, indent=2, ensure_ascii=False), encoding="utf-8")
            logger.info("Results saved to %s", args.output)
    else:
        results = await run_batch(client, args.model, prompts, use_grammar=args.grammar)
        print_report(results, "WITH grammar" if args.grammar else "WITHOUT grammar")

        if args.output:
            args.output.write_text(
                json.dumps([r.__dict__ for r in results], indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            logger.info("Results saved to %s", args.output)


if __name__ == "__main__":
    asyncio.run(main())
