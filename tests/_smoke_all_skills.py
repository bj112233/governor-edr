"""End-to-end smoke test for every skill via SkillsEngine.execute().
This mirrors exactly how the agent invokes skills, ensuring the contract
between the LLM-facing layer and CLI scripts is intact."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.skills_engine import get_skills_engine  # noqa: E402

TESTS: list[tuple[str, str, str]] = [
    ("weather-skill", "run", '--location "תל אביב"'),
    ("currency-skill", "run", "--amount 100 --from EUR --to ILS"),
    ("stocks-skill", "quote", "--symbol AAPL"),
    ("translator-skill", "run", "--text hello --to he"),
    ("geocode-skill", "forward", '--address "חיפה"'),
    ("geocode-skill", "distance", '--from "תל אביב" --to "חיפה"'),
    ("crypto-skill", "hash", '--text "hello" --algo sha256'),
    ("firewall-skill", "list", ""),
    ("intel-skill", "dns", "--target google.com"),
    ("intel-skill", "ip", "--target 8.8.8.8"),
    ("news-monitor", "news_il", "--limit 2"),
    ("web-scraper", "fetch", "--url https://example.com"),
    # report-maker without --stdin/--input would error gracefully (validates dispatch)
    (
        "report-maker",
        "default",
        f"--title Test --input {Path(__file__).resolve().parents[1] / 'config' / 'news_feeds.json'}",
    ),
]


async def main() -> int:
    engine = get_skills_engine()
    failures = 0
    for skill, cmd, args in TESTS:
        out = await engine.execute(skill, cmd, args)
        ok = bool(out) and not out.startswith("❌") and "Skill not found" not in out
        marker = "✅" if ok else "❌"
        if not ok:
            failures += 1
        head = (out or "(empty)").splitlines()[0][:120]
        print(f"{marker} {skill:<18} {cmd:<10} -> {head}")
    print(f"\n{len(TESTS) - failures}/{len(TESTS)} passed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
