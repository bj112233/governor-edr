"""Trigger the agent on a complex multi-step task to exercise the subtask DAG path.

Run:  .\\.venv\\Scripts\\python.exe bin\trigger_agent.py
"""

import asyncio
import logging
import sys
from pathlib import Path

# Ensure project root on path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Fix Windows console encoding for Hebrew output
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    stream=sys.stdout,
)

from services.agent._agent_loop import run_agent

COMPLEX_TASK = (
    "בצע ניתוח אבטחה מקיף ב-3 שלבים: "
    "(1) קבל תמונת מצב מערכת עכשווית עם get_system_snapshot, "
    "(2) בדוק חיבורים חיצוניים פעילים עם get_external_connections, "
    "(3) צור דוח סיכום איומים על בסיס הנתונים שנאספו."
)


async def main():
    print(f"\n{'=' * 60}")
    print("TRIGGERING AGENT on complex task (bypasses DISABLED):")
    print(f"{'=' * 60}")
    print(f"Task: {COMPLEX_TASK}\n")

    result = await run_agent(
        user_question=COMPLEX_TASK,
        max_rounds=15,
        allow_bypasses=False,  # Force full DAG path — no sysreport shortcut
    )

    print(f"\n{'=' * 60}")
    print("AGENT RESULT:")
    print(f"{'=' * 60}")
    print(result[:2000] if result else "(empty result)")


if __name__ == "__main__":
    asyncio.run(main())
