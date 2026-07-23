"""Live agent test — writes result to file to avoid Windows console encoding issues."""
import sys
sys.path.insert(0, '.')
import asyncio
from services.agent import run_agent

async def test():
    with open('tests/_agent_test_result.txt', 'w', encoding='utf-8') as f:
        f.write("=== Live Agent Test (Textual ReAct) ===\n\n")
        try:
            result = await asyncio.wait_for(run_agent('מה המצב של המערכת?'), timeout=90.0)
            f.write("STATUS: SUCCESS\n")
            f.write(f"RESULT:\n{result}\n")
        except Exception as e:
            f.write(f"STATUS: ERROR\n{type(e).__name__}: {e}\n")

asyncio.run(test())
print("Test completed. Check tests/_agent_test_result.txt")
