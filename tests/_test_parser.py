"""Quick parser test script."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from services.agent._react_parser import parse_react_response

# Test 1: Valid textual ReAct
text1 = "Thought: I will check the system status.\nAction: get_system_snapshot\nAction Input: {}"
r1 = parse_react_response(text1)
print("Test 1:", r1)

# Test 2: final_answer with Hebrew
text2 = 'Thought: I have all the data.\nAction: final_answer\nAction Input: {"text": "System OK"}'
r2 = parse_react_response(text2)
print("Test 2:", r2)

# Test 3: No action (thought leak)
text3 = "Thought: The system is running fine, CPU at 5%, RAM at 30%."
r3 = parse_react_response(text3)
print("Test 3:", r3)

# Test 4: Old JSON format (backward compat)
text4 = '{"thought": "test", "tool_calls": [{"name": "final_answer", "arguments": {"text": "hi"}}]}'
r4 = parse_react_response(text4)
print("Test 4 (old JSON):", r4)

# Test 5: Empty output
r5 = parse_react_response("")
print("Test 5 (empty):", r5)
