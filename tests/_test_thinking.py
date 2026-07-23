"""Test <thinking> tag parsing."""
import sys
sys.path.insert(0, '.')
from services.agent._react_parser import parse_react_response

# Test 1: <thinking> + Action
actual1 = "<thinking>\nThe user is asking about the system status in Hebrew.\n</thinking>\n\nThought: I will check system status\nAction: get_system_snapshot\nAction Input: {}"
r1 = parse_react_response(actual1)
print("Test 1 (<thinking> + Action):")
print("  thought:", repr(r1["thought"][:60]))
print("  tool_calls:", r1["tool_calls"])

# Test 2: <thinking> without Thought: line
actual2 = "<thinking>Done gathering data.</thinking>\nThought: Done\nAction: final_answer\nAction Input: {\"text\": \"System is OK\"}"
r2 = parse_react_response(actual2)
print("\nTest 2 (<thinking> + final_answer):")
print("  thought:", repr(r2["thought"][:60]))
print("  tool_calls:", r2["tool_calls"])

# Test 3: No Action at all (thought leak)
actual3 = "<thinking>The system is running fine, CPU at 5%, RAM at 30%.</thinking>"
r3 = parse_react_response(actual3)
print("\nTest 3 (No Action — thought leak):")
print("  thought:", repr(r3["thought"][:60]))
print("  tool_calls:", r3["tool_calls"])

print("\n=== All tests completed ===")
