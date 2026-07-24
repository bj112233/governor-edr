"""Build multi-turn prompts that simulate the real failure scenario.

The structural failures in logs happen AFTER tool_output is injected into
the conversation context. Single-turn prompts don't reproduce this.
These prompts simulate step 2+ of a real agent run.
"""
import json
from pathlib import Path

SYSTEM_PROMPT = """You are Sentinel, an autonomous reasoning agent (local Qwen3.5-4B, KoboldCpp, 16K context).

# TOOLS
[{"name":"get_system_snapshot","description":"CPU RAM memory disk usage status"},{"name":"scan_suspicious_procs","description":"Suspicious processes powershell wmic certutil threat hunt"},{"name":"get_external_connections","description":"Network connections external IP remote hosts outbound traffic"},{"name":"get_listening_ports","description":"Listening ports TCP UDP open services network exposed"},{"name":"run_powershell","description":"PowerShell command execute script run terminal"},{"name":"final_answer","description":"Return final answer to user"}]

# REACT PROTOCOL (STRICT TEXT FORMAT — NO XML TAGS)
Thought: <≤100 char plan>
Action: <tool_name>
Action Input: {"param": "value"}

After <tool_output>: call next tool OR call final_answer.
Round 1 = gather data. Round 2 = final_answer({"text": "תשובה מלאה בעברית"}).
On error: analyze briefly in Thought, try alternative, or report via final_answer.
NEVER emit <thinking>, <system>, <tool_output> or any XML tags — use ONLY the text format above.

# FEW-SHOT EXAMPLE (copy this structure EXACTLY)
Thought: סריקת תהליכים חשודים
Action: scan_suspicious_procs
Action Input: {}

Thought: קיבלתי תוצאה, עובר לסיכום
Action: final_answer
Action Input: {"text": "דוח מלא בעברית עם כל הנתונים"}

CRITICAL: Every response MUST start with 'Thought:' followed by 'Action:' and 'Action Input:'.
Action Input MUST be valid JSON (curly braces required). No exceptions."""

# Simulated tool outputs (realistic but truncated)
TOOL_OUTPUT_SNAPSHOT = """<tool_output>
CPU: 12.3%
RAM: 68.2% (10.9GB/16GB)
Disk C: 82% used (410GB/500GB)
Top processes: chrome.exe (3.2% CPU), python.exe (2.1% CPU), koboldcpp.exe (1.8% CPU)
Uptime: 4d 12h 33m
</tool_output>"""

TOOL_OUTPUT_PROCS = """<tool_output>
Scanned 47 processes. 2 suspicious flagged:
1. powershell.exe (PID 4521) - encoded command: -enc SGVsbG8gV29ybGQ=
2. certutil.exe (PID 7832) - downloading from external URL
MITRE TTPs: T1059 (PowerShell), T1105 (Ingress Tool Transfer)
</tool_output>"""

TOOL_OUTPUT_NET = """<tool_output>
12 active external connections:
- 142.250.1.78:443 (HTTPS, chrome.exe)
- 20.190.159.21:443 (HTTPS, Microsoft Teams)
- 151.101.1.69:443 (HTTPS, reddit)
- 10.0.0.5:53 (DNS, local)
No suspicious outbound traffic detected.
</tool_output>"""

TOOL_OUTPUT_PORTS = """<tool_output>
Listening ports:
- TCP 0.0.0.0:135 (RPC)
- TCP 0.0.0.0:445 (SMB)
- TCP 127.0.0.1:5001 (KoboldCpp)
- TCP 0.0.0.0:3389 (RDP)
- UDP 0.0.0.0:5355 (LLMNR)
</tool_output>"""

TOOL_OUTPUT_PS = """<tool_output>
Get-Process output (top 10 by CPU):
Handles  NPM(K)  PM(K)  WS(K)  CPU(s)  Id  ProcessName
-------  ------  -----  -----  ------  --  -----------
   1234    45    12340  45600   125.3   4521  powershell
    892    32     8900  23400    89.1   7832  certutil
   2341    78    34500  89000   234.7   1200  chrome
</tool_output>"""

# Multi-turn prompts: simulate step 2+ after tool output
# These are the EXACT scenarios that trigger "No ReAct structure found"
MULTI_TURN_QUERIES = [
    # After system snapshot — should call final_answer or next tool
    ("mt01_after_snapshot", f"{TOOL_OUTPUT_SNAPSHOT}\n\nYou have received tool output. Analyze and continue to the next step.", "final_answer"),
    ("mt02_after_snapshot_continue", f"{TOOL_OUTPUT_SNAPSHOT}\n\nSubtask 1 complete. Proceed to subtask 2: scan for suspicious processes.", "scan_suspicious_procs"),
    ("mt03_after_snapshot_final", f"{TOOL_OUTPUT_SNAPSHOT}\n\nAll subtasks complete. Generate the final report in Hebrew.", "final_answer"),

    # After suspicious procs — should call final_answer
    ("mt04_after_procs", f"{TOOL_OUTPUT_PROCS}\n\nYou have received tool output. Analyze and continue.", "final_answer"),
    ("mt05_after_procs_next", f"{TOOL_OUTPUT_PROCS}\n\nSubtask 2 complete. Proceed to subtask 3: check network connections.", "get_external_connections"),
    ("mt06_after_procs_final", f"{TOOL_OUTPUT_PROCS}\n\nInvestigation complete. Deliver final answer with all findings.", "final_answer"),

    # After network scan — should call final_answer
    ("mt07_after_net", f"{TOOL_OUTPUT_NET}\n\nYou have received tool output. Continue to next step.", "final_answer"),
    ("mt08_after_net_next", f"{TOOL_OUTPUT_NET}\n\nSubtask 3 complete. Proceed to final summary.", "final_answer"),
    ("mt09_after_net_procs", f"{TOOL_OUTPUT_NET}\n\nNow scan suspicious processes as the next subtask.", "scan_suspicious_procs"),

    # After ports scan
    ("mt10_after_ports", f"{TOOL_OUTPUT_PORTS}\n\nYou have received tool output. Continue.", "final_answer"),
    ("mt11_after_ports_next", f"{TOOL_OUTPUT_PORTS}\n\nCheck external connections next.", "get_external_connections"),

    # After PowerShell
    ("mt12_after_ps", f"{TOOL_OUTPUT_PS}\n\nYou have received tool output. Analyze the results.", "final_answer"),
    ("mt13_after_ps_next", f"{TOOL_OUTPUT_PS}\n\nNow scan for suspicious processes based on this data.", "scan_suspicious_procs"),

    # Multiple tool outputs in context (longer conversation)
    ("mt14_two_outputs", f"{TOOL_OUTPUT_SNAPSHOT}\n\n{TOOL_OUTPUT_PROCS}\n\nYou have received outputs from 2 tools. Generate final report.", "final_answer"),
    ("mt15_two_outputs_continue", f"{TOOL_OUTPUT_SNAPSHOT}\n\n{TOOL_OUTPUT_NET}\n\nTwo subtasks done. Check listening ports next.", "get_listening_ports"),

    # Edge cases that specifically trigger format collapse in logs
    ("mt16_just_thought", f"{TOOL_OUTPUT_SNAPSHOT}\n\nContinue to the next subtask.", None),
    ("mt17_next_subtask_vague", f"{TOOL_OUTPUT_PROCS}\n\nSubtask 2 is done. Move to the next step.", None),
    ("mt18_final_step", f"{TOOL_OUTPUT_SNAPSHOT}\n\nSubtask 5: Final summary. Report all findings in Hebrew.", "final_answer"),
    ("mt19_no_data", f"<tool_output>\nNo data returned from tool.\n</tool_output>\n\nContinue.", None),
    ("mt20_empty_output", f"<tool_output>\n\n</tool_output>\n\nAnalyze and continue.", None),

    # System warning injection (happens after format collapse)
    ("mt21_after_warning", f"{TOOL_OUTPUT_SNAPSHOT}\n\n[SYSTEM WARNING] You provided a 'Thought' but skipped the 'Action' JSON. You MUST output valid JSON tool calls using the ReAct format.", None),
    ("mt22_after_correction", f"{TOOL_OUTPUT_PROCS}\n\n[SYSTEM WARNING] Previous response had no Action. You MUST include Action and Action Input.", None),

    # Long context (simulates many rounds)
    ("mt23_long_context", f"{TOOL_OUTPUT_SNAPSHOT}\n\n{TOOL_OUTPUT_PROCS}\n\n{TOOL_OUTPUT_NET}\n\n{TOOL_OUTPUT_PORTS}\n\nAll 4 subtasks complete. Generate comprehensive final report in Hebrew.", "final_answer"),
    ("mt24_long_continue", f"{TOOL_OUTPUT_SNAPSHOT}\n\n{TOOL_OUTPUT_PROCS}\n\n{TOOL_OUTPUT_NET}\n\n3 subtasks done. Check listening ports as subtask 4.", "get_listening_ports"),

    # Ambiguous after tool output
    ("mt25_ambiguous_after", f"{TOOL_OUTPUT_SNAPSHOT}\n\nמה עכשיו?", None),
    ("mt26_ambiguous_continue", f"{TOOL_OUTPUT_PROCS}\n\nהמשך", None),
    ("mt27_ambiguous_final", f"{TOOL_OUTPUT_NET}\n\nתסכם", "final_answer"),

    # Loop detection scenario
    ("mt28_loop_detected", f"{TOOL_OUTPUT_SNAPSHOT}\n\n[SYSTEM ALERT: LOOP DETECTED] Tool 'get_system_snapshot' was ALREADY executed. Do NOT repeat it. IMMEDIATELY use 'final_answer'.", "final_answer"),
    ("mt29_loop_procs", f"{TOOL_OUTPUT_PROCS}\n\n[SYSTEM ALERT: LOOP DETECTED] Tool 'scan_suspicious_procs' was ALREADY executed. Use 'final_answer' now.", "final_answer"),
    ("mt30_loop_final", f"{TOOL_OUTPUT_PORTS}\n\n[SYSTEM ALERT: LOOP DETECTED] You have already called 'get_listening_ports'. Use 'final_answer' to generate the report.", "final_answer"),
]

output = Path(__file__).parent / "prompts_multiturn.jsonl"
with open(output, "w", encoding="utf-8") as f:
    for qid, query, expected_tool in MULTI_TURN_QUERIES:
        f.write(json.dumps({
            "id": qid,
            "system_prompt": SYSTEM_PROMPT,
            "user_prompt": query,
            "expected_tool": expected_tool,
        }, ensure_ascii=False) + "\n")

print(f"Generated {len(MULTI_TURN_QUERIES)} multi-turn prompts → {output}")
