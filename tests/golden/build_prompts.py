"""Build prompts.jsonl for the ReAct grammar spike.

Generates a representative set of user queries with a minimal system prompt
that includes a small tool catalog (6 tools). The system prompt mirrors the
real Sentinel format but is truncated for spike speed.
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

# 30 representative user queries (Hebrew + English, varying complexity)
QUERIES = [
    # Simple system queries (should be easy — 1 tool call)
    ("q01_system_status", "מה מצב המערכת עכשיו?", "get_system_snapshot"),
    ("q02_cpu_usage", "כמה CPU תפוס?", "get_system_snapshot"),
    ("q03_ram_check", "בדוק זיכרון RAM", "get_system_snapshot"),
    ("q04_disk_space", "כמה מקום פנוי בדיסק?", "get_system_snapshot"),
    ("q05_performance", "האם יש בעיות ביצועים?", "get_system_snapshot"),

    # Suspicious process queries (security-focused)
    ("q06_suspicious_procs", "סרוק תהליכים חשודים", "scan_suspicious_procs"),
    ("q07_powershell_procs", "יש תהליכי PowerShell רצים?", "scan_suspicious_procs"),
    ("q08_malware_check", "בדוק אם יש תהליכים זדוניים", "scan_suspicious_procs"),
    ("q09_certutil", "תהליך certutil רץ? זה חשוד", "scan_suspicious_procs"),
    ("q10_threat_hunt", "צוד איומים בתהליכים", "scan_suspicious_procs"),

    # Network queries
    ("q11_connections", "מה החיבורים החיצוניים הפעילים?", "get_external_connections"),
    ("q12_external_ips", "יש חיבורים לIP חיצוני?", "get_external_connections"),
    ("q13_outbound_traffic", "בדוק תעבורה יוצאת", "get_external_connections"),
    ("q14_listening_ports", "אילו פורטים פתוחים?", "get_listening_ports"),
    ("q15_open_ports", "סרוק פורטים בהאזנה", "get_listening_ports"),

    # Multi-step queries (harder — may trigger format collapse)
    ("q16_full_check", "תן לי דוח מלא: מערכת, תהליכים חשודים, ורשת", None),
    ("q17_security_audit", "בצע ביקורת אבטחה מלאה", None),
    ("q18_investigate", "חקור את המערכת לאיומים פוטנציאליים", None),
    ("q19_incident_response", "התחל תגובת אירוע: בדוק הכל", None),
    ("q20_comprehensive", "סריקה מקיפה של כל המערכת", None),

    # PowerShell queries (tool with parameters)
    ("q21_powershell_simple", "הרץ Get-Process", "run_powershell"),
    ("q22_powershell_network", "הרץ netstat -an", "run_powershell"),
    ("q23_powershell_eventlog", "בדוק event log עם PowerShell", "run_powershell"),
    ("q24_powershell_services", "הרץ Get-Service", "run_powershell"),
    ("q25_powershell_custom", "הפעל ipconfig /all", "run_powershell"),

    # Edge cases (known to trigger format collapse in logs)
    ("q26_after_tool", "You have received tool output from get_system_snapshot. Analyze and continue.", None),
    ("q27_next_subtask", "Subtask 2: Analyze alert logs for TTPs using scan_suspicious_procs", "scan_suspicious_procs"),
    ("q28_final_step", "Subtask 5: Final summary. Report all findings in Hebrew.", "final_answer"),
    ("q29_ambiguous", "תגיד לי מה קורה", None),
    ("q30_empty_context", "המשך", None),
]

output = Path(__file__).parent / "prompts.jsonl"
with open(output, "w", encoding="utf-8") as f:
    for qid, query, expected_tool in QUERIES:
        f.write(json.dumps({
            "id": qid,
            "system_prompt": SYSTEM_PROMPT,
            "user_prompt": query,
            "expected_tool": expected_tool,
        }, ensure_ascii=False) + "\n")

print(f"Generated {len(QUERIES)} prompts → {output}")
