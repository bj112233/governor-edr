# services/thinking_parser.py
"""
Level 150: Thinking Token Parser — Single Source of Truth
מנקה תגיות חשיבה פנימיות ודליפות פרומפטים מתשובות המודל.

פורמטים נתמכים:
  - Meta-Llama-3.1 / DeepSeek-R1:  <think>...</think>
  - Generic verbose:  Thinking Process:...done thinking.
  - Leaked prompts: internal system instructions appearing in output
"""

import re
from typing import Any

_THINK_PATTERNS = [
    r"<thinking>.*?<\/thinking>",
    r"<think>.*?<\/think>",
    # GPT-OSS / OpenAI channel markers: <|channel|>thought ... <|channel|>final
    # Strip everything up to and including the final marker, keep what follows.
    r"<\|channel\|?>\s*thought.*?(?=<\|channel\|?>\s*final|$)",
    r"<\|channel\|?>\s*final\s*",
    r"<\|start\|?>.*?<\|message\|?>",
    r"<\|end\|?>",
    r"Thinking Process:.*?\.\.\.done thinking\.",
    r"Thinking Process:.*?(?=\n\n[A-Z\u0590-\u05FF]|\Z)",
    # Progress-style structured thinking - main block from Progress to end of Response Strategy
    r"^\s*(?:##?\s*)?Progress\s*\n.*?Response Strategy\s*\n.*?\n(?=\S|$)",
    # Individual section headers that might appear
    r"^\s*(?:##?\s*)?(?:Done|In Progress|Blocked|Key Decisions|Next Steps|Critical Context|Response Strategy)\s*\n",
    r"^\s*•\s*\[\s*[xX ]\s*\].*?\n",
    r"^\s*•\s*(?:Pattern Analysis|User input).*?\n",
    r"^\s*\d+\.\s*Maintain Warmth.*?(?:\n|$)",
    r"^\s*\d+\.\s*Stronger Call.*?(?:\n|$)",
]

# דליפות פרומפטים נפוצות במודלים מקומיים — מנקה מהתשובה הסופית
_LEAKED_PROMPT_PATTERNS = [
    # Internal instructions from previous context
    r"Do not infer or repeat old tasks from prior chats.*?If nothing needs attention, reply[:\s\w_]+",
    r"When reading HEARTBEAT\.md, use workspace file C:/Users/[^/]+/tactical_bot/HEARTBEAT\.md.*?exact case",
    r"\(כדי לבטא.*?If nothing needs attention, reply HEARTBEAT_OK.*?\)",
    r"\(כדי לבטא את השיחה,.*?\)",
    r"\(לאחר קריאה,.*?\)",
    r"Use workspace file C:/Users/[^/]+/tactical_bot/[^\)]+\(exact case\)",
    r"Read HEARTBEAT\.md if it exists.*?Follow it strictly",
    r"\*\*.*?HEARTBEAT_OK.*?\*\*",
    # Generic internal markers
    r"\[CRITICAL OVERRIDE\].*?\[\d{2}/\d{2}/\d{4} \d{2}:\d{2}\]",
]

_COMPILED = [re.compile(p, re.DOTALL | re.IGNORECASE | re.MULTILINE) for p in _THINK_PATTERNS]
_LEAKED_COMPILED = [re.compile(p, re.DOTALL | re.IGNORECASE) for p in _LEAKED_PROMPT_PATTERNS]


# מרקרי Final-Answer — אם אחד מהם מופיע, שומרים רק מה שאחריו (כולל המרקר)
_FINAL_ANSWER_MARKERS = [
    "תשובה:",
    "תשובה סופית:",
    "Final Answer:",
    "FINAL ANSWER:",
    "Answer:",
    "<final_answer>",
]


# Boundary-hardened final-answer matcher (variant B).
# Requires the marker to appear at the start of a (logical) line, after the
# CoT/leak strippers have already run. Markers are sorted by length DESC so
# that 'תשובה סופית:' wins over its substring 'תשובה:'.
_FINAL_MARKER_RE = re.compile(
    r"(?m)^\s*(?:" + "|".join(re.escape(m) for m in sorted(_FINAL_ANSWER_MARKERS, key=len, reverse=True)) + r")\s*"
)


def _extract_final_answer(text: str) -> str:
    """
    מחלץ את התשובה הסופית בצורה בטוחה.
    דורש שהמרקר יופיע בתחילת שורה (^ ב-multiline) כדי למנוע חיתוך טקסט
    לגיטימי כמו 'הניתוח הושלם. לגבי השאלה השנייה, התשובה: ...' בתוך פסקה.
    """
    m = _FINAL_MARKER_RE.search(text)
    if m:
        return text[m.end() :].lstrip()
    return text


def strip_thinking_content(text: str) -> str:
    """מסיר את כל בלוקי החשיבה מהטקסט — שומר רק את ה-Final Answer."""
    for pattern in _COMPILED:
        text = pattern.sub("", text)
    for pattern in _LEAKED_COMPILED:
        text = pattern.sub("", text)
    # אם המודל השאיר preamble אנליטי ('Reason:', '1. Deconstruct...') + מרקר 'תשובה:' בסוף,
    # השאר רק את התשובה הסופית.
    text = _extract_final_answer(text)
    # Strip remaining pseudo-XML tags (e.g. </final_answer>) while keeping content
    text = re.sub(r"</?final_answer>\s*", "", text)
    return text.strip()


def clean_assistant_message(msg: dict[str, Any]) -> dict[str, Any]:
    """
    מנקה הודעת assistant לפני הכנסה להיסטוריה.
    - מוחק שדה 'thinking' מובנה (structured thinking API field)
    - מנקה תגיות חשיבה inline מתוך ה-content
    הזנת תהליך החשיבה חזרה ל-Prompt תגרום ל-Role Confusion ובזבוז טוקנים.
    """
    cleaned = {k: v for k, v in msg.items() if k != "thinking"}
    if cleaned.get("content"):
        cleaned["content"] = strip_thinking_content(cleaned["content"])
    return cleaned
