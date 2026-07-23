# services/news_ai/prompts.py
"""Prompt builders + response parsers + text helpers. Pure functions, no LLM calls."""

import logging
import re
from typing import Optional

from ._security import sanitize, wrap_untrusted_block

logger = logging.getLogger(__name__)

_RE_BULK_ITEM = re.compile(
    r"(\d+)\.\s*Summary:\s*(.*?)\s*Sentiment:\s*(positive|negative|neutral)",
    re.IGNORECASE | re.DOTALL,
)

_CLUSTER_HEADER_RE = re.compile(
    r"^\s*(?:[\*#>\-]+\s*)?"
    r"(?:\[\s*(?:cluster\s*|group\s*)?(\d+)\s*]"
    r"|(?:cluster\s*|group\s*)?(\d+))"
    r"[\.\):]\s*(.*)$",
    re.IGNORECASE,
)


def _normalize(text: str) -> str:
    """Normalize for comparison: lowercase, strip, remove punctuation."""
    return re.sub(r"[^\w\sא-ת]", "", text.lower().strip())


def _is_title_echo(title: str, summary: str) -> bool:
    """Return True if summary is identical or near-identical to title.

    Uses Jaccard token overlap ratio (>= 0.8) instead of substring match
    to avoid false positives like "Attack on Israel" ⊂ "Attack on Israel's borders".
    """
    if not title or not summary:
        return False
    t = _normalize(title)
    s = _normalize(summary)
    if t == s:
        return True
    # Jaccard similarity: |intersection| / |union| of word sets
    t_words = set(t.split())
    s_words = set(s.split())
    if not t_words or not s_words:
        return False
    overlap = len(t_words & s_words)
    union = len(t_words | s_words)
    jaccard = overlap / union if union > 0 else 0
    # High overlap = summary just echoes title words
    if jaccard >= 0.8:
        return True
    # Short title edge case: if title is ≤3 words and all appear in summary
    if len(t_words) <= 3 and t_words <= s_words:
        return True
    return False


# ── Bulk enrich prompt builders ──


def build_bulk_prompt(items: list[dict]) -> str:
    header = "\n".join(
        [
            "For each numbered item below, provide:",
            "1. A one-sentence summary in Hebrew (keep cyber/tech terms in English)",
            "2. The sentiment: exactly one of positive / negative / neutral",
            "",
            "Format your reply exactly like this:",
            "1. Summary: <sentence>",
            "   Sentiment: <positive/negative/neutral>",
            "2. Summary: <sentence>",
            "   Sentiment: <positive/negative/neutral>",
            "...",
            "",
            "Items:",
        ]
    )
    item_lines = []
    for i, it in enumerate(items, 1):
        title = sanitize(it.get("title", "").strip())
        text = sanitize((it.get("full_text", "") or it.get("summary", ""))[:400])
        item_lines.append(f"{i}. Title: {title} | Text: {text}")
    return header + "\n" + wrap_untrusted_block("\n".join(item_lines))


def parse_bulk_response(text: str, n: int) -> list[dict]:
    out: list[dict] = [{"summary": "", "sentiment": "unknown"} for _ in range(n)]
    if not text:
        return out
    for m in _RE_BULK_ITEM.finditer(text):
        try:
            idx = int(m.group(1)) - 1
            if 0 <= idx < n:
                out[idx]["summary"] = m.group(2).strip()
                out[idx]["sentiment"] = m.group(3).strip().lower()
        except (ValueError, IndexError):
            continue
    return out


# ── Bulk summarize prompt builders ──


def build_bulk_summarize_prompt(items: list[dict]) -> str:
    header = "\n".join(
        [
            "You are a news summarizer. Summarize each article in EXACTLY ONE sentence.",
            "CRITICAL RULES:",
            "- Write the summary ONLY in Hebrew. Do NOT use English, except cyber terms.",
            "- Keep cyber terms in English: MITRE ATT&CK, TTP, IOC, Encoded Commands, Execution Policy Bypass, Defense Evasion, Persistence.",
            "- Do NOT repeat the title.",
            "- Extract NEW information from the body text.",
            "- If body text is empty, reply with a single dash '-'.",
            "",
            "CRITICAL: Reply in EXACTLY this format, one per line. No markdown, no labels, no extra text:",
            "1. <summary sentence>",
            "2. <summary sentence>",
            "",
            "Example (Hebrew):",
            '1. צה"ל תקף עמדות חיזבאללה בדרום לבנון בתגובה לשיגורים לעבר יישובי הצפון',
            "",
            "Items:",
        ]
    )
    item_lines = []
    for i, it in enumerate(items, 1):
        title = sanitize(it.get("title", "").strip())
        text = sanitize((it.get("full_text", "") or it.get("summary", ""))[:300])
        item_lines.append(f"{i}. Title: {title}")
        item_lines.append(f"   Text: {text}")
    return header + "\n" + wrap_untrusted_block("\n".join(item_lines))


def parse_bulk_summarize(text: str, n: int, items: list[dict]) -> list[str]:
    out: list[str] = [""] * n
    if not text:
        return out
    _RE_PATTERN = re.compile(
        r"^\s*(?:\*\*)?(\d+)(?:\*\*)?\.\s*(?:Summary:|סיכום:)?\s*(.+)$",
        re.IGNORECASE,
    )
    for line in (text or "").splitlines():
        m = _RE_PATTERN.match(line)
        if m:
            try:
                idx = int(m.group(1)) - 1
                if 0 <= idx < n:
                    if out[idx]:
                        continue
                    val = m.group(2).strip()
                    val = re.sub(r"^<summary>\s*|\s*</summary>$", "", val)
                    if val == "-" or _is_title_echo(items[idx].get("title", ""), val):
                        out[idx] = ""
                    else:
                        out[idx] = val
            except (ValueError, IndexError):
                continue
    return out


# ── Bulk sentiment prompt builders ──


def build_bulk_sentiment_prompt(items: list[dict]) -> str:
    header = "\n".join(
        [
            "You are a sentiment classifier. For each item, reply with EXACTLY ONE word.",
            "CRITICAL RULES:",
            "- Reply with EXACTLY one English word: positive / negative / neutral.",
            "",
            "CRITICAL: Reply in EXACTLY this format, one per line. No extra text:",
            "1. positive",
            "2. negative",
            "",
            "Items:",
        ]
    )
    item_lines = []
    for i, it in enumerate(items, 1):
        title = sanitize(it.get("title", "").strip())
        text = sanitize((it.get("full_text", "") or it.get("summary", ""))[:300])
        item_lines.append(f"{i}. {title} | {text}")
    return header + "\n" + wrap_untrusted_block("\n".join(item_lines))


def parse_bulk_sentiment(text: str, n: int) -> list[str]:
    out: list[str] = ["unknown"] * n
    if not text:
        return out
    _RE_PATTERN = re.compile(
        r"^\s*(?:\*\*)?(\d+)(?:\*\*)?\.\s*(?:Sentiment:|סנטימנט:)?\s*(.+)$",
        re.IGNORECASE,
    )
    for line in (text or "").splitlines():
        m = _RE_PATTERN.match(line)
        if m:
            try:
                idx = int(m.group(1)) - 1
                if 0 <= idx < n:
                    clean = m.group(2).strip().lower().rstrip(".")
                    if clean in ("positive", "negative", "neutral"):
                        out[idx] = clean
            except (ValueError, IndexError):
                continue
    if all(s == "unknown" for s in out):
        found: list[str] = []
        for m in re.finditer(r"\b(positive|negative|neutral)\b", text, re.IGNORECASE):
            found.append(m.group(1).lower())
        # Fail-Safe: only apply positional mapping if count matches exactly.
        # If the LLM skipped an item, positional mapping shifts all results
        # by one, corrupting the entire batch. Better to leave "unknown".
        if len(found) == n:
            for i, s in enumerate(found):
                out[i] = s
        else:
            logger.warning(
                "Sentiment fallback length mismatch: expected %d, found %d. Aborting fallback.",
                n,
                len(found),
            )
    return out


# ── Cluster prompt builders ──


def build_cluster_prompt(clusters: list[list[dict]]) -> str:
    header = (
        "You are a tactical news analyst. Summarize the following news clusters.\n"
        "For EACH cluster, provide EXACTLY this format:\n"
        "[Cluster Number]. [Headline - max 10 words]\n"
        "- [Key insight 1, details/numbers, max 14 words]\n"
        "- [Key insight 2, details/numbers, max 14 words]\n"
        "- [Key insight 3, details/numbers, max 14 words]\n\n"
        "CRITICAL: Write the headline and insights ONLY in Hebrew.\n"
        "Keep cyber/tech terms in English: MITRE ATT&CK, TTP, IOC, etc.\n"
        "Do NOT translate Hebrew source text to English.\n\n"
    )
    body = ""
    for i, cluster in enumerate(clusters, 1):
        body += f"--- Cluster {i} ---\n"
        for a in cluster[:5]:
            t = sanitize(a.get("title", ""))
            s = sanitize(a.get("summary", ""))
            body += f"Title: {t}\nSummary: {s[:150]}\n"
        body += "\n"
    return header + wrap_untrusted_block(body)


def parse_cluster_response(text: str, expected_count: int) -> list[str]:
    """State-machine parser: group headline + bullets per cluster.

    Falls back to line-by-line parsing if state machine finds 0 clusters.
    """
    clusters: list[str] = []
    current_cluster: list[str] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip().strip("*").strip()
        if not line:
            continue
        m = _CLUSTER_HEADER_RE.match(line)
        if m:
            headline_text = m.group(3) if m.lastindex and m.lastindex >= 3 else None
            if headline_text is None:
                continue
            if current_cluster:
                clusters.append("\n".join(current_cluster))
                current_cluster = []
            clean_line = headline_text.replace("Headline:", "").replace("כותרת:", "").strip().strip("*").strip()
            if clean_line:
                current_cluster.append(clean_line)
            continue
        if current_cluster:
            if line.startswith(("-", "•", "*", "·", "—", "–")):
                current_cluster.append(line)
            else:
                current_cluster.append(f"  {line}")
    if current_cluster:
        clusters.append("\n".join(current_cluster))

    # Fallback: line-by-line parsing if state machine found nothing
    if not clusters and text:
        clusters = _fallback_cluster_parse(text, expected_count)

    if not clusters:
        logger.warning(
            "[NewsAI] cluster parser found 0 clusters. Raw (first 400 chars): %r",
            (text or "")[:400],
        )
    while len(clusters) < expected_count:
        clusters.append("")
    return clusters[:expected_count]


def _fallback_cluster_parse(text: str, expected_count: int) -> list[str]:
    """Line-by-line fallback: split on blank lines, treat each block as a cluster."""
    blocks: list[str] = []
    current: list[str] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            if current:
                blocks.append("\n".join(current))
                current = []
            continue
        # Strip bullet markers for cleaner output
        clean = line.lstrip("-•*·—–").strip()
        if clean:
            current.append(clean)
    if current:
        blocks.append("\n".join(current))
    if blocks:
        logger.info("[NewsAI] Fallback cluster parser found %d blocks", len(blocks))
    return blocks[:expected_count]
