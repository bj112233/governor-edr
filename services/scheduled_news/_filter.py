"""Keyword filter — Hebrew/ASCII aware substring matching."""

import re


class KeywordFilter:
    """Filter news items by profile keywords."""

    @staticmethod
    def filter(items: list[dict], keywords: list[str]) -> list[dict]:
        """Return items matching any keyword."""
        if not keywords:
            return items

        matched = []
        for item in items:
            text = f"{item.get('title', '')} {item.get('summary', '')}".lower()
            for kw in keywords:
                if _match_keyword(text, kw.lower()):
                    item["matched_keyword"] = kw
                    matched.append(item)
                    break
        return matched


def _match_keyword(text: str, kw_lower: str) -> bool:
    """Hebrew/ASCII aware keyword match."""
    # Hebrew / non-ASCII: \b doesn't work (\w is ASCII-only)
    if any(ord(c) > 127 for c in kw_lower):
        return kw_lower in text
    # ASCII: use word boundary
    return bool(re.search(rf"\b{re.escape(kw_lower)}\b", text))
