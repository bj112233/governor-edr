"""Content extractors — text, tables, prices, hashing, CSV serialization."""

from __future__ import annotations

import csv
import hashlib
import io
import re

from bs4 import BeautifulSoup


def extract_text(html: str, selector: str, limit: int = 0):
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "header", "footer"]):
        tag.decompose()
    items = soup.select(selector)
    if limit and limit > 0:
        items = items[:limit]
    return "\n\n".join(item.get_text(strip=True, separator=" ") for item in items)


def extract_table(html: str, selector: str):
    soup = BeautifulSoup(html, "html.parser")
    table = soup.select_one(selector)
    if not table:
        return []
    rows = []
    for tr in table.find_all("tr"):
        row = [td.get_text(strip=True) for td in tr.find_all(["td", "th"])]
        if row:
            rows.append(row)
    return rows


def extract_price(html: str, selector: str):
    soup = BeautifulSoup(html, "html.parser")
    el = soup.select_one(selector)
    if not el:
        return None
    text = el.get_text(strip=True)

    # Match a number that may contain thousands separators and a decimal part.
    # Supports: 1234, 1,234, 1.234, 1,234.56, 1.234,56
    m = re.search(r"\d{1,3}(?:[.,]\d{3})*(?:[.,]\d+)?|\d+(?:[.,]\d+)?", text)
    if not m:
        return None
    raw = m.group()
    # Decide decimal separator: the rightmost separator with 1-2 trailing digits
    # is treated as decimal; everything else is a thousands separator.
    last_dot = raw.rfind(".")
    last_comma = raw.rfind(",")
    dec_idx = max(last_dot, last_comma)
    if dec_idx != -1 and len(raw) - dec_idx - 1 in (1, 2):
        int_part = re.sub(r"[.,]", "", raw[:dec_idx])
        frac_part = raw[dec_idx + 1 :]
        normalized = f"{int_part}.{frac_part}"
    else:
        normalized = re.sub(r"[.,]", "", raw)
    try:
        return float(normalized)
    except ValueError:
        return None


def hash_content(html: str):
    return hashlib.sha256(html.encode("utf-8")).hexdigest()[:16]


def to_csv(rows, output=None):
    if output:
        with open(output, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerows(rows)
        return f"✅ CSV saved: {output}"
    else:
        s = io.StringIO()
        w = csv.writer(s)
        w.writerows(rows)
        return s.getvalue()
