# services/credential_format.py
"""Formatting for credential leak scan results (ReAct observation text).

Extracted from credential_monitor.py to keep files < 300 lines (SRP) and to
flatten nesting — cognitive complexity is nesting-weighted, so splitting the
per-source / per-item / per-credential-type loops into separate functions
collapses a single 40-point function into several single-digit ones.
"""

from typing import Any

from services.credential_patterns import mask_credential

_MAX_ITEMS_SHOWN = 5
_MAX_CREDS_SHOWN = 2
_SNIPPET_LEN = 100


def _collect_item_credentials(item: dict[str, Any]) -> dict[str, list[str]]:
    """Merge credentials/snippet_credentials/raw_credentials into one dict."""
    merged: dict[str, list[str]] = {}
    for key in ("credentials", "snippet_credentials", "raw_credentials"):
        creds = item.get(key, {})
        if not isinstance(creds, dict):
            continue
        for ctype, cvals in creds.items():
            merged.setdefault(ctype, []).extend(cvals)
    return merged


def _format_credential_lines(all_creds: dict[str, list[str]]) -> list[str]:
    """Render the 'Credentials found' block for one item."""
    if not all_creds:
        return []
    lines = ["  Credentials found:"]
    for ctype, cvals in all_creds.items():
        lines.append(f"    {ctype}: {len(cvals)} match(es)")
        lines.extend(f"      {mask_credential(v)}" for v in cvals[:_MAX_CREDS_SHOWN])
    return lines


def _format_item(item: dict[str, Any]) -> list[str]:
    """Render one search-result item (URL, snippet, credentials)."""
    lines = [f"  URL: {item.get('url', '?')}"]
    snippet = (item.get("snippet", "") or "")[:_SNIPPET_LEN]
    if snippet:
        lines.append(f"  Snippet: {snippet}")
    lines.extend(_format_credential_lines(_collect_item_credentials(item)))
    return lines


def _format_source(source_name: str, source_data: Any) -> list[str]:
    """Render one source's block: error / empty / list of items."""
    if isinstance(source_data, dict) and source_data.get("error"):
        return [f"\n[{source_name}] Error: {source_data['error']}"]
    if not isinstance(source_data, list) or not source_data:
        return [f"\n[{source_name}] No results"]

    lines = [f"\n[{source_name}] {len(source_data)} results"]
    for item in source_data[:_MAX_ITEMS_SHOWN]:
        lines.extend(_format_item(item))
    if len(source_data) > _MAX_ITEMS_SHOWN:
        lines.append(f"  ... and {len(source_data) - _MAX_ITEMS_SHOWN} more")
    return lines


def format_credential_results(results: dict[str, Any]) -> str:
    """Format credential scan results as text for ReAct observation."""
    lines: list[str] = [
        f"Credential leak scan for: {results.get('query', '?')}",
        f"Total credential hits: {results.get('total_hits', 0)}",
    ]
    for source_name, source_data in results.get("sources", {}).items():
        lines.extend(_format_source(source_name, source_data))

    return "\n".join(lines) if lines else "No credential leaks found."
