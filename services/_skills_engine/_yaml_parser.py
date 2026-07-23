# services/_skills_engine/_yaml_parser.py
"""YAML frontmatter parser with graceful fallback."""

from typing import Any

__all__ = ["yaml", "parse_frontmatter", "SimpleYAML"]

# -- 1. Industrial library loading --
try:
    import yaml
except ModuleNotFoundError as _e:  # noqa: F841
    yaml = None

if yaml is None:
    try:
        import ruamel.yaml as yaml
    except ModuleNotFoundError:
        yaml = None


# -- 2. Fallback engine -- always defined unconditionally --
def _parse_yaml_value(value: str) -> Any:
    """Parse a YAML scalar value into Python type."""
    value = value.strip()
    if not value:
        return ""
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    low = value.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~", ""):
        return None
    try:
        if "." in value or "e" in low or "E" in value:
            return float(value)
        return int(value)
    except ValueError:
        pass
    return value


def _indent(line_str: str) -> int:
    """Return indentation level of a line."""
    return len(line_str) - len(line_str.lstrip())


def _parse_sub_dict(lines: list[str], k: int, base_indent: int) -> tuple[dict[str, Any], int]:
    """Parse a sub-dictionary under a list item."""
    sub_dict: dict[str, Any] = {}
    k += 1
    sub_indent = _indent(lines[k]) if k < len(lines) else base_indent + 2
    while k < len(lines):
        sub_line = lines[k]
        if not sub_line.strip():
            k += 1
            continue
        if _indent(sub_line) <= base_indent:
            break
        if _indent(sub_line) < sub_indent:
            sub_indent = _indent(sub_line)
        sub_s = sub_line.strip()
        if ":" in sub_s:
            sk, sv = sub_s.split(":", 1)
            sk = sk.strip()
            sv = sv.strip()
            if sv:
                sub_dict[sk] = _parse_yaml_value(sv)
            else:
                val, k = _parse_block(lines, k + 1, _indent(lines[k]))
                sub_dict[sk] = val
                continue
        k += 1
    return sub_dict, k


def _parse_list_item(item_text: str, lines: list[str], k: int, base_indent: int) -> tuple[Any, int]:
    """Parse a single list item, potentially a sub-dict."""
    if ":" in item_text:
        sub_key, sub_val = item_text.split(":", 1)
        sub_key = sub_key.strip()
        sub_val = sub_val.strip()
        if sub_val:
            return {sub_key: _parse_yaml_value(sub_val)}, k
        sub_dict, k = _parse_sub_dict(lines, k, base_indent)
        return sub_dict, k
    return _parse_yaml_value(item_text), k


def _parse_block(lines: list[str], start_idx: int, base_indent: int) -> tuple[Any, int]:
    """Parse a YAML block (list or scalar) starting at start_idx."""
    j = start_idx
    while j < len(lines) and (not lines[j].strip() or _indent(lines[j]) > base_indent):
        j += 1
    list_candidates = [lines[k].strip() for k in range(start_idx, j) if lines[k].strip()]
    if list_candidates and all(lc.startswith("- ") for lc in list_candidates):
        items: list[Any] = []
        k = start_idx
        while k < len(lines):
            line = lines[k]
            if not line.strip():
                k += 1
                continue
            if _indent(line) <= base_indent and not line.strip().startswith("-"):
                break
            if line.strip().startswith("- "):
                item_text = line.strip()[2:]
                item, k = _parse_list_item(item_text, lines, k, base_indent)
                items.append(item)
            k += 1
        return items, k
    return _parse_yaml_value(lines[start_idx].strip()), start_idx + 1


def _parse_dotted_key(
    metadata: dict[str, Any], key: str, value: str, lines: list[str], i: int, indent: int
) -> tuple[bool, int]:
    """Parse a dotted key (e.g. 'a.b.c: value'). Returns (handled, new_i)."""
    if "." not in key or " " in key:
        return False, i
    key_parts = key.split(".")
    current = metadata
    for part in key_parts[:-1]:
        if part not in current:
            current[part] = {}
        current = current[part]
    if value:
        current[key_parts[-1]] = _parse_yaml_value(value)
        return True, i + 1
    val, i = _parse_block(lines, i + 1, indent)
    current[key_parts[-1]] = val
    return True, i


def _fallback_parse(content: str) -> tuple[dict[str, Any], str]:
    """Parse YAML frontmatter without external libraries."""
    if not content.startswith("---"):
        return {}, content

    parts = content.split("---", 2)
    if len(parts) < 3:
        return {}, content

    lines = parts[1].split("\n")
    body = parts[2].strip()
    metadata: dict[str, Any] = {}
    i = 0

    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.strip().startswith("#"):
            i += 1
            continue
        if ":" not in line:
            i += 1
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        indent = _indent(line)

        handled, new_i = _parse_dotted_key(metadata, key, value, lines, i, indent)
        if handled:
            i = new_i
            continue

        if value:
            metadata[key] = _parse_yaml_value(value)
        else:
            val, i = _parse_block(lines, i + 1, indent)
            metadata[key] = val
            continue
        i += 1

    return metadata, body


class SimpleYAML:
    @staticmethod
    def safe_load(content: str) -> dict[str, Any]:
        metadata, _ = _fallback_parse("---\n" + content + "\n---\n")
        return metadata


# -- 3. Active engine selection --
if yaml is None:
    yaml = SimpleYAML()


# -- 4. Unconditional public API --
def parse_frontmatter(content: str) -> tuple[dict[str, Any], str]:
    """Universal frontmatter extraction and parsing."""
    if isinstance(yaml, SimpleYAML):
        return _fallback_parse(content)

    if not content.startswith("---"):
        return {}, content

    parts = content.split("---", 2)
    if len(parts) < 3:
        return {}, content

    yaml_text = parts[1].strip()
    body_text = parts[2].strip()

    if not yaml_text:
        return {}, body_text

    try:
        metadata = yaml.safe_load(yaml_text) or {}
        if not isinstance(metadata, dict):
            metadata = {}
    except Exception:
        metadata = {}

    return metadata, body_text
