# services/action_tools/files.py
"""Sandboxed file write — ONLY writes to whitelisted paths."""

import logging
from pathlib import Path

from .security import is_extension_blocked, is_path_write_allowed

logger = logging.getLogger(__name__)


def write_file(path: str, content: str) -> str:
    """Write content to file — allowed only in whitelisted project subdirs."""
    try:
        target = Path(path).resolve()
    except Exception as e:
        return f"❌ נתיב לא תקין: {e}"

    if not is_path_write_allowed(target):
        from .security import _WRITE_ALLOWED_ROOTS

        return (
            f"❌ כתיבה חסומה: '{target}' אינו בתוך נתיבים מותרים.\n"
            f"מותר: {', '.join(str(r) for r in _WRITE_ALLOWED_ROOTS)}"
        )

    if is_extension_blocked(target):
        return f"❌ כתיבה חסומה לסיומת: {target.suffix}"

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        logger.info("[action_tools] write_file: %s (%d chars)", target, len(content))
        return f"✅ נכתבו {len(content)} תווים ל-{target}"
    except Exception as e:
        logger.error("[action_tools] write_file error: %s", e)
        return f"❌ שגיאה בכתיבה: {e}"
