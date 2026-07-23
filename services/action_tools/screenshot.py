# services/action_tools/screenshot.py
"""Desktop screenshot capture."""

import ctypes
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).parent.parent.parent


def _local_screenshot_exec() -> str:
    """INTERNAL executor — actually capture the desktop."""
    try:
        session_id = ctypes.windll.kernel32.GetCurrentProcessId()
        sess = ctypes.c_uint32()
        success = ctypes.windll.kernel32.ProcessIdToSessionId(session_id, ctypes.byref(sess))
        if not success or sess.value == 0:
            return (
                "❌ צילום מסך לא זמין כאשר הבוט רץ כ-Service (Windows Session 0).\n"
                "לשימוש ב-/screenshot: הפעל את הבוט ידנית (python main.py) "
                "כאשר משתמש מחובר ל-desktop."
            )
    except Exception:
        pass

    try:
        import mss
        from PIL import Image

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = _PROJECT_ROOT / "state" / f"screenshot_{ts}.png"
        dest.parent.mkdir(parents=True, exist_ok=True)

        with mss.mss() as sct:
            monitor = sct.monitors[0]
            screenshot = sct.grab(monitor)
            img = Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")
            img.save(str(dest), "PNG")

        logger.info("[action_tools] local_screenshot saved: %s", dest)
        return f"✅ Screenshot שמור: {dest} ({img.width}x{img.height})"
    except ImportError:
        return "❌ mss/Pillow לא מותקן — הרץ: pip install mss Pillow"
    except Exception as e:
        logger.error("[action_tools] local_screenshot error: %s", e)
        if "BitBlt" in str(e):
            return (
                "❌ שגיאת צילום מסך: אין desktop session פעיל.\n"
                "הפעל את הבוט ידנית (python main.py) במקום כ-Service כדי לאפשר צילום מסך."
            )
        return f"❌ שגיאה: {e}"


async def local_screenshot() -> str:
    """Capture desktop screenshot — HITL-protected via pending action.

    SECURITY: No fast-path. Every screenshot queues for user approval
    (privacy: autonomous desktop capture without consent is prohibited).
    The actual capture runs via _local_screenshot_exec after /approve.
    """
    from services.pending_actions import set_pending

    await set_pending(
        {"action": "screenshot", "target": "", "reason": "Desktop screenshot capture pending user approval"}
    )
    return "⏳ PENDING_APPROVAL: Screenshot queued. Use /approve to capture or /deny to cancel."
