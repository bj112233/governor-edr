import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOG_DIR = Path(__file__).parent / "logs"
_FMT = "%(asctime)s - %(levelname)s - %(name)s - %(message)s"
_MAX_BYTES = 2_000_000  # 2 MB per file
_BACKUPS = 5


def setup_logging() -> None:
    """מגדירה logging אחיד לכל ה-process — נקראת פעם אחת מ-main().

    Handlers:
      * RotatingFileHandler → logs/bot.log (INFO+, 2MB×5)
      * RotatingFileHandler → logs/bot_err.log (ERROR+, 2MB×3)

    Filenames are distinct from NSSM-managed `sentinel_*.log` / `gw_*.log`
    redirects to avoid Windows file-lock conflicts during rotation.
      * StreamHandler → stderr (תאימות ל-NSSM redirect הקיים)
    """
    _LOG_DIR.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter(_FMT)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    # Avoid duplicate handlers if called twice.
    for h in list(root.handlers):
        root.removeHandler(h)

    info_h = RotatingFileHandler(
        _LOG_DIR / "bot.log",
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUPS,
        encoding="utf-8",
    )
    info_h.setLevel(logging.INFO)
    info_h.setFormatter(formatter)
    root.addHandler(info_h)

    err_h = RotatingFileHandler(
        _LOG_DIR / "bot_err.log",
        maxBytes=_MAX_BYTES,
        backupCount=3,
        encoding="utf-8",
    )
    err_h.setLevel(logging.ERROR)
    err_h.setFormatter(formatter)
    root.addHandler(err_h)

    stream_h = logging.StreamHandler()
    stream_h.setLevel(logging.INFO)
    stream_h.setFormatter(formatter)
    root.addHandler(stream_h)

    logging.getLogger("services.llm_bridge").setLevel(logging.INFO)
    # Quieten noisy 3rd-party libs in rotated files.
    for noisy in ("urllib3", "httpx", "httpcore", "aiogram.event"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    # Allow override via env without code change.
    lvl = os.getenv("SENTINEL_LOG_LEVEL")
    if lvl:
        try:
            root.setLevel(getattr(logging, lvl.upper()))
        except AttributeError:
            pass
