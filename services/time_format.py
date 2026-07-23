"""Unified timestamp formatting for all bot outputs (SSOT).

Standard:
- Feeds (RSS/Atom): RFC-2822/822 -> UTC -> local Israel time via zoneinfo.
- System events (Sentinel/alerts): local Israel time via zoneinfo.
- Default to UTC when a feed pubDate lacks tzinfo.
"""

from __future__ import annotations

import calendar
import re
import time
import zoneinfo
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

ISRAEL_FMT = "%d/%m/%Y %H:%M"
ISRAEL_FMT_SEC = "%d/%m/%Y %H:%M:%S"
ISRAEL_FMT_SHORT = "%d/%m %H:%M"

ISRAELI_SOURCES = {
    "walla",
    "ynet",
    "n12",
    "maariv",
    "haaretz",
    "israel hayom",
    "jerusalem post",
    "times of israel",
    "globes",
    "israel national news",
    "vesty",
}

# Sources that publish local Jerusalem time but mislabel it as "GMT"/"UTC"
# in their RSS pubDate. feedparser trusts the label and treats it as real UTC,
# so we must apply the Israeli correction to get the right local time.
# Verified 2026-07-05: Walla's "GMT" articles are ~3h ahead of real UTC (i.e.
# they are actually IDT). Maariv's "GMT" is real UTC (articles align with UTC).
_MISLABELED_GMT_SOURCES = frozenset({"walla"})

# Numeric timezone offset in an RFC-2822 date (e.g. " +0300", " -05:00").
_NUMERIC_TZ_RE = re.compile(r"[+-]\d{2}:?\d{2}\s*$")
# "GMT" or "UTC" label in an RFC-2822 date.
_GMT_UTC_RE = re.compile(r"\b(?:GMT|UTC)\b", re.IGNORECASE)

_JERUSALEM = zoneinfo.ZoneInfo("Asia/Jerusalem")


def _is_israeli(item: dict) -> bool:
    """Detect Israeli feeds that publish local time without tzinfo."""
    if item.get("category") == "israel":
        return True
    source = (item.get("source", "") or "").lower()
    return any(s in source for s in ISRAELI_SOURCES)


def _is_mislabeled_gmt(item: dict) -> bool:
    """True if the source publishes local time mislabeled as GMT/UTC."""
    source = (item.get("source", "") or "").lower()
    return any(s in source for s in _MISLABELED_GMT_SOURCES)


def _raw_has_numeric_tz(raw: str) -> bool:
    """True if the raw pubDate string carries a numeric timezone offset."""
    return bool(raw and _NUMERIC_TZ_RE.search(raw))


def _raw_has_gmt_utc_label(raw: str) -> bool:
    """True if the raw pubDate string carries a GMT/UTC label."""
    return bool(raw and _GMT_UTC_RE.search(raw))


def _to_jerusalem(dt: datetime) -> datetime:
    """Presentation layer: convert UTC datetime to Asia/Jerusalem."""
    return dt.astimezone(_JERUSALEM)


def _needs_israeli_correction(item: dict, raw_pub: str) -> bool:
    """Decide whether the Israeli timezone correction applies to this item.

    Only apply it when the raw pubDate does NOT carry a real numeric tz
    offset AND either (a) there's no tz label at all, or (b) the source
    is known to mislabel local time as GMT/UTC.
    """
    if not _is_israeli(item):
        return False
    if _raw_has_numeric_tz(raw_pub):
        return False  # feedparser already converted correctly
    if not _raw_has_gmt_utc_label(raw_pub):
        return True  # naive pubDate from Israeli source → treat as local
    return _is_mislabeled_gmt(item)  # GMT/UTC label: only correct if mislabeled


def _attach_tz(dt: datetime, needs_correction: bool) -> datetime:
    """Attach Jerusalem tz when correction needed, else UTC."""
    return dt.replace(tzinfo=_JERUSALEM if needs_correction else UTC)


def feed_timestamp_to_epoch(item: dict) -> float | None:
    """Parse a feed item's pubDate to UTC epoch seconds.

    Shared parsing logic for format_feed_time (display) and freshness
    filtering (age check). Returns None when no valid timestamp is found.

    Timezone handling for Israeli sources:
    - Numeric offset (e.g. "+0300"): feedparser already converted to UTC
      correctly — no correction needed.
    - "GMT"/"UTC" label from a known mislabeled source (e.g. Walla): the
      label is a lie; the feed actually publishes local Jerusalem time.
      Apply the Israeli correction (treat UTC ts as naive local → real UTC).
    - "GMT"/"UTC" label from a trusted source (e.g. Maariv): the label is
      honest; feedparser's UTC conversion is correct — no correction.
    - No timezone info at all: feedparser assumes UTC. For Israeli sources,
      the pubDate is actually local Jerusalem time — apply correction.
    """
    raw_pub = item.get("published") or ""
    needs_correction = _needs_israeli_correction(item, raw_pub)

    pp = item.get("published_parsed")
    if pp and isinstance(pp, (tuple, list, time.struct_time)):
        try:
            ts = calendar.timegm(tuple(pp))
            if needs_correction:
                fake_utc_dt = datetime.fromtimestamp(ts, tz=UTC).replace(tzinfo=None)
                real_il_dt = fake_utc_dt.replace(tzinfo=_JERUSALEM)
                ts = int(real_il_dt.astimezone(UTC).timestamp())
            return float(ts)
        except (ValueError, TypeError, OverflowError):
            pass

    try:
        dt = parsedate_to_datetime(raw_pub)
        if needs_correction:
            # Mislabeled GMT/UTC: the tzinfo from parsedate_to_datetime is a lie
            # (feedparser trusts the "GMT" label). Strip it and re-attach Jerusalem.
            dt = dt.replace(tzinfo=None)
            dt = _attach_tz(dt, needs_correction)
        elif dt.tzinfo is None:
            dt = _attach_tz(dt, needs_correction)
        dt = dt.astimezone(UTC)
        return dt.timestamp()
    except (TypeError, ValueError):
        pass

    # ISO-8601 fallback (e.g. "2026-05-27T12:22:52Z")
    try:
        dt = datetime.fromisoformat(str(raw_pub).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = _attach_tz(dt, needs_correction)
        dt = dt.astimezone(UTC)
        return dt.timestamp()
    except (TypeError, ValueError):
        return None


def format_feed_time(item: dict, with_seconds: bool = False) -> str:
    """Normalize a feedparser entry pubDate to UTC, then format as Jerusalem time.

    Delegates parsing to feed_timestamp_to_epoch, then formats as Jerusalem time.
    Falls back to raw string truncation when no valid timestamp is found.
    """
    fmt = ISRAEL_FMT_SEC if with_seconds else ISRAEL_FMT
    ts = feed_timestamp_to_epoch(item)
    if ts is not None:
        dt = datetime.fromtimestamp(ts, tz=UTC)
        return _to_jerusalem(dt).strftime(fmt)
    return str(item.get("published") or "")[:40]


def format_feed_time_short(item_or_raw) -> str:
    """Short variant (no year) for daily digests. Accepts dict or raw str."""
    item = item_or_raw if isinstance(item_or_raw, dict) else {"published": item_or_raw or ""}
    full = format_feed_time(item, with_seconds=False)
    try:
        date_part, rest = full.split(" ", 1)
        d, m, _y = date_part.split("/")
        return f"{d}/{m} {rest}"
    except Exception:
        return full


def format_event_time(ts: float | None = None, with_date: bool = False) -> str:
    """Format Unix epoch timestamp for system events (Sentinel).
    If ts is None, uses current time. Output is Asia/Jerusalem time."""
    fmt = ISRAEL_FMT_SEC if with_date else "%H:%M:%S"
    if ts is None:
        return datetime.now(_JERUSALEM).strftime(fmt)
    return datetime.fromtimestamp(ts, tz=UTC).astimezone(_JERUSALEM).strftime(fmt)


def format_now(with_date: bool = True) -> str:
    """Backward-compat alias. Prefer format_event_time()."""
    return format_event_time(ts=None, with_date=with_date)


# ISO 8601 date for report headers/filenames (SSOT for all batch reports).
_REPORT_DATE_FMT = "%Y-%m-%d"


def format_report_date(ts: float | None = None) -> str:
    """ISO 8601 date (YYYY-MM-DD) in Jerusalem time for report headers/filenames.

    Replaces the divergent %d/%m/%Y (Daily Security), %Y%m%d (CTI/News filenames),
    and ad-hoc datetime.now().strftime() calls across report generators.
    """
    if ts is None:
        return datetime.now(_JERUSALEM).strftime(_REPORT_DATE_FMT)
    return datetime.fromtimestamp(ts, tz=UTC).astimezone(_JERUSALEM).strftime(_REPORT_DATE_FMT)
