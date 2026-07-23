# services/ip_enrich.py
"""Local GeoIP/ASN enrichment via geoip2 .mmdb databases.
Air-gapped — zero external APIs. Reader loaded once at init.
All new files < 300 lines (SRP).
"""

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from config import GEOIP_DB_PATH

try:
    import geoip2.database

    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False

logger = logging.getLogger(__name__)

_DEFAULT_CITY_DB = str(Path(GEOIP_DB_PATH) / "GeoLite2-City.mmdb")
_DEFAULT_ASN_DB = str(Path(GEOIP_DB_PATH) / "GeoLite2-ASN.mmdb")


class _GeoIPReaders:
    """Lazy singleton — loads Readers once, keeps them in memory."""

    _city: Optional["geoip2.database.Reader"] = None
    _asn: Optional["geoip2.database.Reader"] = None

    @classmethod
    def city(cls) -> Optional["geoip2.database.Reader"]:
        if cls._city is None and _GEOIP2_AVAILABLE:
            path = os.getenv("GEOIP_CITY_DB", _DEFAULT_CITY_DB)
            if Path(path).exists():
                try:
                    cls._city = geoip2.database.Reader(path)
                    logger.info("[GeoIP] City DB loaded: %s", path)
                except Exception as exc:
                    logger.warning("[GeoIP] Failed to load City DB: %s", exc)
        return cls._city

    @classmethod
    def asn(cls) -> Optional["geoip2.database.Reader"]:
        if cls._asn is None and _GEOIP2_AVAILABLE:
            path = os.getenv("GEOIP_ASN_DB", _DEFAULT_ASN_DB)
            if Path(path).exists():
                try:
                    cls._asn = geoip2.database.Reader(path)
                    logger.info("[GeoIP] ASN DB loaded: %s", path)
                except Exception as exc:
                    logger.warning("[GeoIP] Failed to load ASN DB: %s", exc)
        return cls._asn

    @classmethod
    def close(cls) -> None:
        """Close all open GeoIP readers and clear singleton state."""
        if cls._city is not None:
            cls._city.close()
            cls._city = None
            logger.info("[GeoIP] City DB closed")
        if cls._asn is not None:
            cls._asn.close()
            cls._asn = None
            logger.info("[GeoIP] ASN DB closed")

    @classmethod
    def reload(cls) -> None:
        """Close existing readers so next access re-loads from disk."""
        cls.close()


@lru_cache(maxsize=1024)
def enrich_ip(ip: str) -> dict[str, str]:
    """Return Geo/ASN enrichment dict for an IP.

    O(1) local memory read. Cached by LRU (max 1024 entries).
    Returns {} if DBs missing or IP invalid.
    """
    result: dict[str, str] = {}

    if not ip or ip in ("127.0.0.1", "::1"):
        return result

    city_r = _GeoIPReaders.city()
    if city_r:
        try:
            resp = city_r.city(ip)
            country = resp.country.name or resp.country.iso_code or ""
            if country:
                result["country"] = country
        except Exception:
            pass

    asn_r = _GeoIPReaders.asn()
    if asn_r:
        try:
            asn_resp = asn_r.asn(ip)
            org = getattr(asn_resp, "autonomous_system_organization", None)
            num = getattr(asn_resp, "autonomous_system_number", None)
            if org:
                result["org"] = org
            if num:
                result["asn"] = str(num)
        except Exception:
            pass

    return result
