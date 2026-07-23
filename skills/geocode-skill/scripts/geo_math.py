"""Pure math utilities for geocode skill — zero I/O, zero side effects."""

import math

EARTH_RADIUS_KM = 6371.0


def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in km."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = (
        math.sin(dphi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    )
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def fmt_hours(mins: float) -> str:
    """Format minutes into Hebrew hours/minutes string."""
    if mins >= 60:
        h = int(mins // 60)
        m = int(mins % 60)
        return f"~{h}.{m / 60 * 10:.0f} שעות" if m > 0 else f"~{h} שעות"
    return f"~{int(mins)} דקות"
