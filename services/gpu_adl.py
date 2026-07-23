"""AMD GPU ADL bindings — ctypes structures + ADL helper functions.

Extracted from gpu_amd.py (SRP). Low-level ADL (AMD Display Library) access
via atiadlxx.dll for temperature, utilization, fan speed, power draw.
"""

import ctypes
import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ── ADL Structures ──────────────────────────────────────────────────────
class _ADLTemperature(ctypes.Structure):
    _fields_ = [("iSize", ctypes.c_int), ("iTemperature", ctypes.c_int)]


class _ADLPMActivity(ctypes.Structure):
    _fields_ = [
        ("iSize", ctypes.c_int),
        ("iEngineClock", ctypes.c_int),
        ("iMemoryClock", ctypes.c_int),
        ("iVddc", ctypes.c_int),
        ("iActivityPercent", ctypes.c_int),
        ("iCurrentPerformanceLevel", ctypes.c_int),
        ("iCurrentBusSpeed", ctypes.c_int),
        ("iCurrentBusLanes", ctypes.c_int),
        ("iMaximumBusLanes", ctypes.c_int),
        ("iReserved", ctypes.c_int),
    ]


class _ADLFanSpeedValue(ctypes.Structure):
    _fields_ = [
        ("iSize", ctypes.c_int),
        ("iSpeedType", ctypes.c_int),
        ("iFanSpeed", ctypes.c_int),
        ("iFlags", ctypes.c_int),
    ]


_ADL_MAIN_MALLOC_CALLBACK = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_int)
_cb = _ADL_MAIN_MALLOC_CALLBACK(lambda size: ctypes.windll.kernel32.LocalAlloc(0, size))


# ── ADL Helpers ─────────────────────────────────────────────────────────
def _find_atiadlxx() -> str | None:
    for p in (r"C:\Windows\System32\atiadlxx.dll", r"C:\Windows\SysWOW64\atiadlxx.dll"):
        if os.path.isfile(p):
            return p
    for base in (r"C:\Program Files\AMD", r"C:\Program Files (x86)\AMD"):
        if os.path.isdir(base):
            for root, _ds, fs in os.walk(base):
                if "atiadlxx.dll" in fs:
                    return os.path.join(root, "atiadlxx.dll")
    return None


def _init_adl() -> Any | None:
    path = _find_atiadlxx()
    if not path:
        return None
    try:
        adl = ctypes.windll.LoadLibrary(path)
    except OSError:
        return None
    try:
        fn = adl.ADL_Main_Control_Create
        fn.argtypes = [_ADL_MAIN_MALLOC_CALLBACK, ctypes.c_int]
        fn.restype = ctypes.c_int
        return adl if fn(_cb, 1) == 0 else None
    except Exception:
        return None


def _adl_first_amd(adl: Any) -> int:
    count = ctypes.c_int()
    try:
        fn = adl.ADL_Adapter_NumberOfAdapters_Get
        fn.argtypes = [ctypes.POINTER(ctypes.c_int)]
        fn.restype = ctypes.c_int
        if fn(ctypes.byref(count)) != 0:
            return -1
    except Exception:
        return -1
    n = count.value
    if n <= 0:
        return -1
    raw = ctypes.create_string_buffer(2048 * n)
    try:
        fn = adl.ADL_Adapter_AdapterInfo_Get
        fn.argtypes = [ctypes.c_void_p, ctypes.c_int]
        fn.restype = ctypes.c_int
        if fn(ctypes.cast(raw, ctypes.c_void_p), ctypes.sizeof(raw)) != 0:
            return -1
        for i in range(min(n, 16)):
            off = 2048 * i
            idx = ctypes.c_int.from_buffer(raw, off + 4).value
            name = raw.raw[off + 264 : off + 520].split(b"\x00")[0].decode("utf-8", "ignore")
            if "AMD" in name.upper() or "RADEON" in name.upper():
                active = ctypes.c_int()
                try:
                    a = adl.ADL_Adapter_Active_Get
                    a.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_int)]
                    a.restype = ctypes.c_int
                    if a(idx, ctypes.byref(active)) == 0 and active.value == 1:
                        return idx
                except Exception:
                    return idx
        return ctypes.c_int.from_buffer(raw, 4).value
    except Exception:
        return -1


def _adl_perf(adl: Any, idx: int) -> dict[str, Any]:
    out: dict[str, Any] = {}
    t = _ADLTemperature()
    t.iSize = ctypes.sizeof(_ADLTemperature)
    try:
        fn = adl.ADL_Overdrive5_Temperature_Get
        fn.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(_ADLTemperature)]
        fn.restype = ctypes.c_int
        if fn(idx, 0, ctypes.byref(t)) == 0:
            out["temperature_c"] = t.iTemperature // 1000
    except Exception:
        pass
    a = _ADLPMActivity()
    a.iSize = ctypes.sizeof(_ADLPMActivity)
    try:
        fn = adl.ADL_Overdrive5_CurrentActivity_Get
        fn.argtypes = [ctypes.c_int, ctypes.POINTER(_ADLPMActivity)]
        fn.restype = ctypes.c_int
        if fn(idx, ctypes.byref(a)) == 0:
            if a.iActivityPercent >= 0:
                out["utilization_percent"] = a.iActivityPercent
            if a.iEngineClock > 0:
                out["engine_clock_mhz"] = a.iEngineClock // 100
            if a.iMemoryClock > 0:
                out["memory_clock_mhz"] = a.iMemoryClock // 100
    except Exception:
        pass
    f = _ADLFanSpeedValue()
    f.iSize = ctypes.sizeof(_ADLFanSpeedValue)
    f.iSpeedType = 1
    try:
        fn = adl.ADL_Overdrive5_FanSpeed_Get
        fn.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(_ADLFanSpeedValue)]
        fn.restype = ctypes.c_int
        if fn(idx, 0, ctypes.byref(f)) == 0:
            out["fan_speed_percent"] = f.iFanSpeed
    except Exception:
        pass
    p = ctypes.c_int()
    for pname in ("ADL2_Overdrive6_CurrentPower_Get", "ADL_Overdrive6_CurrentPower_Get"):
        try:
            fn = getattr(adl, pname)
            fn.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int)]
            fn.restype = ctypes.c_int
            if fn(idx, 0, ctypes.byref(p)) == 0:
                out["power_draw_w"] = p.value if p.value < 1000 else p.value // 1000
                break
        except Exception:
            pass
    return out


def adl_metrics() -> dict[str, Any]:
    """Full ADL metrics: init → find AMD adapter → read perf → destroy."""
    adl = _init_adl()
    if not adl:
        return {}
    try:
        idx = _adl_first_amd(adl)
        return _adl_perf(adl, idx) if idx >= 0 else {}
    finally:
        try:
            adl.ADL_Main_Control_Destroy()
        except Exception:
            pass
