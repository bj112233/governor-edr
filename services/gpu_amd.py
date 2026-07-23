# services/gpu_amd.py
"""AMD GPU metrics — WMI base + registry VRAM + perf counter fallback.

ADL bindings extracted to gpu_adl.py (SRP). This module handles WMI-based
GPU detection, registry VRAM lookup, and performance counter fallbacks.

GPU telemetry is cached via a background daemon thread (_gpu_sampler_daemon)
that polls every 15s. Callers use get_cached_gpu_info() for O(1) reads.
The raw get_amd_gpu_info() remains for the daemon's own use.
"""

import logging
import subprocess
import threading
import time
import winreg
from typing import Any

try:
    import pythoncom
    import wmi

    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False
    pythoncom = None

from services.gpu_adl import adl_metrics as _adl_metrics

logger = logging.getLogger(__name__)

# ── Registry VRAM (fixes WMI 32-bit overflow) ───────────────────────────
_AMD_DISPLAY_CLASS = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"


def _get_vram_from_registry() -> int:
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _AMD_DISPLAY_CLASS)
        for i in range(winreg.QueryInfoKey(key)[0]):
            try:
                sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
                try:
                    val, _ = winreg.QueryValueEx(sub, "HardwareInformation.qwMemorySize")
                    if isinstance(val, int) and val > 0:
                        winreg.CloseKey(sub)
                        winreg.CloseKey(key)
                        return val
                except FileNotFoundError:
                    pass
                finally:
                    winreg.CloseKey(sub)
            except Exception:
                pass
        winreg.CloseKey(key)
    except Exception as e:
        logger.debug(f"Registry VRAM read failed: {e}")
    return 0


# ── WMI Base ────────────────────────────────────────────────────────────
def _wmi_base() -> dict[str, Any]:
    if not WMI_AVAILABLE or pythoncom is None:
        return {"error": "WMI not available"}
    try:
        pythoncom.CoInitialize()
    except Exception:
        pass
    try:
        c = wmi.WMI()
        for gpu in c.Win32_VideoController():
            if "AMD" in gpu.Name.upper() or "RADEON" in gpu.Name.upper():
                ram = _get_vram_from_registry()
                if not ram:
                    ram = getattr(gpu, "AdapterRAM", 0)
                    if isinstance(ram, int) and ram < 0:
                        ram &= 0xFFFFFFFF
                return {
                    "name": gpu.Name,
                    "adapter_ram_bytes": ram,
                    "driver_version": getattr(gpu, "DriverVersion", "Unknown"),
                    "status": getattr(gpu, "Status", "Unknown"),
                }
        return {"error": "No AMD GPU found"}
    except Exception as e:
        logger.warning(f"WMI GPU query failed: {e}")
        return {"error": f"WMI access failed: {e}"}
    finally:
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass


# ── Perf Counter Fallback ───────────────────────────────────────────────
def _perf_util_wmi() -> dict[str, Any]:
    """GPU utilization via WMI performance counters."""
    out: dict[str, Any] = {}
    if not (WMI_AVAILABLE and pythoncom is not None):
        return out
    try:
        pythoncom.CoInitialize()
    except Exception:
        return out
    try:
        c = wmi.WMI()
        max_3d = 0
        for inst in c.Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine():
            try:
                if "engtype_3D" not in getattr(inst, "Name", ""):
                    continue
                u = getattr(inst, "UtilizationPercentage", None)
                if u is not None:
                    val = int(u)
                    if val > max_3d:
                        max_3d = val
            except Exception:
                pass
        if max_3d > 0:
            out["utilization_percent"] = max_3d
    except Exception:
        pass
    finally:
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass
    return out


def _perf_util_typeperf() -> dict[str, Any]:
    """GPU utilization via typeperf CLI fallback."""
    out: dict[str, Any] = {}
    try:
        proc = subprocess.run(
            ["typeperf", r"\GPU Engine(*)\Utilization Percentage", "-sc", "1", "-f", "CSV"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0:
            lines = proc.stdout.strip().splitlines()
            if len(lines) >= 2:
                hdr = lines[0].split(",")
                data = lines[-1].split(",")
                max_3d = 0
                for i, val in enumerate(data[1:], start=1):
                    if i < len(hdr) and "engtype_3D" in hdr[i]:
                        try:
                            v = float(val.strip().strip('"'))
                            if v > max_3d:
                                max_3d = int(v)
                        except ValueError:
                            pass
                if max_3d > 0:
                    out["utilization_percent"] = max_3d
    except Exception:
        pass
    return out


def _perf_util() -> dict[str, Any]:
    """GPU utilization: WMI first, typeperf CLI fallback."""
    out = _perf_util_wmi()
    if "utilization_percent" not in out:
        out = _perf_util_typeperf()
    return out


# ── Public API ──────────────────────────────────────────────────────────
def get_amd_gpu_info() -> dict[str, Any]:
    """Raw GPU query — WMI + ADL + perf counter fallback. 0.2-5s latency.

    Callers should prefer get_cached_gpu_info() which reads O(1) from the
    background daemon cache. This function is used by the daemon itself.
    """
    base = _wmi_base()
    if "error" in base:
        return base
    perf = _adl_metrics() or _perf_util()
    info = {**base, **perf}
    ram = info.get("adapter_ram_bytes", 0)
    if ram:
        info["adapter_ram_gb"] = round(ram / (1024**3), 1)
    for k in (
        "utilization_percent",
        "temperature_c",
        "engine_clock_mhz",
        "memory_clock_mhz",
        "fan_speed_percent",
        "power_draw_w",
    ):
        info.setdefault(k, None)
    return info


# ── GPU Daemon Cache ──────────────────────────────────────────────────────
# Background thread polls GPU every 15s, absorbing the 0.2-5s WMI/ADL/typeperf
# latency. All callers read O(1) from cache via get_cached_gpu_info().
_gpu_cache: dict[str, Any] = {"gpu": {}}
_gpu_cache_lock = threading.Lock()
_GPU_SAMPLE_INTERVAL = 15  # seconds


def _gpu_sampler_daemon() -> None:
    """Background thread: poll AMD GPU every 15s, cache result.

    The GPU query (WMI + ADL + typeperf fallback) takes 0.2-5s depending on
    which fallback path fires. This daemon absorbs that latency in the
    background so the agent's hot path reads O(1) from cache.
    """
    while True:
        try:
            info = get_amd_gpu_info()
            with _gpu_cache_lock:
                _gpu_cache["gpu"] = info
        except Exception as e:
            logger.warning("[GPU-DAEMON] Sampling failed: %s", e)
        time.sleep(_GPU_SAMPLE_INTERVAL)


threading.Thread(target=_gpu_sampler_daemon, daemon=True, name="gpu-sampler").start()


def get_cached_gpu_info() -> dict[str, Any]:
    """O(1) read from GPU daemon cache. Returns empty dict on cold start.

    Cold start: first 0-15s after import, the daemon hasn't populated yet.
    Callers must handle empty dict (no 'name' key) — formatting code already
    uses .get() with truthiness checks.
    """
    with _gpu_cache_lock:
        return _gpu_cache["gpu"]
