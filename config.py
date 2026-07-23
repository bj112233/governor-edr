import ipaddress
import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator

load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))


class SentinelConfig(BaseModel):
    """Validated Sentinel runtime configuration."""

    cpu_threshold: float = Field(default=85.0)
    ram_threshold: float = Field(default=90.0)
    disk_threshold: float = Field(default=85.0)
    monitor_interval: int = Field(default=30)
    llm_timeout: int = Field(default_factory=lambda: int(os.getenv("LLM_TIMEOUT", "45")))
    llm_retry_attempts: int = Field(default=3)
    llm_cb_threshold: int = Field(default=3)
    llm_health_interval: int = Field(default=15)
    llm_context_window: int = Field(default=8192)
    llm_agent_max_tokens: int = Field(default=4096)
    llm_agent_trim_chars: int = Field(default=4096)

    @field_validator("cpu_threshold", "ram_threshold", "disk_threshold")
    def _warn_extreme_thresholds(cls, v: float) -> float:
        if v < 10.0:
            raise ValueError("Threshold < 10% would trigger excessive alerts")
        return v


# ==========================================
# Core Configuration
# ==========================================
# LM Studio (OpenAI-compatible API)
LLM_API_BASE = os.getenv("LLM_API_BASE", "http://127.0.0.1:5001/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen3.5-4b")  # Q4_K_S on 6GB VRAM (more KV-cache headroom)
EMBEDDING_MODEL = os.getenv(
    "EMBEDDING_MODEL", "text-embedding-multilingual-e5-large-instruct"
)  # 1024-dim multilingual embedding model (E5-instruct, requires query:/passage: prefixes)
# Embedding vector dimension — MUST match the model above. Single Source of Truth
# for memory_db.py (vectorlite table creation) and vector_manager.py (HNSW init).
# Changing the model requires changing this value — mismatch causes OperationalError
# at vector insertion time.
EMBEDDING_DIM = int(os.getenv("EMBEDDING_DIM", "1024"))
LLM_API_KEY = os.getenv("LLM_API_KEY", "lm-studio")
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "45"))  # Faster timeout - fail fast if model stuck

# LLM bridge: retry / circuit breaker / health monitor
LLM_RETRY_ATTEMPTS = int(
    os.getenv("LLM_RETRY_ATTEMPTS", "2")
)  # 2 attempts - one retry after 1s backoff for transient timeouts
LLM_CB_THRESHOLD = int(os.getenv("LLM_CB_THRESHOLD", "3"))
LLM_HEALTH_INTERVAL = int(os.getenv("LLM_HEALTH_INTERVAL", "60"))  # Less frequent health checks

# Smart Circuit Breaker — TPOT-based degradation detection.
# tpot_ms = (latency_seconds / completion_tokens) * 1000 — physical decode rate,
# independent of prompt/completion length. EMA-tracked; baseline locked after
# LLM_BASELINE_SAMPLES samples. DEGRADED state still accepts traffic but signals
# downstream consumers (e.g. news enrichment) to throttle.
LLM_DEGRADED_MULTIPLIER = float(os.getenv("LLM_DEGRADED_MULTIPLIER", "3.0"))
LLM_DEGRADED_CLEAR_MULTIPLIER = float(
    os.getenv("LLM_DEGRADED_CLEAR_MULTIPLIER", "1.5")
)  # hysteresis — must drop below this to leave DEGRADED
LLM_EMA_ALPHA = float(os.getenv("LLM_EMA_ALPHA", "0.2"))
LLM_BASELINE_SAMPLES = int(os.getenv("LLM_BASELINE_SAMPLES", "10"))
LLM_OPEN_COOLDOWN = int(os.getenv("LLM_OPEN_COOLDOWN", "30"))  # seconds before OPEN -> HALF_OPEN
LLM_MIN_TOKENS_FOR_TPOT = int(
    os.getenv("LLM_MIN_TOKENS_FOR_TPOT", "50")
)  # drop samples below this — prefill dominates, TPOT noisy

# Qwen3.5-4B-GGUF (~2.1GB weights Q4_K_S) on RX 5600 XT (6GB VRAM)
# KoboldCpp set to 16K context (kobold.kcpps, quantkv q8_0); model supports 262K
# natively but 6GB VRAM caps the safe KV-cache at 16384. .env overrides this default.
LLM_CONTEXT_WINDOW = int(os.getenv("LLM_CONTEXT_WINDOW", "16384"))
# Dedicated budgets: keep generous headroom inside the window.
# NOTE: LM Studio UI shows max 2048, but API may accept higher values (4096 tested)
LLM_AGENT_MAX_TOKENS = int(os.getenv("LLM_AGENT_MAX_TOKENS", "2048"))  # LM Studio UI limit for stability
LLM_COMPLETE_MAX_TOKENS = int(os.getenv("LLM_COMPLETE_MAX_TOKENS", "512"))  # Fast completions
# Sampling — Agent Mode (ReAct): temp=0.6 prevents JSON looping on errors,
# top_p=0.95 keeps valid logical tokens, min_p=0.05 blocks hallucinated commands.
# Complete mode: temp=0.7, top_p=0.8 for natural text.
# presence_penalty=0.0 (Hebrew stability — official 1.5 causes rare-token bias).
LLM_AGENT_TEMPERATURE = float(os.getenv("LLM_AGENT_TEMPERATURE", "0.6"))
LLM_COMPLETE_TEMPERATURE = float(os.getenv("LLM_COMPLETE_TEMPERATURE", "0.7"))
LLM_AGENT_TOP_P = float(os.getenv("LLM_AGENT_TOP_P", "0.95"))
LLM_COMPLETE_TOP_P = float(os.getenv("LLM_COMPLETE_TOP_P", "0.8"))
LLM_PRESENCE_PENALTY = float(
    os.getenv("LLM_PRESENCE_PENALTY", "0.0")
)  # Official=1.5 but causes Hebrew gibberish; disabled for stability
LLM_TOP_P = float(os.getenv("LLM_TOP_P", "0.8"))
LLM_TOP_K = int(os.getenv("LLM_TOP_K", "20"))
LLM_MIN_P = float(os.getenv("LLM_MIN_P", "0.05"))
# Sliding-window cap for agent messages (chars).
# Dynamic: 75% of context window (in chars, ~4 chars/token).
# Preserves multi-round tool_output context so final_answer fallback can
# recover prior tool data on truncated LLM responses.
# Override via env var for manual tuning.
LLM_AGENT_TRIM_CHARS = int(os.getenv("LLM_AGENT_TRIM_CHARS", str(int(LLM_CONTEXT_WINDOW * 0.75))))

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
AI_SEARCH_API_KEY = os.getenv("AI_SEARCH_API_KEY", "")

# ==========================================
# GitHub Integration (Code Search for credential leaks)
# ==========================================
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
# Authenticated: 30 req/min. Unauthenticated: 10 req/min.
GITHUB_SEARCH_RATE_LIMIT = 30 if GITHUB_TOKEN else 10
GITHUB_SEARCH_RATE_WINDOW = 60.0  # seconds
GITHUB_SEARCH_MIN_INTERVAL = 2.0  # min seconds between requests (anti-abuse)

# ==========================================
# News Monitor AI Configuration
# ==========================================
NEWS_EMBEDDING_MODEL = os.getenv("NEWS_EMBEDDING_MODEL", "text-embedding-multilingual-e5-large-instruct")
NEWS_SIMILARITY_THRESHOLD = float(os.getenv("NEWS_SIMILARITY_THRESHOLD", "0.75"))
NEWS_CLUSTER_THRESHOLD = float(os.getenv("NEWS_CLUSTER_THRESHOLD", "0.75"))
NEWS_MAX_ITEMS = int(os.getenv("NEWS_MAX_ITEMS", "25"))
NEWS_LLM_TIMEOUT = int(os.getenv("NEWS_LLM_TIMEOUT", "10"))

# Bypass controls — read from env (bool string "true" / "false")
ENABLE_NEWS_BYPASS = os.getenv("ENABLE_NEWS_BYPASS", "true").lower() in (
    "true",
    "1",
    "yes",
)
ENABLE_FILE_BYPASS = os.getenv("ENABLE_FILE_BYPASS", "true").lower() in (
    "true",
    "1",
    "yes",
)

# ==========================================
# System Tools Semantic Routing
# ==========================================
# Threshold for system tool filtering (lower than skill threshold 0.55 because
# system tools are technical/dry descriptions vs natural language questions).
SYSTEM_TOOL_THRESHOLD = float(os.getenv("SYSTEM_TOOL_THRESHOLD", "0.68"))
# Maximum number of system tools to send to LLM (5 tools ≈ 400 tokens for Qwen 4B).
MAX_SYSTEM_TOOLS = int(os.getenv("MAX_SYSTEM_TOOLS", "5"))

# ==========================================
# Sentinel Monitor Thresholds
# ==========================================
_sentinel_config = SentinelConfig()
CPU_THRESHOLD = _sentinel_config.cpu_threshold
RAM_THRESHOLD = _sentinel_config.ram_threshold
DISK_THRESHOLD = _sentinel_config.disk_threshold
MONITOR_INTERVAL = _sentinel_config.monitor_interval
DAILY_DIGEST_HOUR = int(os.getenv("DAILY_DIGEST_HOUR", "8"))

# Hard timeout for asyncio.to_thread OS calls in get_system_snapshot.
# Prevents monitor_loop from blocking indefinitely on a hung psutil/WMI call.
SNAPSHOT_TO_THREAD_TIMEOUT = float(os.getenv("SNAPSHOT_TO_THREAD_TIMEOUT", "3.0"))


# ==========================================
# File Integrity Monitor (FIM) Configuration
# ==========================================
def _resolve_fim_paths() -> list[str]:
    """Resolve FIM watch paths at call time (not import time).

    Handles NSSM/service environments where USERPROFILE may be absent.
    Supports FIM_WATCH_PATHS env var override (semicolon-separated).
    """
    env_paths = os.environ.get("FIM_WATCH_PATHS", "")
    if env_paths:
        return [p.strip() for p in env_paths.split(";") if p.strip() and os.path.isdir(p.strip())]
    home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    appdata = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
    local_appdata = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
    temp = os.environ.get("TEMP") or os.environ.get("TMP") or os.path.join(local_appdata, "Temp")
    startup = os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    candidates = [
        os.path.join(home, "Downloads"),
        os.path.join(home, "Desktop"),
        os.path.join(home, "Documents"),
        temp,
        startup,
    ]
    return [p for p in candidates if os.path.isdir(p)]


FIM_WATCH_PATHS: list[str] = _resolve_fim_paths()

# Subdirectory patterns to IGNORE when recursive=True.
# Prevents watchdog buffer overflow from browser/app cache writes.
# Matched case-insensitively against any path segment.
FIM_IGNORE_PATH_PATTERNS: tuple[str, ...] = (
    "cache",
    "code cache",
    "gpucache",
    "shadercache",
    "thumbnails",
    "iconcache",
    "jump list",
    "d3dscache",
    "crashpad",
    "blob_storage",
    "service worker",
    "indexeddb",
    ".tmp",
    "cookies",
)

FIM_DANGEROUS_EXTS: frozenset[str] = frozenset(
    {
        ".ps1",
        ".bat",
        ".cmd",
        ".vbs",
        ".vbe",  # encoded VBScript (evades string detection)
        ".js",
        ".jse",  # encoded JScript
        ".wsf",  # Windows Script File (XML wrapper)
        ".exe",
        ".dll",
        ".scr",
        ".hta",
        ".com",  # legacy executable
        ".pif",  # program information file (executable)
        ".psm1",  # PowerShell module
        ".lnk",
        ".url",  # internet shortcut (similar to .lnk)
        ".mht",  # MHTML (embedded scripts)
        ".py",
        ".sh",
        ".zip",
        ".rar",
        ".7z",
    }
)
FIM_MAX_SCAN_SIZE = int(os.getenv("FIM_MAX_SCAN_SIZE", str(50 * 1024 * 1024)))  # 50MB (M10 fix)
FIM_MAX_RETRIES = int(os.getenv("FIM_MAX_RETRIES", "5"))
FIM_ENABLED = os.getenv("FIM_ENABLED", "true").lower() in ("true", "1", "yes")

# Number of un-whitelisted external connections that trigger an alert.
# Tune per environment: dev workstation ~15, busy server / browser ~30+,
# air-gapped host can drop to 5 for higher sensitivity.
SUSPICIOUS_NET_THRESHOLD = int(os.getenv("SUSPICIOUS_NET_THRESHOLD", "35"))

# ==========================================
# Monitoring AI Daemon Configuration
# ==========================================
MONITOR_AI_ENABLED = os.getenv("MONITOR_AI_ENABLED", "true").lower() in (
    "true",
    "1",
    "yes",
)
MONITOR_AI_INTERVAL = int(os.getenv("MONITOR_AI_INTERVAL", "60"))
MONITOR_BASELINE_WINDOW_DAYS = int(os.getenv("MONITOR_BASELINE_WINDOW_DAYS", "7"))
MONITOR_ALERT_COOLDOWN_SECONDS = int(os.getenv("MONITOR_ALERT_COOLDOWN_SECONDS", "900"))
MONITOR_MAX_ALERTS_PER_WINDOW = int(os.getenv("MONITOR_MAX_ALERTS_PER_WINDOW", "3"))
MONITOR_Z_THRESHOLD = float(os.getenv("MONITOR_Z_THRESHOLD", "3.0"))
MONITOR_REQUIRED_CYCLES = int(os.getenv("MONITOR_REQUIRED_CYCLES", "3"))

# ==========================================
# Proactive Threat Hunting (Agentic AI)
# ==========================================
# Daemon wakes the agent every 6h to hunt for threats based on system state +
# recent alerts + memory recall. Dispatches to Telegram ONLY if threat_score
# exceeds threshold; otherwise logs + stores silently (no alert fatigue).
THREAT_HUNT_INTERVAL_HOURS = int(os.getenv("THREAT_HUNT_INTERVAL_HOURS", "6"))
THREAT_HUNT_COOLDOWN_HOURS = int(os.getenv("THREAT_HUNT_COOLDOWN_HOURS", "4"))
THREAT_HUNT_DISPATCH_THRESHOLD = float(os.getenv("THREAT_HUNT_DISPATCH_THRESHOLD", "0.6"))
THREAT_HUNT_MAX_ALERTS = int(os.getenv("THREAT_HUNT_MAX_ALERTS", "5"))
THREAT_HUNT_MAX_ANOMALIES = int(os.getenv("THREAT_HUNT_MAX_ANOMALIES", "3"))
THREAT_HUNT_MAX_MEMORY_CHARS = int(os.getenv("THREAT_HUNT_MAX_MEMORY_CHARS", "500"))

# ==========================================
# Daily Report Configuration
# ==========================================
DAILY_REPORT_INCLUDE_TOP_PROCS = True
DAILY_REPORT_MAX_ALERTS = 10

# ==========================================
# Network Whitelist (CIDR ranges to ignore in monitoring)
# ==========================================
# CIDR-based — replaces the legacy /8 string-prefix approach which whitelisted
# entire blocks like "3.0.0.0/8". Tighten or extend per environment.
_WHITELIST_CIDRS_RAW: list[str] = [
    # Loopback / link-local / RFC1918 LAN
    "127.0.0.0/8",
    "::1/128",
    "fe80::/10",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    # Telegram
    "149.154.160.0/20",
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.56.0/22",
    "2001:67c:4e8::/48",
    "2001:b28:f23d::/48",
    # Hetzner (LM Studio connector)
    "2a01:4f8::/29",
    # Cloudflare (Windsurf IDE) + DNS
    "172.67.0.0/16",
    "104.16.0.0/13",
    "1.1.1.1/32",
    "1.0.0.1/32",
    "2606:4700::/32",
    # Microsoft / Azure / Bing
    "204.79.197.0/24",
    "13.107.0.0/16",
    "20.190.0.0/16",
    "40.126.0.0/16",
    "52.182.0.0/16",
    "2620:1ec::/36",
    "2a01:111::/32",
    "2603::/24",
    "2a06::/29",
    # Google
    "8.8.8.8/32",
    "8.8.4.4/32",
    "172.217.0.0/16",
    "216.58.192.0/19",
    "2001:4860::/32",
    "2404:6800::/32",
    "2607:f8b0::/32",
    "2800:3f0::/32",
    "2a00:1450::/32",
    # LM Studio / HuggingFace CDN
    "2606:b740::/32",
    # Akamai
    "2a02:26f0::/32",
    "2600:1400::/24",  # Akamai IPv6 (ARIN-allocated, validated via RDAP 2026-06-01)
    "23.0.0.0/12",
    "23.32.0.0/11",
    "23.64.0.0/14",
    "96.16.0.0/15",
    "184.24.0.0/13",
    "2.16.0.0/13",
    # Fastly
    "151.101.0.0/16",
    "199.232.0.0/16",
    "146.75.0.0/16",
    # Amazon CloudFront IPv6
    "2600:9000::/28",
    "2400:6500::/32",
    "2404:c2c0::/32",
    "2406:da00::/24",
    "2620:108:d000::/44",
    "2a05:d000::/29",
]

WHITELIST_IPS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network(c, strict=False) for c in _WHITELIST_CIDRS_RAW
]


def is_ip_whitelisted(ip: str) -> bool:
    """Return True if `ip` falls within any whitelisted CIDR range."""
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return any(addr in net for net in WHITELIST_IPS)


# GeoIP local MMDB database path (air-gapped enrichment)
# Priority: 1) Env var, 2) PROJECT_ROOT/downloads/geo, 3) None (graceful skip)
_PROJECT_DIR = Path(__file__).parent
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", str((_PROJECT_DIR / "downloads" / "geo").absolute()))

# ==========================================
# OS Module Security Settings
# ==========================================
PROTECTED_PROCESSES = ["explorer.exe", "svchost.exe", "system", "csrss.exe"]

MONITOR_PROCESS_EXCLUSIONS = [
    "lms",
    "lms-backend",
    "lmlink-connector",
    "Windsurf",
    "devin",
    "cascade",  # future IDE agents
    "language_server",  # LSP (Windsurf, VS Code, etc.)
    "CompatTelRunner",  # Windows Compatibility Telemetry
]

# NOTE: legacy `BLOCKED_COMMANDS` (used by the retired
# `os_module.execute_terminal_command`) was removed.
# PowerShell command filtering is now enforced inside
# `services.action_tools._PS_BLOCKED_KEYWORDS`.

# ==========================================
# MCP Server Security
# ==========================================
MCP_AUTH_TOKEN = os.getenv("MCP_AUTH_TOKEN", "")
MCP_AUTH_ENABLED = os.getenv("MCP_AUTH_ENABLED", "true").lower() == "true"

# ==========================================
# Sentinel Runtime Flags
# ==========================================
MCP_ENABLED = True
AUTONOMOUS_MONITOR = True
SENTINEL_ALERT_QUEUE_MAX = int(os.getenv("SENTINEL_ALERT_QUEUE_MAX", "100"))

# ==========================================
# Web C2 Dashboard Authentication
# ==========================================
# WARNING: load_dotenv() at top of this file reads .env BEFORE this line.
# If .env defines WEB_C2_HOST, that value wins over this default.
# To change the binding, edit .env (not git-tracked) or set the env var.
WEB_C2_HOST = os.getenv("WEB_C2_HOST", "127.0.0.1")
WEB_C2_PORT = int(os.getenv("WEB_C2_PORT", "8765"))
WEB_C2_AUTH_USER = os.getenv("WEB_C2_AUTH_USER", "admin")
WEB_C2_AUTH_PASSWORD = os.getenv("WEB_C2_AUTH_PASSWORD", "")

# ==========================================
# Telegram Channel Configuration
# ==========================================
# BOT_TOKEN / ADMIN_ID supported as legacy names.
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID") or os.getenv("ADMIN_ID", "")


# Per-tool output cap before any LLM / Telegram ingestion.
# Single source of truth — see architecture memory: 4B model attention
# degrades sharply >24K, so we cap each tool result at 24000 chars
# regardless of transport (in-process LLM or MCP→Telegram).
TOOL_OUTPUT_MAX_CHARS = int(os.getenv("TOOL_OUTPUT_MAX_CHARS", "24000"))


def truncate_for_context(text: str, max_chars: int = TOOL_OUTPUT_MAX_CHARS) -> str:
    """Truncate text to fit within LLM context budget."""
    return text[:max_chars] if len(text) > max_chars else text
