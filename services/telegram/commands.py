# services/telegram/commands.py
"""
Static Telegram command definitions and menu structures.
Intel commands bypass the LLM and POST directly to the local MCP server.
"""

_MCP_URL = "http://127.0.0.1:11123/mcp/call"

INTEL_COMMANDS: dict[str, tuple] = {
    "system": ("get_system_snapshot", "📊 תמונת מערכת"),
    "procs": ("get_process_list", "⚙️ תהליכים לפי CPU"),
    "conns": ("get_external_connections", "🌐 חיבורים חיצוניים"),
    "ports": ("get_listening_ports", "🔌 פורטים פתוחים"),
    "events": ("get_event_log", "📜 אירועי אבטחה"),
    "services": ("get_services", "🛠️ שירותי Windows"),
    "users": ("get_local_users", "👤 משתמשים מקומיים"),
    "disks": ("get_disk_details", "💾 דיסקים"),
    "startup": ("get_startup_items", "🚀 Startup Items"),
    "firewall": ("get_firewall_drops", "🔥 חסימות Firewall"),
    "sessions": ("get_active_sessions", "🧑‍💻 סשנים פעילים"),
    "tasks": ("get_scheduled_tasks_detail", "⏰ משימות מתוזמנות"),
    "adapters": ("get_network_adapters", "📡 כרטיסי רשת"),
    "gpu": ("get_amd_gpu_info", "🎮 מידע GPU"),
    "alerts": ("query_alert_history", "🚨 התראות SOC"),
    "lan": ("get_known_devices", "🏠 מכשירי LAN"),
    "news": ("trigger_news_digest", "📰 חדשות יומי"),
    "scan": ("defender_scan", "🛡️ סריקת Defender"),
    "screenshot": ("local_screenshot", "📸 צילום מסך"),
    "fullsys": ("sentinel_get_system_snapshot_full", "🔍 תמונת מערכת מלאה"),
    "lanscan": ("scan_lan", "🔎 סריקת רשת ARP"),
    "pending": ("sentinel_get_pending_events", "📋 אירועים ממתינים"),
    "approve": ("approve_pending_action", "✅ אישור פעולה"),
    "deny": ("deny_pending_action", "❌ ביטול פעולה"),
    "memory": ("recent_memory", "🧠 זיכרון שיחות"),
    "clear": ("sentinel_clear_event_queue", "🗑️ ניקוי תור אירועים"),
}

# Commands that accept text after the slash (e.g. /search query)
INTEL_COMMANDS_WITH_ARGS: dict[str, tuple] = {
    # command: (tool_name, title, arg_key, default_value)
    "search": ("web_search", "🔍 חיפוש באינטרנט", "query", ""),
    "kill": ("terminate_process", "💀 הריגת תהליך", "pid", ""),
    "block": ("block_ip", "🚫 חסימת IP", "ip", ""),
    "unblock": ("unblock_ip", "✅ שחרור IP", "ip", ""),
    "hash": ("hash_file", "🔐 Hash קובץ", "path", ""),
    "read": ("read_file", "📄 קריאת קובץ", "path", ""),
    "ls": ("list_directory", "📁 תצוגת תיקייה", "path", "."),
    "analyze": ("skill_file_analyst", "📄 ניתוח קובץ", "path", ""),
    "scrape": ("skill_web_scraper", "🌐 Web Scraper", "url", ""),
    "intel": ("skill_intel", "🛡️ מודיעין איומים", "target", ""),
    "hunt": ("osint_hunt", "🛡️ חיפוש OSINT", "topic", ""),
}
