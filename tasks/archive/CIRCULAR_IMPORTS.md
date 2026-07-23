# Circular Import Registry — Inline Imports Debt

> **Status:** Architectural debt — documented, not resolved.
> **Rule:** Any new inline import MUST be added here with justification.

## Why This File Exists

Inline imports (`import` inside functions) hide the true dependency graph of the
system. In a codebase with 18+ inline imports, a developer cannot reason about
coupling by reading `import` blocks at the top of files. This registry brings
these hidden edges to light so they can be systematically eliminated via DI
(Dependency Injection) or interface extraction.

## Taxonomy

| Symbol | Meaning |
|--------|---------|
| `CIRCULAR` | Two modules import each other; inline breaks the loop at runtime |
| `LAZY` | Heavy module loaded only when needed (perf optimization) |
| `TYPE_ONLY` | `if TYPE_CHECKING` guard — no runtime cost, safe |
| `UNKNOWN` | Reason unclear; investigate and document |

---

## Registry (by file)

### `services/bot_memory/highlevel.py`
- `from services.thinking_parser import strip_thinking_content` @ `store_conversation()`
  - **Reason:** `CIRCULAR` — `thinking_parser` may transitively import `bot_memory`
- `from services.embedding_service import get_embedding_service, serialize_vector` @ `async_store_conversation()`
  - **Reason:** `CIRCULAR` — `embedding_service` ↔ `bot_memory` mutual dependency

### `services/telegram/polling.py`
- `from aiogram import Bot, Dispatcher` @ `_start_polling()`
  - **Reason:** `LAZY` — heavy library; defer until Telegram actually enabled
- `from aiogram.fsm.storage.memory import MemoryStorage` @ same
  - **Reason:** `LAZY`

### `services/telegram/processing.py`
- `from services.telegram.permissions import get_response_prefix` @ `_process_message()`
  - **Reason:** `CIRCULAR` — `telegram` package internal loop (`processing` ↔ `permissions`)

### `services/telegram/routing.py`
- `from services.telegram.callbacks import handle_callback_query` @ `on_callback_query()`
  - **Reason:** `CIRCULAR` — `routing` ↔ `callbacks` mutual import within `telegram/`

### `services/telegram/sender.py`
- `from services.channels_config import ErrorPolicy` @ `send_error_with_context()`
  - **Reason:** `CIRCULAR` — `sender` → `channels_config` → back to `telegram` namespace

### `services/telegram/handlers.py`
- `from services.telemetry import get_telemetry` @ `cmd_stats()`
  - **Reason:** `CIRCULAR` — `handlers` → `telemetry` may pull agent tools

### `services/news_cluster.py`
- `from services.embedding_service import get_embedding_service` @ `cluster_news()`
  - **Reason:** `CIRCULAR` — `news_cluster` → `embedding_service` → `bot_memory` → cluster

### `services/night_watchman.py`
- `from services.bot_memory import get_memory_service, MemoryEntry` @ `_store_summary_memory()`
  - **Reason:** `CIRCULAR` — `night_watchman` → `bot_memory` → embedding → night_watchman
- `from services.embedding_service import get_embedding_service, serialize_vector` @ same
  - **Reason:** `CIRCULAR`

### `services/scheduled_news/_formatter.py`
- `from services.time_format import format_feed_time_short` @ `format_digest()`
  - **Reason:** `CIRCULAR` — `_formatter` ↔ `time_format` within `scheduled_news/`

### `services/alert_dispatcher.py`
- `from services.alert_history import async_save_audit_log` @ `_dispatch_alert()`
  - **Reason:** `CIRCULAR` — dispatcher → history → dispatcher (both save/read alerts)

### `services/memory_db.py`
- `import vectorlite` @ module top-level (try/except)
  - **Reason:** `LAZY` / `OPTIONAL` — C extension may be missing; graceful degradation
- `from services.embedding_service import get_embedding_service, serialize_vector` @ `_vectorlite_search()`
  - **Reason:** `CIRCULAR` — `memory_db` ↔ `embedding_service` mutual dependency

### `services/_skills_engine/security.py`
- `from .cli_builder import dict_to_cli_flags, sanitize_args` @ module top (delayed)
  - **Reason:** `TYPE_ONLY` sibling import; safe, not truly circular

### `services/_skills_engine/_yaml_parser.py`
- `import yaml` @ module top (try/except)
  - **Reason:** `LAZY` / `OPTIONAL` — heavy external library; graceful fallback

### `services/local_mcp_server.py`
- `from services.agent import run_agent` @ module top (try/except)
  - **Reason:** `CIRCULAR` — MCP server ↔ agent bridge mutual dependency

### `services/ip_enrich.py`
- `import geoip2.database` @ module top (try/except)
  - **Reason:** `LAZY` / `OPTIONAL`

### `services/gpu_amd.py`
- `import pythoncom`, `import wmi` @ module top (try/except)
  - **Reason:** `LAZY` / `OPTIONAL` — Windows-only COM libraries

### `services/embedding_service.py`
- `import struct` @ `serialize_vector()`, `deserialize_vector()`
  - **Reason:** `LAZY` — tiny stdlib module; harmless micro-optimization

### `services/bot_memory/vector_manager.py`
- `import vectorlite` @ module top (try/except)
  - **Reason:** `LAZY` / `OPTIONAL`
- `from services.memory_db import _VECTORLITE_AVAILABLE, _VECTORLITE_INDEX_DIM` @ module top
  - **Reason:** `CIRCULAR` — `vector_manager` ↔ `memory_db` share vectorlite flags

### `services/tools/mcp_tools.py`
- `from services.telegram_channel import get_telegram_channel` @ module top (try/except)
  - **Reason:** `CIRCULAR` — tools → telegram channel → agent → tools

---

## Elimination Roadmap

Priority candidates for Dependency Injection or `_interfaces.py` extraction:

1. **`services/agent/` → `services/llm_bridge/`** — bridge is already extracted; complete the cut
2. **`services/telegram/` internal cycle** — extract `telegram/_interfaces.py` with protocols
3. **`services/bot_memory/` ↔ `services/embedding_service/`** — create `services/interfaces/embeddings.py`
4. **`services/news_cluster.py` → `services/embedding_service/`** — inject via constructor, not inline
5. **`services/night_watchman.py` → `services/bot_memory/`** — pass `MemoryService` as arg, not import

## Last Updated

2026-06-13 — 18 inline imports catalogued, 0 resolved.
