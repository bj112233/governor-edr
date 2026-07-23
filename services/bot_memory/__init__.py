# services/bot_memory/__init__.py
"""Bot Memory package — re-exports for backward compatibility."""

from .archive import (
    archive_memories_by_ids,
    cleanup_old_memories,
    clear_conversation_memory,
    fetch_old_memories_for_compaction,
    restore_archived_memories,
    vacuum_archived_memories,
)
from .crud import get_memory_service
from .highlevel import (
    async_store_conversation,
    inject_audit_event,
    recall_context,
    store_conversation,
)
from .models import (
    MemoryEntry,
    MemoryQuery,
    _is_nonpersistable_response,
)

__all__ = [
    "MemoryEntry",
    "MemoryQuery",
    "get_memory_service",
    "_is_nonpersistable_response",
    "async_store_conversation",
    "clear_conversation_memory",
    "cleanup_old_memories",
    "inject_audit_event",
    "recall_context",
    "store_conversation",
    "archive_memories_by_ids",
    "fetch_old_memories_for_compaction",
    "restore_archived_memories",
    "vacuum_archived_memories",
]
