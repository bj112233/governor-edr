# services/osint_memory.py
"""OSINT Vector Memory — re-exports from reference_store (Sprint 5 Phase 3).

All osint_intel CRUD now lives in services/reference_store.py (reference.db).
This shim preserves backward compatibility for existing imports.
"""

from services.reference_store import search_intel, store_intel

__all__ = ["store_intel", "search_intel"]
