# services/agent/context.py
# TODO: Add size cap or expiration to prevent memory bloat
_last_document = None


def set_last_document(content: str) -> None:
    """Store the last analyzed document for context awareness."""
    global _last_document
    _last_document = content


def clear_last_document() -> None:
    """Clear the last analyzed document (e.g. on /start)."""
    global _last_document
    _last_document = None


def get_last_document() -> str:
    """Get the last analyzed document for context awareness."""
    global _last_document
    return _last_document or ""
