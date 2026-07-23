"""
CLI path resolution — enforce containment against the bot root.

All user-supplied paths are resolved against the bot root and validated
to prevent path-traversal escapes.
"""

from pathlib import Path


def resolve_safe_path(base_path: Path, target_path: str) -> Path | None:
    """Resolve ``target_path`` against ``base_path`` and enforce containment.

    Raises:
        ValueError: if the fully-resolved target escapes ``base_path``
            (Path Traversal attempt).
    """
    if not target_path:
        return None

    clean_target = str(target_path).strip("\"'")
    bot_root_path = Path(base_path).resolve()

    candidate = Path(clean_target)
    if not candidate.is_absolute():
        candidate = bot_root_path / candidate

    resolved = candidate.resolve()

    if not resolved.is_relative_to(bot_root_path):
        raise ValueError("Security Exception: Path traversal detected.")

    return resolved


def resolve_arg_paths(args, bot_root: Path):
    """Resolve ``--path``, ``--dir`` and ``--output`` in-place on ``args``."""
    args.path = resolve_safe_path(bot_root, args.path)
    args.dir = resolve_safe_path(bot_root, args.dir)
    args.output = resolve_safe_path(bot_root, args.output)
    return args
