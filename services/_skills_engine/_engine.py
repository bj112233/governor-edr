# services/_skills_engine/_engine.py
"""Skills engine: loading, registry, and execution orchestration."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Optional

from cachetools import TTLCache

from ._yaml_parser import parse_frontmatter
from .models import Skill

__all__ = ["SkillsEngine", "get_skills_engine", "skill_tool"]

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).parent.parent.parent
SKILLS_DIR = _PROJECT_ROOT / "skills"

# Skill result cache: 128 entries, 45s TTL
_SKILL_CACHE: TTLCache[tuple[str, str, str, str], str] = TTLCache(maxsize=128, ttl=45)
_SKILL_CACHE_LOCK: asyncio.Lock | None = None
_SKILL_SEMAPHORE: asyncio.Semaphore | None = None
_MAX_CONCURRENT_SKILLS = 3


def _get_cache_lock() -> asyncio.Lock:
    """Lazy-init cache lock — must be called inside event loop."""
    global _SKILL_CACHE_LOCK
    if _SKILL_CACHE_LOCK is None:
        _SKILL_CACHE_LOCK = asyncio.Lock()
    return _SKILL_CACHE_LOCK


def _get_skill_semaphore() -> asyncio.Semaphore:
    """Lazy-init skill semaphore — must be called inside event loop."""
    global _SKILL_SEMAPHORE
    if _SKILL_SEMAPHORE is None:
        _SKILL_SEMAPHORE = asyncio.Semaphore(_MAX_CONCURRENT_SKILLS)
    return _SKILL_SEMAPHORE


class SkillsEngine:
    """Manages skills loading and execution."""

    def __init__(self, skills_dir: Path | None = None):
        self.skills_dir = skills_dir or SKILLS_DIR
        self._skills: dict[str, Skill] = {}

    def load(self) -> "SkillsEngine":
        """Synchronous load — safe to call BEFORE asyncio.run()."""
        if not self._skills:
            self._load_all()
        return self

    async def load_async(self) -> "SkillsEngine":
        """Async-safe load — offloads sync I/O to thread pool."""
        if not self._skills:
            await asyncio.to_thread(self._load_all)
        return self

    def _load_all(self) -> None:
        """Load all skills from skills directory."""
        if not self.skills_dir.exists():
            logger.warning("[Skills] Directory not found: %s", self.skills_dir)
            return

        logger.debug("[Skills-DEBUG] Loading from: %s", self.skills_dir)
        skill_dirs = [d for d in self.skills_dir.iterdir() if d.is_dir()]

        for skill_dir in skill_dirs:
            skill_file = skill_dir / "SKILL.md"
            if skill_file.exists():
                try:
                    skill = self._load_skill(skill_file)
                    if skill:
                        self._skills[skill.name] = skill
                        logger.info("[Skills] Loaded: %s %s", skill.emoji, skill.name)
                    else:
                        logger.warning("[Skills-DEBUG] _load_skill returned None for %s", skill_file)
                except Exception as e:
                    logger.warning("[Skills] Failed to load %s: %s", skill_file, e, exc_info=True)
        logger.debug(
            "[Skills-DEBUG] Checked %d dirs, loaded %d skills",
            len(skill_dirs),
            len(self._skills),
        )

    def _load_skill(self, path: Path) -> Skill | None:
        """Load a single SKILL.md file."""
        content = path.read_text(encoding="utf-8")
        logger.debug("[Skills-DEBUG] _load_skill: %s size=%d chars", path, len(content))

        try:
            # 1. Delegate to abstraction layer — no library handling here
            metadata, body = parse_frontmatter(content)

            if not metadata:
                logger.warning("[Skills-DEBUG] No valid YAML frontmatter in %s", path)
                return None

            # 2. Inject into Skill model
            logger.debug("[Skills-DEBUG] Parsed metadata: %s", metadata)
            return Skill(path, metadata, body)

        except Exception as e:
            logger.warning("[Skills] Frontmatter parse error in %s: %s", path, e, exc_info=True)
            return None

    def get_tools(self) -> list[dict[str, Any]]:
        """Get all healthy skills as OpenAI tool definitions."""
        if not self._skills:
            self.load()
        tools = []
        _skipped = 0
        for skill in self._skills.values():
            if not getattr(skill, "_healthy", True):
                _skipped += 1
                continue
            tool = skill.to_tool_def()
            if tool:
                tools.append(tool)
                logger.debug(
                    "[Skills-DEBUG] get_tools: added %s",
                    tool["function"]["name"],
                )
            else:
                logger.warning("[Skills-DEBUG] get_tools: %s returned None", skill.name)
        if _skipped:
            logger.info(
                "[Skills] get_tools: %d healthy / %d total (%d unhealthy hidden)",
                len(tools),
                len(self._skills),
                _skipped,
            )
        else:
            logger.debug(
                "[Skills-DEBUG] get_tools: returning %d tools",
                len(tools),
            )
        return tools

    async def execute(self, skill_name: str, command: str, args: str | dict = "") -> str:
        """Execute a skill by name. Rate-limited via semaphore (max 3 concurrent)."""
        if not self._skills:
            await self.load_async()
        # Remove skill_ prefix if present
        if skill_name.startswith("skill_"):
            skill_name = skill_name[6:]

        skill = self._skills.get(skill_name)
        if not skill:
            available = ", ".join(self._skills.keys())
            return f"❌ Skill not found: {skill_name}\nAvailable: {available}"

        args_str = args if isinstance(args, str) else json.dumps(args, ensure_ascii=False)
        async with _get_skill_semaphore():
            return await skill.execute(command, args_str)

    def list_skill_names(self) -> list[str]:
        """Return a list of loaded skill names."""
        if not self._skills:
            self.load()
        return list(self._skills.keys())

    def list_skills(self) -> str:
        """List all loaded skills."""
        if not self._skills:
            self.load()
        if not self._skills:
            return "No skills loaded."

        lines = ["📦 Loaded Skills:"]
        for name, skill in self._skills.items():
            lines.append(f"  {skill.emoji} {name}: {skill.description[:60]}...")
        return "\n".join(lines)


# Singleton instance
_skills_engine: SkillsEngine | None = None


def get_skills_engine() -> SkillsEngine:
    """Get singleton SkillsEngine."""
    global _skills_engine
    if _skills_engine is None:
        _skills_engine = SkillsEngine()
    return _skills_engine


def _canonicalize_args(args: str | dict) -> str:
    """Normalize arguments to create a consistent cache key."""
    if isinstance(args, str):
        return args.strip().lower()
    try:
        return json.dumps(args, sort_keys=True)
    except Exception:
        return str(args)


async def skill_tool(skill_name: str, command: str, args: str | dict = "") -> str:
    """Execute a skill via the skills engine (non-blocking) with TTLCache.

    This is the AGENT-PATH entry point — output is injected into the LLM context
    window, so Absolute Skill Sandboxing validation is applied here. Bypasses
    call engine.execute() directly (output → user, no LLM) and skip validation.
    """
    normalized_args = _canonicalize_args(args)
    cache_key = (skill_name.lower(), command.lower(), normalized_args, str(Path.cwd()))

    cached_result = _SKILL_CACHE.get(cache_key)
    if cached_result is not None:
        logger.debug("[Skills-CACHE] Hit: %s %s", skill_name, command)
        return cached_result

    engine = get_skills_engine()
    raw_output = await engine.execute(skill_name, command, args)

    # Absolute Skill Sandboxing: validate output against schema contract
    # before it reaches the LLM context window. This is the LLM-injection
    # boundary — bypasses that return directly to the user skip this gate.
    from ._output_validator import validate_skill_output

    result = validate_skill_output(skill_name, raw_output)

    # Only cache successful results (not errors or timeouts)
    if not result.sanitized_output.startswith(("❌", "⏱️")):
        async with _get_cache_lock():
            _SKILL_CACHE[cache_key] = result.sanitized_output

    return result.sanitized_output
