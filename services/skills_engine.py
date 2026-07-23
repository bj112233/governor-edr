# services/skills_engine.py
"""Backward-compat explicit re-exports -- all logic moved to _skills_engine/."""

from services._skills_engine._engine import SkillsEngine, get_skills_engine, skill_tool
from services._skills_engine.models import Skill

__all__ = ["SkillsEngine", "get_skills_engine", "skill_tool", "Skill"]
