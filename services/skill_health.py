# services/skill_health.py
"""Periodic skill health monitoring — ping skills and hide unhealthy from LLM."""

import asyncio
import logging

from services._skills_engine._engine import SkillsEngine

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 10.0


class SkillHealthService:
    """Ping skills with lightweight calls; track state transitions."""

    def __init__(self, engine: SkillsEngine) -> None:
        self._engine = engine
        self._health_state: dict[str, bool] = {}

    async def ping(self, skill_name: str) -> bool:
        """Run lightweight health check for a single skill."""
        skill = self._engine._skills.get(skill_name)
        if not skill:
            return False

        health_spec = skill.metadata.get("health_check", {})
        if not health_spec:
            # No health_check configured → always healthy
            return True

        command = health_spec.get("command", "run")
        args = health_spec.get("args", "")
        timeout = health_spec.get("timeout", _DEFAULT_TIMEOUT)

        try:
            result = await asyncio.wait_for(
                self._engine.execute(skill_name, command, args),
                timeout=timeout,
            )
            if isinstance(result, str) and result.startswith(("❌", "⏱️", "⚠️", "[ERROR]")):
                return False
            return True
        except TimeoutError:
            return False
        except Exception as exc:
            logger.debug("[HealthCheck] Exception in %s: %s", skill_name, exc)
            return False

    async def pulse_all(self) -> None:
        """Run health checks on all skills and update their state."""
        if not self._engine._skills:
            await self._engine.load_async()

        for name, skill in self._engine._skills.items():
            if "health_check" not in skill.metadata:
                skill._healthy = True
                continue

            is_healthy = await self.ping(name)
            was_healthy = self._health_state.get(name, True)
            skill._healthy = is_healthy
            self._health_state[name] = is_healthy

            if is_healthy and not was_healthy:
                logger.info("🟢 [HealthCheck] Skill recovered: %s", name)
            elif not is_healthy and was_healthy:
                logger.warning(
                    "🔴 [HealthCheck] Skill failed: %s — Removed from Agent tools",
                    name,
                )
