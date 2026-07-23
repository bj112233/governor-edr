"""Generic AI analysis — simple completion wrapper with safety guards."""

import asyncio
import logging

import openai

logger = logging.getLogger(__name__)


async def analyze_data(system_prompt: str, user_data: str, max_tokens: int = 200) -> str:
    """Generic AI analysis — simple completion with safety guards.

    Args:
        max_tokens: Token budget for the response. SOC analysis should use 800+.
    """
    from services.agent.utils import _is_truncated_response, _strip_markdown
    from services.llm_bridge import LLMBridge, is_llm_ready

    if not is_llm_ready():
        return "⚠️ מנוע AI לא זמין."

    MAX_DATA_CHARS = 4000
    if len(user_data) > MAX_DATA_CHARS:
        logger.warning(
            "[AI] Truncating user_data: %d → %d chars",
            len(user_data),
            MAX_DATA_CHARS,
        )
        head = user_data[:1000]
        tail = user_data[-(MAX_DATA_CHARS - 1000 - 100) :]
        user_data = f"{head}\n... [{len(user_data) - 1100} chars truncated] ...\n{tail}"

    engine = LLMBridge.get_instance()
    for attempt in range(3):
        try:
            result = await engine.complete(
                system_prompt=system_prompt,
                user_input=user_data,
                temperature=0.1,
                max_tokens=max_tokens,
            )
            break
        except (TimeoutError, openai.APIConnectionError, openai.APITimeoutError):
            if attempt < 2:
                await asyncio.sleep(1)
                continue
            return "⚠️ מנוע AI לא זמין כרגע. נסה שוב בעוד רגע."

    try:
        result = _strip_markdown(result)

        if _is_truncated_response(result):
            logger.warning("[AI] Truncated response detected: %r...", result[:80])
            return "⚠️ ניתוח חלק — נתונים מורחבים מדי ל-context window הנוכחי."

        return result
    except Exception as e:
        logger.warning("[AI] analyze_data failed: %s", e)
        return f"⚠️ ניתוח AI נכשל: {e}"
