# services/telegram/hitl_handler.py
"""Human-in-the-loop approval handler (HITL) for dangerous commands."""

import asyncio
import logging

from aiogram import Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from services.agent_tools import execute_tool as _execute_tool
from services.bot_memory import inject_audit_event
from services.telegram.fsm_states import ExecApproval

router = Router()
logger = logging.getLogger(__name__)


async def _execute_approved(state: FSMContext, user_id: int) -> str:
    """Execute the pending dangerous tool after approval. Returns result text."""
    data = await state.get_data()
    tool_name = data.get("pending_command", "unknown")
    tool_args = data.get("pending_args", {})
    try:
        exec_result = await _execute_tool(tool_name, tool_args)
        result = f"Approved and executed: {tool_name}. Result: {exec_result}"
        logger.info("[HITL] Tool executed: %s | Result: %s", tool_name, exec_result)
    except Exception as e:
        result = f"Approved but execution failed: {e}"
        logger.error("[HITL] Execution error for %s: %s", tool_name, e, exc_info=True)
    await inject_audit_event(
        user_id,
        f"SYSTEM EVENT: User approved dangerous tool [{tool_name}] via HITL. Result: {result}",
    )
    await state.clear()
    return result


async def _reject(state: FSMContext, user_id: int) -> str:
    """Reject the pending dangerous tool."""
    data = await state.get_data()
    tool_name = data.get("pending_command", "unknown")
    await inject_audit_event(
        user_id,
        f"SYSTEM EVENT: User REJECTED dangerous tool [{tool_name}] via HITL.",
    )
    await state.clear()
    return "❌ הפקודה נדחתה."


@router.message(Command("cancel"))
async def cancel_fsm(message: Message, state: FSMContext) -> None:
    """Global interrupt: cancel any active FSM and return control to ReAct."""
    current = await state.get_state()
    if current is not None:
        await state.clear()
        await message.reply("התהליך בוטל. מחזיר שליטה לסוכן הראשי (ReAct).")
    else:
        await message.reply("אין תהליך פעיל לביטול.")


@router.callback_query(lambda c: c.data in ("hitl_approve", "hitl_reject"))
async def handle_hitl_callback(callback: CallbackQuery, state: FSMContext) -> None:
    """Handle HITL approve/reject button presses (InlineKeyboard)."""
    user_id = callback.from_user.id if callback.from_user else 0
    current = await state.get_state()
    if current != ExecApproval.waiting_for_auth:
        await callback.answer("אין בקשה פעילה.", show_alert=True)
        return
    if callback.data == "hitl_approve":
        result = await _execute_approved(state, user_id)
        if isinstance(callback.message, Message):
            await callback.message.edit_text(f"✅ {result}")
    else:
        result = await _reject(state, user_id)
        if isinstance(callback.message, Message):
            await callback.message.edit_text(result)
    await callback.answer()


@router.message(ExecApproval.waiting_for_auth)
async def handle_approval(message: Message, state: FSMContext) -> None:
    """Handle approval response when in HITL state (text input fallback)."""
    text = (message.text or "").strip().lower()
    user_id = message.from_user.id if message.from_user else 0

    if text in ("כן", "yes", "אשר", "approve", "y"):
        result = await _execute_approved(state, user_id)
        await message.reply(f"✅ {result}")

    elif text in ("לא", "no", "דחה", "reject", "n"):
        result = await _reject(state, user_id)
        await message.reply(result)

    else:
        await message.reply('אנא ענה "כן" לאישור או "לא" לדחייה, או לחץ על הכפתורים.')
