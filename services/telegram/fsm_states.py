# services/telegram/fsm_states.py
"""Aiogram FSM states for deterministic multi-step flows."""

from aiogram.fsm.state import State, StatesGroup


class ExecApproval(StatesGroup):
    """Human-in-the-loop approval for dangerous commands."""

    waiting_for_auth = State()
