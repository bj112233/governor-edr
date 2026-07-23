# services/_skills_engine/security.py
"""Security layer: validates commands + builds cmd_list with hard allowlists."""

import asyncio
import logging
import shlex
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from .cli_builder import dict_to_cli_flags, sanitize_args

if TYPE_CHECKING:
    from .models import Skill

logger = logging.getLogger(__name__)

_KNOWN_BINS = {"python", "py", "python3", "python.exe", "py.exe"}
_ALLOWED_DIRECT = {"curl", "wget", "nmap", "ping", "tracert", "nslookup", "whois"}


def _get_venv_python(project_root: Path) -> str:
    """Return the venv Python executable path."""
    import sys

    # Check .venv (standard Python venv name)
    dotvenv_windows = project_root / ".venv" / "Scripts" / "python.exe"
    dotvenv_unix = project_root / ".venv" / "bin" / "python"
    if dotvenv_windows.exists():
        return str(dotvenv_windows)
    if dotvenv_unix.exists():
        return str(dotvenv_unix)

    # Check legacy venv312 name
    venv312_windows = project_root / "venv312" / "Scripts" / "python.exe"
    venv312_unix = project_root / "venv312" / "bin" / "python"
    if venv312_windows.exists():
        return str(venv312_windows)
    if venv312_unix.exists():
        return str(venv312_unix)

    return sys.executable


def check_binary(name: str) -> bool:
    if name.lower() in _KNOWN_BINS:
        return True
    resolved = shutil.which(name)
    if not resolved:
        return False
    # Block .bat/.cmd due to cmd.exe injection
    if resolved.lower().endswith((".bat", ".cmd")):
        return False
    return True


_PYPI_TO_IMPORT: dict[str, str] = {
    "beautifulsoup4": "bs4",
    "readability-lxml": "readability",
    "pillow": "PIL",
    "python-dotenv": "dotenv",
    "opencv-python": "cv2",
    "pdfminer.six": "pdfminer",
    "python-docx": "docx",
    "pyjwt": "jwt",
    "argon2-cffi": "argon2",
    "pytesseract": "pytesseract",
    "pymupdf": "fitz",
    "pdf2image": "pdf2image",
    "html2text": "html2text",
    "weasyprint": "weasyprint",
    "markitdown": "markitdown",
    "langdetect": "langdetect",
    "feedparser": "feedparser",
    "aiosqlite": "aiosqlite",
}


def _check_python_lib(name: str) -> bool:
    """Return True if the named Python package can be imported.

    Handles PyPI→import name mismatches (e.g. beautifulsoup4 → bs4).
    Uses a thread with timeout to prevent hanging on circular imports.
    """
    import_name = _PYPI_TO_IMPORT.get(name.lower(), name)
    try:
        import threading

        result: list[bool] = []

        def _do_import():
            try:
                __import__(import_name)
                result.append(True)
            except ImportError:
                result.append(False)

        t = threading.Thread(target=_do_import, daemon=True)
        t.start()
        t.join(timeout=5.0)
        if t.is_alive():
            logger.warning("[Security] __import__('%s') timed out (5s) — treating as missing", import_name)
            return False
        return result[0] if result else False
    except ImportError:
        return False


def check_required(skill) -> str | None:
    bins = skill.requires.get("bins", [])
    for binary in bins:
        if not check_binary(binary):
            return f"❌ Required binary not found: {binary}\nInstall: {skill.install}"
    py_libs = skill.requires.get("python_libs", [])
    missing = [lib for lib in py_libs if not _check_python_lib(lib)]
    if missing:
        return f"❌ Required Python packages not installed: {', '.join(missing)}\nInstall: {skill.install}"
    return None


def _resolve_run_command(skill, command: str, args_str: str) -> tuple[str, str]:
    """Map a literal "run" command to a real subcommand.

    Returns (actual_command, remaining_args_str). Three cases for command=="run":
      1. command_override set, "run" not in it → first token of args_str if it
         matches an allowed command, else command_override[0] (args consumed
         when matched).
      2. command_override set, "run" in it → stays "run".
      3. no command_override → skill.name.
    Non-"run" commands pass through unchanged.
    """
    if command != "run":
        return command, args_str
    if not skill.command_override:
        return skill.name, args_str
    if "run" in skill.command_override:
        return command, args_str
    if args_str:
        stripped = args_str.strip()
        first_token = stripped.split()[0] if stripped else ""
        if first_token in skill.command_override:
            rest = stripped[len(first_token) :].strip()
            logger.info("[Skills] %s: 'run' mapped to '%s'", skill.name, first_token)
            return first_token, rest
    actual = skill.command_override[0]
    logger.info("[Skills] %s: 'run' mapped to '%s'", skill.name, actual)
    return actual, args_str


def _build_known_bin_cmd(actual_command: str, args_str: str, venv_python: str) -> list[str]:
    """Build cmd_list for a known Python-bin invocation (with -c/-m/-x guard)."""
    cmd_list: list[str] = [venv_python]
    parsed_args = sanitize_args(args_str) if args_str else []
    for arg in parsed_args:
        arg_lower = arg.lower()
        if arg_lower.startswith("-c") or arg_lower.startswith("-m") or arg_lower == "-x":
            return ["❌ SECURITY ERROR: BLOCKED. הרצת קוד ישירה מתוך ארגומנט פייתון חסומה לחלוטין."]
    if parsed_args:
        cmd_list.extend(parsed_args)
    return cmd_list


def _build_script_cmd(skill, actual_command: str, args_str: str, args_dict, venv_python: str) -> list[str]:
    """Build cmd_list for a skill-script invocation (python script.py <cmd> ...)."""
    from .parser import get_script_path

    script = get_script_path(skill)
    if not script:
        return ["❌ SECURITY ERROR: BLOCKED. פקודה לא מוכרת ולא נמצא סקריפט תואם."]
    cmd_list: list[str] = [venv_python, str(script), actual_command]
    if args_dict:
        cmd_list.extend(dict_to_cli_flags(args_dict))
    elif args_str:
        cmd_list.extend(sanitize_args(args_str))
    return cmd_list


async def _build_direct_bin_cmd(actual_command: str, args_str: str) -> list[str]:
    """Build cmd_list for an allowed direct binary (curl/wget/nmap/...)."""
    resolved_bin = await asyncio.to_thread(shutil.which, actual_command)
    if not resolved_bin:
        return [f"❌ SECURITY ERROR: Binary '{actual_command}' not found."]
    if resolved_bin.lower().endswith((".bat", ".cmd")):
        logger.error(
            "[Security] BLOCKED: Attempted to execute a batch file (%s)",
            resolved_bin,
        )
        return ["❌ SECURITY ERROR: הרצת קבצי עטיפה (.cmd / .bat) חסומה עקב חולשת Command Injection ברמת מערכת ההפעלה."]
    cmd_list: list[str] = [resolved_bin]
    if args_str:
        cmd_list.extend(sanitize_args(args_str))
    return cmd_list


async def build_cmd_list(
    skill,
    command: str,
    args_str: str,
    args_dict: dict | None,
    project_root: Path,
) -> list[str]:
    """Build validated cmd_list. Returns error string if security blocks."""
    venv_python = _get_venv_python(project_root)

    actual_command, args_str = _resolve_run_command(skill, command, args_str)

    # Explicit arg_template override
    if skill.arg_template:
        # If args were parsed into a dict, don't pass the raw string to avoid duplication
        effective_args_str = "" if args_dict else args_str
        return await _apply_arg_template(skill, actual_command, effective_args_str, args_dict, venv_python)

    cmd_lower = actual_command.lower()
    if cmd_lower in _KNOWN_BINS:
        return _build_known_bin_cmd(actual_command, args_str, venv_python)
    if cmd_lower not in _ALLOWED_DIRECT:
        return _build_script_cmd(skill, actual_command, args_str, args_dict, venv_python)
    return await _build_direct_bin_cmd(actual_command, args_str)


def _convert_flags_to_json_if_needed(args_str: str, arg_template: str) -> str:
    """Backward-compat: convert --flag CLI args to JSON when template expects JSON."""
    import json

    from ._cli_utils import _cli_flags_to_json_dict

    if not args_str:
        return args_str
    if not args_str.strip().startswith("--"):
        return args_str
    if "'{args}'" not in arg_template and '"{args}"' not in arg_template:
        return args_str
    try:
        return json.dumps(
            _cli_flags_to_json_dict(args_str),
            ensure_ascii=False,
            separators=(",", ":"),
        )
    except Exception:
        return args_str


def _render_and_tokenize_template(skill, command: str, args_str: str, args_dict, venv_python: str) -> list[str]:
    """Render arg_template and tokenize into a cmd_list."""
    try:
        rendered = (
            skill.arg_template.replace("{command}", str(command)).replace("{args}", str(args_str or ""))
        ).strip()
    except (KeyError, IndexError) as fmt_err:
        return [f"❌ arg_template format error: {fmt_err}"]

    try:
        if "'{args}'" in skill.arg_template or '"{args}"' in skill.arg_template:
            script_tpl = skill.arg_template.replace("'{args}'", "").replace('"{args}"', "").replace("{args}", "")
            script_rendered = script_tpl.format(command=command).strip()
            tokens = shlex.split(script_rendered, posix=False) if script_rendered else []
            if args_str:
                tokens.append(args_str)
        else:
            tokens = shlex.split(rendered, posix=False)
            if args_dict:
                tokens.extend(dict_to_cli_flags(args_dict))
    except Exception as e:
        return [f"❌ arg_template tokenization error: {e}"]

    if not tokens:
        return ["❌ arg_template produced empty command"]
    return [venv_python, *tokens]


async def _apply_arg_template(skill, command: str, args_str: str, args_dict, venv_python: str) -> list[str]:
    """Handle arg_template rendering and tokenization."""
    import json

    # If args were parsed into a dict but template expects a JSON string,
    # serialize back so the script receives its expected argument.
    if not args_str and args_dict and ("'{args}'" in skill.arg_template or '"{args}"' in skill.arg_template):
        args_str = json.dumps(args_dict, ensure_ascii=False, separators=(",", ":"))

    actual_command, args_str = _resolve_run_command(skill, command, args_str)
    args_str = _convert_flags_to_json_if_needed(args_str, skill.arg_template)

    return _render_and_tokenize_template(skill, actual_command, args_str, args_dict, venv_python)
