# services/_skills_engine/models.py
"""Skill dataclass — no logic, pure data."""

import re
from pathlib import Path
from typing import Any, Optional


class Skill:
    """Represents a loaded skill."""

    def __init__(self, path: Path, metadata: dict, content: str):
        self.path = path
        self.name = metadata.get("name", path.name)
        self.description = metadata.get("description", "")
        self.metadata = metadata.get("metadata", {})
        self.content = content
        self.emoji = self._get_emoji()
        self.requires = self._get_requires()
        self.install = self._get_install()

        clawdbot = self.metadata.get("clawdbot", {})
        cmd_override = clawdbot.get("commands")
        self.command_override: list[str] | None = (
            list(cmd_override) if isinstance(cmd_override, list) and cmd_override else None
        )
        tpl = clawdbot.get("arg_template")
        self.arg_template: str | None = tpl if isinstance(tpl, str) and tpl.strip() else None
        # Per-skill timeout override (default 30s). Heavy skills (file-analyst, report-maker)
        # can declare a longer timeout in frontmatter: "timeout": 90
        _skill_timeout = clawdbot.get("timeout")
        self.timeout: int = (
            int(_skill_timeout)
            if isinstance(_skill_timeout, (int, float, str)) and str(_skill_timeout).strip().isdigit()
            else 30
        )
        args_desc = clawdbot.get("args_description")
        self.args_description: str | None = args_desc if isinstance(args_desc, str) and args_desc.strip() else None
        auto_tpl = clawdbot.get("command_to_args_template")
        self.command_to_args_template: str | None = auto_tpl if isinstance(auto_tpl, str) and auto_tpl.strip() else None
        # Rich per-command JSON Schema from frontmatter (Tool Depth)
        cmd_schema = clawdbot.get("commands_schema", {})
        self.commands_schema: dict[str, Any] = cmd_schema if isinstance(cmd_schema, dict) else {}

        # Health check state (managed by SkillHealthService)
        self._healthy = True

    def _get_emoji(self) -> str:
        clawdbot = self.metadata.get("clawdbot", {})
        return clawdbot.get("emoji", "🔧")

    def _get_requires(self) -> dict:
        clawdbot = self.metadata.get("clawdbot", {})
        return clawdbot.get("requires", {})

    def _get_install(self) -> list[dict]:
        clawdbot = self.metadata.get("clawdbot", {})
        return clawdbot.get("install", [])

    def _extract_strict_examples(self) -> str:
        """Extract usage examples from ```bash blocks in SKILL.md body."""
        examples = []
        for block in re.findall(r"```bash\n(.*?)```", self.content, re.DOTALL):
            for line in block.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Extract: python scripts/intel.py ip --target 8.8.8.8
                m = re.search(r"(?:python|py)\s+\S+\.py\s+(.+)", line)
                if m:
                    examples.append(m.group(1))
        return "\n".join(f"  {ex}" for ex in examples[:8])

    async def execute(self, command: str, args: str = "") -> str:
        """Execute a skill command — delegates to new SRP modules."""
        import asyncio

        from .cli_builder import apply_template, parse_args
        from .executor import run
        from .security import build_cmd_list, check_required

        # Offload to thread: check_required calls _check_python_lib which uses
        # threading.Thread.join(timeout=5) to bound circular-import hangs.
        # Without to_thread, that join would block the event loop up to 5s per lib.
        err = await asyncio.to_thread(check_required, self)
        if err:
            return err

        # Resolve "run" command before parse_args so single-word commands (e.g. "list") are not treated as paths
        effective_command = command
        effective_args = args
        if command == "run" and self.command_override and "run" not in self.command_override:
            if args:
                first_token = args.strip().split()[0] if args.strip() else ""
                if first_token in self.command_override:
                    effective_command = first_token
                    effective_args = args.strip()[len(first_token) :].strip()
                else:
                    effective_command = self.command_override[0]
            else:
                effective_command = self.command_override[0]

        args_str, args_dict = parse_args(self, effective_args)
        args_str = apply_template(self, effective_command, args_str)

        from pathlib import Path

        project_root = Path(__file__).parent.parent.parent
        cmd_list = await build_cmd_list(self, effective_command, args_str, args_dict, project_root)
        if len(cmd_list) == 1 and isinstance(cmd_list[0], str) and cmd_list[0].startswith("❌"):
            return cmd_list[0]

        raw_output = await run(cmd_list, self.path.parent, timeout=self.timeout)
        return raw_output

    def _build_rich_args_schema(self, commands: list[str]) -> dict[str, Any]:
        """Build rich JSON Schema for args from commands_schema frontmatter.

        Supports two modes:
          1. Shared schema: a ``"*"`` key applies to ALL commands → single
             object with the shared properties (no per-command anyOf bloat).
          2. Per-command schema: each command gets its own variant via anyOf.
        Backward-compat: if commands_schema is empty, falls back to raw string.
        """
        # ── Shared schema ("*") — collapse N identical variants into one ──
        shared = self.commands_schema.get("*")
        if isinstance(shared, dict):
            variant: dict[str, Any] = {"type": "object", "properties": {}}
            cmd_props = shared.get("properties", {})
            if cmd_props and isinstance(cmd_props, dict):
                variant["properties"].update(cmd_props)
            required: list[str] = []
            cmd_required = shared.get("required")
            if isinstance(cmd_required, list):
                required = [r for r in cmd_required if r != "command"]
            if required:
                variant["required"] = required
            return variant

        # ── Per-command schema — one variant per command ──
        variants: list[dict[str, Any]] = []
        for cmd in commands:
            schema = self.commands_schema.get(cmd)
            if not schema or not isinstance(schema, dict):
                continue
            variant = {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "const": cmd},
                },
            }
            # Merge command-specific properties
            cmd_props = schema.get("properties", {})
            if cmd_props and isinstance(cmd_props, dict):
                variant["properties"].update(cmd_props)
            # Required fields: command + any command-specific required
            required = ["command"]
            cmd_required = schema.get("required")
            if isinstance(cmd_required, list):
                required.extend([r for r in cmd_required if r != "command"])
            variant["required"] = required
            variants.append(variant)

        if not variants:
            # Fallback to raw string if no rich schemas defined
            return {
                "type": "string",
                "description": (
                    "Pass raw arguments exactly as shown in examples. "
                    "The engine passes these directly to the script. "
                    "DO NOT use markdown, JSON, or explanatory text here."
                ),
                "default": "",
            }

        if len(variants) == 1:
            return variants[0]
        return {"anyOf": variants}

    def to_tool_def(self) -> dict[str, Any] | None:
        """Convert skill to OpenAI tool definition with STRICT USAGE signature.

        If commands_schema is present in frontmatter, generates a rich
        JSON Schema with per-command typed parameters. Otherwise falls
        back to the legacy flat string-args schema.
        """
        from .parser import extract_commands

        commands = extract_commands(self)
        if not commands:
            return None

        examples = self._extract_strict_examples()
        valid_cmds = ", ".join(commands)
        strict_desc = f"{self.emoji} {self.description}\n\nSTRICT USAGE — Valid commands: {valid_cmds}.\n"
        if examples:
            strict_desc += f"Examples from documentation:\n{examples}\n\n"

        # Build args schema — rich (typed) or legacy (raw string)
        args_schema = self._build_rich_args_schema(commands)

        # Add anti-hallucination guidance based on schema type
        if self.commands_schema:
            strict_desc += (
                "CRITICAL: Pass structured JSON arguments matching the schema. "
                "Each command has specific typed parameters. "
                "Do NOT invent fields not listed in the schema."
            )
        else:
            strict_desc += (
                "CRITICAL: Pass ONLY arguments shown in examples above. "
                "DO NOT invent flags like --path, --pages, or --format "
                "unless explicitly listed. "
                "For 'ip'/'domain'/'hash'/'dns'/'whois' commands, "
                "use --target <value> ONLY."
            )

        return {
            "type": "function",
            "function": {
                "name": f"skill_{self.name}",
                "description": strict_desc,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "enum": commands,
                            "description": (
                                f"REQUIRED. The specific command to run for {self.name}. "
                                f"You MUST provide one of: {valid_cmds}. "
                                "Do NOT omit this field."
                            ),
                        },
                        "args": args_schema,
                    },
                    "required": ["command"],
                },
            },
        }
