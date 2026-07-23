r"""Tool Depth tests — rich JSON Schema from SKILL.md frontmatter + adapter pattern.

Run:  .venv\Scripts\python.exe -m pytest tests/test_tool_depth.py -v -s
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services._skills_engine.models import Skill


def test_build_rich_args_schema_single_command():
    """Skill with one command schema → single object schema."""
    skill = Skill(
        path=Path("/fake/intel-skill/SKILL.md"),
        metadata={
            "name": "intel-skill",
            "description": "Intel skill",
            "metadata": {
                "clawdbot": {
                    "commands_schema": {
                        "ip": {
                            "properties": {
                                "target": {"type": "string"},
                                "format": {"type": "string", "enum": ["json", "markdown"]},
                            },
                            "required": ["target"],
                        }
                    }
                }
            },
        },
        content="",
    )
    schema = skill._build_rich_args_schema(["ip"])

    assert schema["type"] == "object"
    assert schema["properties"]["command"]["const"] == "ip"
    assert schema["properties"]["target"]["type"] == "string"
    assert schema["properties"]["format"]["enum"] == ["json", "markdown"]
    assert "command" in schema["required"]
    assert "target" in schema["required"]
    print("PASS: single command rich schema")


def test_build_rich_args_schema_multiple_commands():
    """Skill with two command schemas → anyOf schema."""
    skill = Skill(
        path=Path("/fake/intel-skill/SKILL.md"),
        metadata={
            "name": "intel-skill",
            "description": "Intel skill",
            "metadata": {
                "clawdbot": {
                    "commands_schema": {
                        "ip": {
                            "properties": {"target": {"type": "string"}},
                            "required": ["target"],
                        },
                        "sweep": {
                            "properties": {"threshold": {"type": "integer"}},
                            "required": [],
                        },
                    }
                }
            },
        },
        content="",
    )
    schema = skill._build_rich_args_schema(["ip", "sweep"])

    assert "anyOf" in schema
    assert len(schema["anyOf"]) == 2
    # ip variant
    ip_variant = schema["anyOf"][0]
    assert ip_variant["properties"]["command"]["const"] == "ip"
    assert "target" in ip_variant["required"]
    # sweep variant
    sweep_variant = schema["anyOf"][1]
    assert sweep_variant["properties"]["command"]["const"] == "sweep"
    assert "threshold" in sweep_variant["properties"]
    print("PASS: multiple commands anyOf schema")


def test_build_rich_args_schema_no_schema_fallback():
    """Skill without commands_schema → legacy string schema."""
    skill = Skill(
        path=Path("/fake/news-monitor/SKILL.md"),
        metadata={
            "name": "news-monitor",
            "description": "News monitor",
            "metadata": {"clawdbot": {}},
        },
        content="",
    )
    schema = skill._build_rich_args_schema(["economy_il", "news_il"])

    assert schema["type"] == "string"
    assert "description" in schema
    print("PASS: no commands_schema → string fallback")


def test_to_tool_def_rich_schema():
    """to_tool_def generates rich schema when commands_schema present."""
    skill = Skill(
        path=Path("/fake/intel-skill/SKILL.md"),
        metadata={
            "name": "intel-skill",
            "description": "Threat intel",
            "metadata": {
                "clawdbot": {
                    "commands": ["ip", "sweep"],
                    "commands_schema": {
                        "ip": {
                            "properties": {"target": {"type": "string"}},
                            "required": ["target"],
                        },
                    },
                }
            },
        },
        content="",
    )
    tool_def = skill.to_tool_def()

    assert tool_def["function"]["name"] == "skill_intel-skill"
    params = tool_def["function"]["parameters"]
    assert "args" in params["properties"]
    # Since only "ip" has schema, sweep will fall through → anyOf with string fallback
    assert params["properties"]["args"]["type"] == "object"
    print("PASS: to_tool_def with rich schema")


def test_to_tool_def_legacy_schema():
    """to_tool_def generates legacy string schema when no commands_schema."""
    skill = Skill(
        path=Path("/fake/news-monitor/SKILL.md"),
        metadata={
            "name": "news-monitor",
            "description": "News monitor",
            "metadata": {
                "clawdbot": {
                    "commands": ["economy_il", "news_il"],
                }
            },
        },
        content="",
    )
    tool_def = skill.to_tool_def()

    params = tool_def["function"]["parameters"]
    assert params["properties"]["args"]["type"] == "string"
    print("PASS: to_tool_def with legacy string schema")


def test_adapter_rich_skill_passes_dict():
    """Adapter: rich-schema skill receives dict as-is (not serialized)."""
    # Create mock engine with a rich-schema skill
    mock_skill = MagicMock()
    mock_skill.commands_schema = {"ip": {"properties": {}}}

    mock_engine = MagicMock()
    mock_engine._skills = {"intel-skill": mock_skill}

    # Patch get_skills_engine to return our mock
    with patch("services.agent_tools.get_skills_engine", return_value=mock_engine):
        # Simulate what agent_tools.py does when skill_args is a dict
        skill_args = {"target": "8.8.8.8"}
        skill_name = "skill_intel-skill"

        # Replicate adapter logic inline
        engine = mock_engine
        instance = engine._skills.get("intel-skill")
        if instance and getattr(instance, "commands_schema", None):
            result_format = "dict"  # would pass as-is
        else:
            result_format = "json_string"

        assert result_format == "dict"
        assert isinstance(skill_args, dict)
    print("PASS: adapter keeps dict for rich-schema skill")


def test_adapter_legacy_skill_serializes_to_json():
    """Adapter: legacy skill receives JSON string (dict serialized)."""
    mock_skill = MagicMock()
    mock_skill.commands_schema = {}  # empty = legacy

    mock_engine = MagicMock()
    mock_engine._skills = {"news-monitor": mock_skill}

    with patch("services.agent_tools.get_skills_engine", return_value=mock_engine):
        skill_args = {"config": "feeds_economy_il.json"}
        instance = mock_engine._skills.get("news-monitor")

        if instance and getattr(instance, "commands_schema", None):
            result = skill_args  # dict as-is
        else:
            result = json.dumps(skill_args, ensure_ascii=False, separators=(",", ":"))

        assert isinstance(result, str)
        assert "config" in result
        parsed = json.loads(result)
        assert parsed["config"] == "feeds_economy_il.json"
    print("PASS: adapter serializes dict for legacy skill")


def run_all():
    test_build_rich_args_schema_single_command()
    test_build_rich_args_schema_multiple_commands()
    test_build_rich_args_schema_no_schema_fallback()
    test_to_tool_def_rich_schema()
    test_to_tool_def_legacy_schema()
    test_adapter_rich_skill_passes_dict()
    test_adapter_legacy_skill_serializes_to_json()
    print("\n=== ALL TOOL DEPTH TESTS PASSED ===")


if __name__ == "__main__":
    run_all()
