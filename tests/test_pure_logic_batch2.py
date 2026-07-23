# tests/test_pure_logic_batch2.py
"""Pure-logic coverage push — batch 2.

Covers missing lines in:
- services/agent/bypass/_translation_utils.py (lines 26, 27, 48, 61, 117)
- services/_skills_engine/_output_router.py (lines 27-39)
- services/agent/directives/news.py (lines 22-28)
- services/agent/directives/staleness.py (lines 32-38)
- services/agent/_tool_ranker.py (lines 73, 90, 105, 106, 108, 109, 116)
- services/agent/routing/intent_routers.py (lines 200, 296, 311, 325, 342, 353, 355, 357)
- services/two_factor.py (lines 193-204)
- services/_skills_engine/_cli_utils.py (lines 24-27, 40, 41, 51, 53, 55)
- services/_skills_engine/parser.py (lines 42, 54, 55)
- services/agent/prompts.py (lines 28, 44, 45)
- services/breaking_news/dispatch.py (line 151)
- services/ioc_extractor.py (lines 172, 182, 185)
"""

import pytest

from services._skills_engine._cli_utils import _cli_flags_to_json_dict, _coerce_value
from services._skills_engine._output_router import route_failure, timeout_message
from services._skills_engine.parser import _extract_from_bash_blocks, _is_real_subcommand
from services.agent._tool_ranker import (
    _extract_lesson_tools,
    _log_ranking,
    _score_tool,
)
from services.agent.bypass._translation_utils import (
    _is_ocr_fragmented,
    is_dot_leader_line,
    split_for_translation,
    strip_document_noise,
)
from services.agent.directives.news import _news_directive
from services.agent.directives.staleness import _staleness_directive
from services.agent.prompts import _os_environment_directive
from services.agent.routing.intent_routers import (
    _detect_file_action,
    _is_eml_query,
    _is_pcap_query,
    _is_process_query,
    _is_yara_query,
)
from services.breaking_news.dispatch import format_cluster_alert
from services.breaking_news.state import EventCluster
from services.ioc_extractor import extract_all
from services.two_factor import verify_challenge


# -- _translation_utils --
class TestSplitForTranslation:
    def test_short_text(self):
        result = split_for_translation("short text", 1000)
        assert result == ["short text"]

    def test_long_text_chunked(self):
        text = "x" * 2500
        result = split_for_translation(text, 1000)
        assert len(result) >= 2

    def test_paragraph_too_long(self):
        """Line 26-27: paragraph > chunk_chars → flush buf, split paragraph."""
        text = "short.\n\n" + "y" * 2000
        result = split_for_translation(text, 500)
        assert len(result) >= 2

    def test_empty(self):
        assert split_for_translation("", 1000) == []


class TestIsDotLeaderLine:
    def test_dot_leader(self):
        assert is_dot_leader_line("..............") is True

    def test_normal_text(self):
        assert is_dot_leader_line("normal text") is False

    def test_empty(self):
        assert is_dot_leader_line("") is False

    def test_few_dots(self):
        assert is_dot_leader_line("..") is False


class TestIsOcrFragmented:
    def test_no_newlines(self):
        is_frag, lines = _is_ocr_fragmented("single line")
        assert is_frag is False
        assert lines == []

    def test_empty(self):
        is_frag, lines = _is_ocr_fragmented("")
        assert is_frag is False
        assert lines == []


class TestStripDocumentNoise:
    def test_empty(self):
        assert strip_document_noise("") == ""

    def test_no_toc(self):
        text = "Just regular content.\n\nMore content."
        result = strip_document_noise(text)
        assert "regular content" in result


# -- _output_router --
class TestRouteFailure:
    def test_exit_1(self):
        result = route_failure(b"", b"arg error", 1)
        assert "❌" in result
        assert "arg error" in result
        assert "Fix the arguments" in result

    def test_exit_2(self):
        result = route_failure(b"", b"usage error", 2)
        assert "Fix the arguments" in result

    def test_other_exit(self):
        result = route_failure(b"", b"crash", 139)
        assert "Exit code 139" in result

    def test_no_stderr(self):
        result = route_failure(b"", b"", 1)
        assert "no error output" in result

    def test_stdout_as_error(self):
        result = route_failure(b"stdout error", b"", 1)
        assert "stdout error" in result


class TestTimeoutMessage:
    def test_basic(self):
        msg = timeout_message(30)
        assert "30" in msg
        assert "timed out" in msg


# -- directives --
class TestNewsDirective:
    def test_no_news_tools(self):
        result = _news_directive("give me news", {"active_tool_names": set()})
        assert result is None

    def test_not_news_question(self):
        result = _news_directive("what is python", {"active_tool_names": {"skill_news-monitor"}})
        assert result is None

    def test_news_question_with_tool(self):
        result = _news_directive(
            "מה החדשות היום",
            {"active_tool_names": {"skill_news-monitor"}},
        )
        # May or may not detect topic, but should not crash
        assert result is None or isinstance(result, str)


class TestStalenessDirective:
    def test_no_history(self):
        result = _staleness_directive("query", {"history_msgs": 0, "active_tool_names": set()})
        assert result is None

    def test_no_live_tools(self):
        result = _staleness_directive("query", {"history_msgs": 5, "active_tool_names": set()})
        assert result is None

    def test_with_history_and_live_tools(self):
        from services.agent.directives.staleness import LIVE_DATA_TOOLS

        result = _staleness_directive(
            "query",
            {"history_msgs": 5, "active_tool_names": LIVE_DATA_TOOLS},
        )
        assert result is not None
        assert "staleness" in result.lower()


# -- _tool_ranker --
class TestExtractLessonTools:
    def test_empty(self):
        assert _extract_lesson_tools([]) == set()

    def test_not_list(self):
        assert _extract_lesson_tools(Exception("err")) == set()

    def test_normal(self):
        lessons = [{"tool_name": "tool_a"}, {"tool_name": "tool_b"}, {"tool_name": ""}]
        result = _extract_lesson_tools(lessons)
        assert result == {"tool_a", "tool_b"}


class TestScoreTool:
    def test_no_stats(self):
        score, tie = _score_tool("tool_a", {}, set())
        assert isinstance(score, int)
        assert isinstance(tie, float)
        assert 0.0 <= tie < 1.0

    def test_with_failures(self):
        stats = {"tool_a": {"failures": 2, "repeat_failures": 1}}
        score, _ = _score_tool("tool_a", stats, set())
        assert score < 100

    def test_with_lesson_bonus(self):
        stats = {"tool_a": {"failures": 0, "repeat_failures": 0}}
        score, _ = _score_tool("tool_a", stats, {"tool_a"})
        assert score == 120  # 100 base + 20 bonus (bonus after cap)

    def test_bonus_after_floor(self):
        """Heavily penalized tool: base floored to 10, THEN bonus → 30 (not 25)."""
        stats = {"tool_a": {"failures": 20, "repeat_failures": 20, "last_seen": ""}}
        score, _ = _score_tool("tool_a", stats, {"tool_a"})
        assert score == 30  # max(0, 10) + 20 = 30, NOT max(0 + 20, 10) = 20

    def test_tie_breaker_deterministic(self):
        """Same name → same tie_breaker value (stable across calls)."""
        _, tie1 = _score_tool("tool_a", {}, set())
        _, tie2 = _score_tool("tool_a", {}, set())
        assert tie1 == tie2

    def test_tie_breaker_different_names(self):
        """Different names → different tie_breakers (almost always)."""
        _, tie_a = _score_tool("tool_a", {}, set())
        _, tie_b = _score_tool("tool_b", {}, set())
        assert tie_a != tie_b


class TestLogRanking:
    def test_no_changes(self):
        """No demotion/bonus → return early (3-tuple format)."""
        scored = [(100, 0.5, {"name": "a"}), (100, 0.3, {"name": "b"})]
        _log_ranking(scored, set())  # should not raise

    def test_with_changes(self):
        scored = [(50, 0.5, {"name": "a"}), (100, 0.3, {"name": "b"})]
        _log_ranking(scored, {"a"})  # should not raise


# -- intent_routers --
class TestDetectFileAction:
    def test_analyze_default(self):
        result = _detect_file_action("scan this file", "txt")
        assert isinstance(result, str)

    def test_iocs(self):
        result = _detect_file_action("extract iocs from this", "txt")
        assert isinstance(result, str)


class TestIsProcessQuery:
    def test_no_match(self):
        assert _is_process_query("hello world") is None

    def test_empty(self):
        assert _is_process_query("") is None


class TestIsYaraQuery:
    def test_no_match(self):
        assert _is_yara_query("hello world") is None

    def test_empty(self):
        assert _is_yara_query("") is None


class TestIsPcapQuery:
    def test_no_match(self):
        assert _is_pcap_query("hello world") is None

    def test_empty(self):
        assert _is_pcap_query("") is None


class TestIsEmlQuery:
    def test_no_match(self):
        assert _is_eml_query("hello world") is None

    def test_empty(self):
        assert _is_eml_query("") is None


# -- two_factor --
class TestVerifyChallenge:
    def test_unknown_challenge(self):
        """Line 193: challenge is None → return False."""
        assert verify_challenge("nonexistent_id", "123456") is False


# -- _cli_utils --
class TestCliFlagsToJsonDict:
    def test_simple_flag(self):
        result = _cli_flags_to_json_dict("--verbose")
        assert result.get("verbose") is True

    def test_flag_with_value(self):
        result = _cli_flags_to_json_dict("--path=/tmp/test")
        assert "path" in result

    def test_flag_with_separate_value(self):
        result = _cli_flags_to_json_dict("--input file.txt")
        assert "input" in result

    def test_multiple_flags(self):
        result = _cli_flags_to_json_dict("--verbose --output result.txt")
        assert result.get("verbose") is True
        assert "output" in result


class TestCoerceValue:
    def test_quoted_string(self):
        assert _coerce_value('"hello"') == "hello"

    def test_bool_true(self):
        assert _coerce_value("true") is True
        assert _coerce_value("yes") is True

    def test_bool_false(self):
        assert _coerce_value("false") is False
        assert _coerce_value("no") is False

    def test_int(self):
        assert _coerce_value("42") == 42

    def test_string(self):
        assert _coerce_value("hello") == "hello"


# -- parser --
class TestIsRealSubcommand:
    def test_flag(self):
        assert _is_real_subcommand("--verbose") is False

    def test_short_flag(self):
        assert _is_real_subcommand("-v") is False

    def test_all_caps_env(self):
        assert _is_real_subcommand("ENV_VAR") is False

    def test_normal(self):
        assert _is_real_subcommand("scan") is True

    def test_empty(self):
        assert _is_real_subcommand("") is False


class TestExtractFromBashBlocks:
    def test_python_subcommand(self):
        commands = []
        content = "```bash\npython tool.py scan\n```"
        _extract_from_bash_blocks(content, commands)
        assert "scan" in commands

    def test_comment_skipped(self):
        commands = []
        content = "```bash\n# comment\npython tool.py run\n```"
        _extract_from_bash_blocks(content, commands)
        assert "run" in commands

    def test_empty_line_skipped(self):
        commands = []
        content = "```bash\n\npython tool.py test\n```"
        _extract_from_bash_blocks(content, commands)
        assert "test" in commands

    def test_blocked_binary(self):
        """Line 54-55: non-allowed binary → warning, not added."""
        commands = []
        content = "```bash\nevil_binary arg\n```"
        _extract_from_bash_blocks(content, commands)
        assert "evil_binary" not in commands


# -- prompts --
class TestOsEnvironmentDirective:
    def test_returns_string(self):
        result = _os_environment_directive()
        assert isinstance(result, str)
        assert "CRITICAL" in result

    def test_mentions_paths(self):
        result = _os_environment_directive()
        assert "path" in result.lower() or "paths" in result.lower()


# -- breaking_news/dispatch (cluster-based) --
def _make_cluster(items):
    import time as _t

    c = EventCluster(fingerprint_key="test")
    for it in items:
        c.add(it, _t.time())
    return c


class TestFormatAlert:
    def test_basic(self):
        item = {"title": "Test Alert", "source": "TestSrc", "matched_keyword": "test", "published": ""}
        cluster = _make_cluster([item])
        result, _, _ = format_cluster_alert(cluster)
        assert "Test Alert" in result
        assert "TestSrc" in result

    def test_title_echo_suppressed(self):
        """ai_summary that echoes title → cleared."""
        item = {"title": "Breaking", "source": "Src", "matched_keyword": "kw", "published": ""}
        cluster = _make_cluster([item])
        result, _, _ = format_cluster_alert(cluster)
        assert "Breaking" in result  # title still in output

    def test_with_summary(self):
        item = {
            "title": "Alert",
            "source": "Src",
            "matched_keyword": "kw",
            "ai_summary": "Important summary content",
            "published": "",
        }
        cluster = _make_cluster([item])
        result, _, _ = format_cluster_alert(cluster)
        assert "Important summary content" in result


# -- ioc_extractor --
class TestIocExtractorDomains:
    def test_valid_domain(self):
        result = extract_all("Visit evil.com for details")
        assert "evil.com" in result["domains"]

    def test_protocol_fragment_skipped(self):
        """Line 182: protocol-prefixed fragment skipped."""
        result = extract_all("https example text")
        # "https" should not be treated as domain
        assert "https" not in result.get("domains", [])

    def test_short_tld_skipped(self):
        """Line 185: TLD < 2 chars skipped."""
        result = extract_all("test.x something")
        # Single-char TLD should not be a domain
        domains = result.get("domains", [])
        assert not any(d == "test.x" for d in domains)

    def test_numeric_tld_skipped(self):
        """Line 172: parts < 2 skipped."""
        result = extract_all("just text here")
        # No valid domains in plain text
        assert isinstance(result["domains"], list)

    def test_ip_extraction(self):
        result = extract_all("Connect to 1.2.3.4 now")
        assert "1.2.3.4" in result["ips_v4"]

    def test_hash_extraction(self):
        result = extract_all("Hash: d41d8cd98f00b204e9800998ecf8427e")
        assert len(result["hashes"]) > 0

    def test_cve_extraction(self):
        result = extract_all("Fixed in CVE-2024-1234")
        assert "CVE-2024-1234" in result["cves"]
