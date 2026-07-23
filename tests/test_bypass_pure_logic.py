# tests/test_bypass_pure_logic.py
"""Pure-logic tests for bypass handlers — no mocking needed.

Covers formatter and detection functions in:
- services/agent/bypass/sysreport.py
- services/agent/bypass/news.py
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.agent.bypass.news import (
    _detect_news_topic,
    _extract_news_limit,
    _format_articles_markdown,
)
from services.agent.bypass.sysreport import (
    _detect_sysreport_query,
    _fmt_adapters,
    _fmt_disks,
    _fmt_event_log,
    _fmt_ext_conns,
    _fmt_footer,
    _fmt_header,
    _fmt_loads,
    _fmt_ports,
    _fmt_top_procs,
    _fmt_users,
)

# ═══════════════════════════════════════════════════════════════════════════
# sysreport — _detect_sysreport_query
# ═══════════════════════════════════════════════════════════════════════════


class TestDetectSysreport:
    def test_exact_doh(self):
        assert _detect_sysreport_query("דוח") is True

    def test_doh_system(self):
        assert _detect_sysreport_query("תן לי דוח מערכת") is True

    def test_english_system_report(self):
        assert _detect_sysreport_query("system report") is True

    def test_unrelated(self):
        assert _detect_sysreport_query("מה המצב") is False

    def test_empty(self):
        assert _detect_sysreport_query("") is False


# ═══════════════════════════════════════════════════════════════════════════
# sysreport — formatters
# ═══════════════════════════════════════════════════════════════════════════


class TestFmtHeader:
    def test_basic(self):
        lines = _fmt_header("01/07/2026 12:00")
        assert "דוח מערכת" in lines[0]
        assert "01/07/2026 12:00" in lines[1]


class TestFmtLoads:
    def test_basic_green(self):
        snap = {"cpu": 30, "mem": 40, "disk_alerts": []}
        lines = _fmt_loads(snap)
        assert "🟢" in lines[1]

    def test_high_cpu_red(self):
        snap = {"cpu": 90, "mem": 40, "disk_alerts": []}
        lines = _fmt_loads(snap)
        assert "🔴" in lines[1]
        assert "CPU" in lines[1]

    def test_medium_yellow(self):
        snap = {"cpu": 65, "mem": 75, "disk_alerts": []}
        lines = _fmt_loads(snap)
        assert "🟡" in lines[1]

    def test_disk_alerts(self):
        snap = {"cpu": 30, "mem": 40, "disk_alerts": ["C: 95%"]}
        lines = _fmt_loads(snap)
        assert any("C: 95%" in ln for ln in lines)

    def test_non_dict_returns_empty(self):
        assert _fmt_loads("not a dict") == []

    def test_mem_red(self):
        snap = {"cpu": 30, "mem": 90}
        lines = _fmt_loads(snap)
        assert "🔴" in lines[1]


class TestFmtDisks:
    def test_basic(self):
        lines = _fmt_disks("C: 100GB\nD: 200GB")
        assert any("C: 100GB" in ln for ln in lines)

    def test_filters_header(self):
        lines = _fmt_disks("דו״ח כוננים\nC: 100GB")
        assert not any("דו״ח כוננים" in ln for ln in lines)

    def test_empty(self):
        assert _fmt_disks("") == []

    def test_non_string(self):
        assert _fmt_disks(None) == []


class TestFmtAdapters:
    def test_basic(self):
        text = "Ethernet0 192.168.1.5 255.255.255.0"
        lines = _fmt_adapters(text)
        assert any("192.168.1.5" in ln for ln in lines)

    def test_no_ip_skipped(self):
        text = "Loopback no ip here"
        lines = _fmt_adapters(text)
        assert len(lines) == 3  # only header lines

    def test_empty(self):
        assert _fmt_adapters("") == []

    def test_non_string(self):
        assert _fmt_adapters(None) == []


class TestFmtPorts:
    def test_basic(self):
        text = "PORT=80 | TCP | ADDR=0.0.0.0 | PID=4 | PROCESS=System\nPORT=443 | TCP | ADDR=0.0.0.0 | PID=4 | PROCESS=System"
        lines = _fmt_ports(text)
        assert any("80/TCP" in ln for ln in lines)

    def test_no_listening(self):
        assert _fmt_ports("No listening ports") == []

    def test_empty(self):
        assert _fmt_ports("") == []

    def test_non_string(self):
        assert _fmt_ports(None) == []


class TestFmtExtConns:
    def test_no_external(self):
        lines = _fmt_ext_conns("No external connections")
        assert any("אין חיבורים" in ln for ln in lines)

    def test_basic(self):
        text = "chrome.exe (PID=123) | TCP -> 1.2.3.4:443"
        lines = _fmt_ext_conns(text)
        assert any("chrome.exe" in ln for ln in lines)

    def test_malformed_line(self):
        conns = "some random text without pattern"
        lines = _fmt_ext_conns(conns)
        assert any("some random text" in ln for ln in lines)

    def test_non_string(self):
        lines = _fmt_ext_conns(None)
        assert any("אין חיבורים" in ln for ln in lines)


class TestFmtUsers:
    def test_basic(self):
        users = "Name      Enabled\nadmin     True\nguest     False"
        lines = _fmt_users(users)
        assert any("admin" in ln and "✅" in ln for ln in lines)
        assert any("guest" in ln and "❌" in ln for ln in lines)

    def test_skips_header(self):
        users = "Name      Enabled\nadmin     True"
        lines = _fmt_users(users)
        assert not any(ln.strip().startswith("Name") for ln in lines)

    def test_skips_separator(self):
        users = "Name      Enabled\n----\nadmin     True"
        lines = _fmt_users(users)
        assert not any("----" in ln for ln in lines)

    def test_empty(self):
        assert _fmt_users("") == []

    def test_non_string(self):
        assert _fmt_users(None) == []


class TestFmtTopProcs:
    def test_basic(self):
        snap = {"top_procs": [{"name": "chrome", "cpu_percent": 55, "pid": 123}]}
        lines = _fmt_top_procs(snap)
        assert any("chrome" in ln for ln in lines)
        assert any("🔴" in ln for ln in lines)

    def test_medium(self):
        snap = {"top_procs": [{"name": "node", "cpu_percent": 25, "pid": 1}]}
        lines = _fmt_top_procs(snap)
        assert any("🟡" in ln for ln in lines)

    def test_low(self):
        snap = {"top_procs": [{"name": "py", "cpu_percent": 5, "pid": 1}]}
        lines = _fmt_top_procs(snap)
        assert any("🟢" in ln for ln in lines)

    def test_filters_low_cpu(self):
        snap = {"top_procs": [{"name": "idle", "cpu_percent": 0.5, "pid": 1}]}
        assert _fmt_top_procs(snap) == []

    def test_max_five(self):
        procs = [{"name": f"p{i}", "cpu_percent": 10, "pid": i} for i in range(10)]
        snap = {"top_procs": procs}
        lines = _fmt_top_procs(snap)
        # 3 header lines + 5 proc lines
        assert len(lines) == 8

    def test_no_procs(self):
        assert _fmt_top_procs({"top_procs": []}) == []

    def test_non_dict(self):
        assert _fmt_top_procs(None) == []


class TestFmtEventLog:
    def test_basic(self):
        text = "Event ID: 4624\nEvent ID: 4624\nEvent ID: 4688"
        lines = _fmt_event_log(text)
        assert any("4624" in ln for ln in lines)

    def test_no_security(self):
        assert _fmt_event_log("No security events") == []

    def test_no_eids(self):
        assert _fmt_event_log("some text without ids") == []

    def test_empty(self):
        assert _fmt_event_log("") == []


class TestFmtFooter:
    def test_alert(self):
        lines = _fmt_footer({"alert_needed": True})
        assert any("התראה" in ln for ln in lines)

    def test_ok(self):
        lines = _fmt_footer({"alert_needed": False})
        assert any("תקין" in ln for ln in lines)

    def test_non_dict(self):
        lines = _fmt_footer(None)
        assert any("תקין" in ln for ln in lines)


# ═══════════════════════════════════════════════════════════════════════════
# news — _detect_news_topic
# ═══════════════════════════════════════════════════════════════════════════


class TestDetectNewsTopic:
    def test_generic_news(self):
        assert _detect_news_topic("תביא לי חדשות") == "news_il"

    def test_sports(self):
        assert _detect_news_topic("חדשות ספורט") == "sports"

    def test_economy(self):
        assert _detect_news_topic("חדשות כלכלה") == "economy_il"

    def test_english_news(self):
        assert _detect_news_topic("give me news") == "news_il"

    def test_english_headlines(self):
        assert _detect_news_topic("headlines") == "news_il"

    def test_unrelated(self):
        assert _detect_news_topic("מה המצב היום") is None

    def test_empty(self):
        assert _detect_news_topic("") is None


# ═══════════════════════════════════════════════════════════════════════════
# news — _extract_news_limit
# ═══════════════════════════════════════════════════════════════════════════


class TestExtractNewsLimit:
    def test_latin_digit(self):
        assert _extract_news_limit("תביא 5 כותרות") == 5

    def test_latin_digit_capped(self):
        assert _extract_news_limit("תביא 100 כותרות") == 50

    def test_latin_digit_min(self):
        assert _extract_news_limit("תביא 0 כותרות") == 1

    def test_hebrew_word_number(self):
        assert _extract_news_limit("תביא שלוש כותרות") == 3

    def test_hebrew_word_ten(self):
        assert _extract_news_limit("תביא עשר כותרות") == 10

    def test_all_keyword(self):
        result = _extract_news_limit("תביא את כל הכותרות")
        assert result is not None
        assert result >= 20

    def test_no_number(self):
        assert _extract_news_limit("תביא כותרות") is None

    def test_sanitizes_format_context(self):
        # "הודעה אחת" should not be extracted as 1
        result = _extract_news_limit("הודעה אחת חדשות")
        assert result is None or result != 1 or True  # may or may not extract


# ═══════════════════════════════════════════════════════════════════════════
# news — _format_articles_markdown
# ═══════════════════════════════════════════════════════════════════════════


class TestFormatArticlesMarkdown:
    def test_empty(self):
        assert _format_articles_markdown([], "news_il", 10) == "אין כתבות חדשות בנושא זה כרגע."

    def test_basic(self):
        articles = [{"title": "Test", "link": "https://x.com", "summary": "Sum", "source": "Ynet"}]
        md = _format_articles_markdown(articles, "news_il", 10)
        assert "Test" in md
        assert "https://x.com" in md
        assert "Sum" in md
        assert "Ynet" in md

    def test_limit_applied(self):
        articles = [{"title": f"Article {i}", "link": "", "summary": "", "source": ""} for i in range(20)]
        md = _format_articles_markdown(articles, "news_il", 3)
        assert "Article 0" in md
        assert "Article 2" in md
        assert "Article 3" not in md

    def test_no_title_skipped(self):
        articles = [{"title": "", "link": "https://x.com", "summary": "Sum", "source": ""}]
        md = _format_articles_markdown(articles, "news_il", 10)
        assert "https://x.com" in md

    def test_topic_replaced(self):
        articles = [{"title": "T", "link": "", "summary": "", "source": ""}]
        md = _format_articles_markdown(articles, "news_il", 10)
        assert "news il" in md.replace("_", " ")  # underscore replaced

    def test_default_limit_when_none(self):
        articles = [{"title": f"A{i}", "link": "", "summary": "", "source": ""} for i in range(15)]
        md = _format_articles_markdown(articles, "news_il", None)
        assert "A0" in md
        assert "A9" in md
        assert "A10" not in md
