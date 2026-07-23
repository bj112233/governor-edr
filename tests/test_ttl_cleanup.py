"""Quick smoke test for TTL cleanup in MonitorState (Sprint 4 refactor).

BreakingNewsMonitor was split into services/breaking_news/ — state lives in
MonitorState (services/breaking_news/state.py) now.
"""

import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from services.breaking_news.state import MonitorState, load_state


def test_cleanup_old_state():
    state = MonitorState()
    state.sent_links = {
        "old-link-1": time.time() - 90000,  # > 12h (25h)
        "old-link-2": time.time() - 100000,  # > 12h (~27.7h)
        "fresh-link-1": time.time() - 3600,  # 1h ago
        "fresh-link-2": time.time() - 300,  # 5 min ago
    }
    state.sent_titles = {
        "old title one": time.time() - 95000,
        "fresh title": time.time() - 600,
    }

    now = time.time()
    state.cleanup(now=now)

    assert "old-link-1" not in state.sent_links, "old-link-1 should be removed"
    assert "old-link-2" not in state.sent_links, "old-link-2 should be removed"
    assert "fresh-link-1" in state.sent_links, "fresh-link-1 should remain"
    assert "fresh-link-2" in state.sent_links, "fresh-link-2 should remain"

    assert "old title one" not in state.sent_titles, "old title should be removed"
    assert "fresh title" in state.sent_titles, "fresh title should remain"

    print("✅ TTL cleanup test passed")


def test_backward_compat_load():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(
            {
                "sent_links": ["link1", "link2"],
                "sent_titles": ["title1", "title2"],
                # v3 format had sent_embeddings — now dropped (dead code removed)
                "sent_embeddings": [[0.1, 0.2]],
            },
            f,
        )
        path = Path(f.name)

    state = asyncio.run(load_state(path))

    assert isinstance(state.sent_links, dict), f"sent_links should be dict, got {type(state.sent_links)}"
    assert isinstance(state.sent_titles, dict), f"sent_titles should be dict, got {type(state.sent_titles)}"
    assert "link1" in state.sent_links, "link1 should be in sent_links"
    assert "title1" in state.sent_titles, "title1 should be in sent_titles"
    # sent_embeddings is no longer loaded (dead code removed); clusters is the new store
    assert not hasattr(state, "sent_embeddings"), "sent_embeddings should not exist on new state"

    os.unlink(path)
    print("✅ Backward compat load test passed")


if __name__ == "__main__":
    test_cleanup_old_state()
    test_backward_compat_load()
    print("\n🎉 All tests passed!")
