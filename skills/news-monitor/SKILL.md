---
name: news-monitor
description: "Live news scraping from RSS feeds with optional AI summarization, sentiment analysis, and story clustering. Do NOT use CLI flags. Pass exactly ONE compacted JSON string matching the NewsMonitorArgs schema. Pre-configured topics — economy_il / news_il / cyber / tech_ai / world / security_mil / politics_il / sports / health / auto / realestate. Trigger ALWAYS when user asks חדשות, news, מבזקים, market updates, recent or today's headlines, OR asks to summarize/consolidate articles on ANY topic. DO NOT answer from memory — always fetch live. IMPORTANT: To get a detailed consolidated summary instead of raw headlines, pass args with {\"summarize\":true, \"extract\":true, \"cluster\":true}."
metadata: {"clawdbot":{"emoji":"📰","commands":["economy_il","news_il","cyber","tech_ai","world","security_mil","politics_il","sports","health","auto","realestate"],"arg_template":"scripts/news_monitor.py '{args}'","timeout":60,"args_description":"Optional JSON overrides. For raw headlines: leave empty. For AI summary per article: pass {\"summarize\":true}. For better quality: add {\"extract\":true} (fetches full text). For consolidated cluster headlines: add {\"cluster\":true}. Full pipeline example: '{\"limit\":10,\"summarize\":true,\"extract\":true,\"cluster\":true}'. Config auto-derived from command.","command_to_args_template":"{\"config\":\"config/feeds_{command}.json\"}","requires":{"bins":["python"],"python_libs":["feedparser","beautifulsoup4","aiosqlite","html2text","readability-lxml"]},"install":[{"id":"pip-news","kind":"pip","packages":["feedparser","beautifulsoup4","aiosqlite","html2text","readability-lxml"],"label":"Install news monitoring dependencies"}],"commands_schema":{"*":{"properties":{"limit":{"type":"integer","description":"Max articles to fetch","default":15},"summarize":{"type":"boolean","description":"AI summary per article","default":false},"extract":{"type":"boolean","description":"Fetch full article text","default":false},"cluster":{"type":"boolean","description":"Cluster related stories","default":false},"keywords":{"type":"string","description":"Comma-separated alert keywords"},"alert":{"type":"boolean","description":"Alert on keyword matches","default":false}}}}}}
---

# News Monitor

Scrape headlines and articles from configured news sites or RSS feeds, then summarize or alert on keywords.

## Quick start

**Do NOT use CLI flags like `--limit`. You MUST pass exactly ONE argument which is a compacted JSON string matching the expected schema.**

```bash
# Israeli economy/finance news:
python {baseDir}/scripts/news_monitor.py '{"config":"config/feeds_economy_il.json","limit":15}'

# Generic single feed:
python {baseDir}/scripts/news_monitor.py '{"feed":"https://feeds.bbci.co.uk/news/rss.xml","limit":5}'

# HTML scraping with CSS selector:
python {baseDir}/scripts/news_monitor.py '{"site":"https://news.ycombinator.com","selector":".titleline>a","limit":10}'

# Multi-feed with keyword alerts:
python {baseDir}/scripts/news_monitor.py '{"config":"config/feeds_economy_il.json","keywords":"ריבית,דולר,בורסה","alert":true}'
```

## Pre-configured feed sets (in `config/`)

| Topic | File | Hebrew trigger | English trigger |
|-------|------|----------------|------------------|
| כלכלה ישראלית | `config/feeds_economy_il.json` | חדשות כלכלה, שוק ההון, בורסה | israeli economy, stock market |
| חדשות ישראל | `config/feeds_news_il.json` | חדשות, מבזקים, מה קורה | israel news |
| סייבר | `config/feeds_cyber.json` | סייבר, פריצה, האקרים | cyber, infosec, ransomware |
| טכנולוגיה/AI | `config/feeds_tech_ai.json` | טכנולוגיה, AI, סטארט-אפ | tech, AI, startup |
| ביטחון/צבא | `config/feeds_security_mil.json` | ביטחוני, צה"ל, מלחמה | defense, military, IDF |
| פוליטיקה | `config/feeds_politics_il.json` | פוליטיקה, כנסת, ממשלה | israeli politics, knesset |
| ספורט | `config/feeds_sports.json` | ספורט, כדורגל, NBA | sports, football, basketball |
| בריאות | `config/feeds_health.json` | בריאות, רפואה | health, medicine |
| רכב | `config/feeds_auto.json` | רכב, מכונית | auto, cars |
| נדל"ן | `config/feeds_realestate.json` | נדל"ן, דירות, שכירות | real estate, housing |

## Common tasks

| Task | JSON Example |
|------|-------------|
| RSS digest | `{"feed":"<url>","summarize":true,"limit":10}` |
| Site scrape | `{"site":"<url>","selector":"<css>","limit":10}` |
| Keyword alerts | `{"config":"feeds.json","keywords":"word1,word2","alert":true}` |
| Save to report | `{"config":"feeds.json","output":"reports/news.md"}` |

## AI / NLP fields (require LLM endpoint at `LLM_API_BASE`, default `localhost:5001/v1`)

| Field | Type | Description |
|-------|------|-------------|
| `summarize` | bool | Generate 1-3 sentence AI summary per article (`ai_summary` field). Pair with `extract` for full-text input. |
| `sentiment` | bool | Classify each article as `positive` / `negative` / `neutral` / `unknown` (`sentiment` field). |
| `llm_categorize` | bool | Zero-shot categorize each article into one of the categories defined in `config` feeds. |
| `cluster` | bool | Group articles into story clusters via embeddings + HAC. |
| `cluster_threshold` | float | Cosine similarity threshold for `cluster` (default `0.82`). Higher = tighter clusters. |
| `semantic_dedup` | bool | Suppress near-duplicate articles via embedding similarity. |
| `semantic_threshold` | float | Cosine threshold for `semantic_dedup` (default `0.92`). |
| `extract` | bool | Fetch full article text in parallel (readability-lxml). Improves `summarize` quality. |
| `categorize` | bool | Run heuristic auto-categorizer on items lacking a `category` field (no LLM). |

## Performance fields

| Field | Type | Description |
|-------|------|-------------|
| `workers` | int (≥1) | Concurrent feed fetchers (default `5`; set `1` for serial mode). |
| `delay` | float (≥0) | Sleep between feeds when using `config` (default `1.0`; ignored when `workers > 1`). |
| `cooldown` | int (≥0) | With `alert`, suppress repeated alerts on the same link within N seconds (`0` = once-ever). |

## Example: full AI pipeline

```bash
python {baseDir}/scripts/news_monitor.py \
  '{"config":"config/feeds_economy_il.json","limit":20,"extract":true,"summarize":true,"sentiment":true,"cluster":true,"cluster_threshold":0.82,"format":"json","output":"reports/news_ai.json"}'
```

## Config format (`config/feeds.json`)

```json
{
  "feeds": [
    {"name": "BBC", "url": "https://feeds.bbci.co.uk/news/rss.xml", "type": "rss"},
    {"name": "Haaretz", "url": "https://www.haaretz.co.il/cmlink/...", "type": "rss"}
  ],
  "keywords": ["cybersecurity", "startup", "AI"],
  "check_interval_minutes": 60
}
```

## Output
- Markdown summaries with title, link, snippet, and matched keywords.
- Alert mode prints matched items to stdout for Sentinel event bus integration.

## Notes
- **Keyword matching** uses word-boundary regex (case-insensitive).
- **Dedup**: items are deduplicated by `link` across overlapping feeds.
- **Alert persistence**: matched links stored in `reference.db` under `skill_state` table; only **new** matches are emitted on subsequent runs.
- **Inter-feed delay**: `delay` field (default `1.0`) when using `config` with multiple feeds.
- For Hebrew sites, aiohttp auto-detects UTF-8.
