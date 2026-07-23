---
name: web-scraper
description: Web scraping via scripts/web_scraper.py. Use command 'python', args 'scripts/web_scraper.py fetch --url <url> --selector <css>', or 'scripts/web_scraper.py price --url <url> --selector <css> --threshold <N>', or 'scripts/web_scraper.py table --url <url> --selector <css> --format csv', or 'scripts/web_scraper.py watch --url <url> --selector <css>'. Trigger when asked to fetch a page, track a price, or extract structured data from a website.
metadata: {"clawdbot":{"emoji":"🌐","commands":["fetch","price","table","watch","batch"],"arg_template":"scripts/web_scraper.py {command} {args}","requires":{"bins":["python"],"python_libs":["requests","beautifulsoup4","lxml","html2text"]},"install":[{"id":"pip-scrape","kind":"pip","packages":["requests","beautifulsoup4","lxml","html2text"],"label":"Install web scraping dependencies"}],"commands_schema":{"profile":{"properties":{"name":{"type":"string"},"query":{"type":"string"},"limit":{"type":"integer","default":10},"output":{"type":"string"},"list":{"type":"boolean"}},"required":["name"]},"fetch":{"properties":{"url":{"type":"string"},"selector":{"type":"string","default":"article, .content, main"},"limit":{"type":"integer","default":0},"output":{"type":"string"}},"required":["url"]},"price":{"properties":{"url":{"type":"string"},"selector":{"type":"string"},"threshold":{"type":"number","default":0},"alert":{"type":"boolean"}},"required":["url","selector"]},"table":{"properties":{"url":{"type":"string"},"selector":{"type":"string"},"format":{"type":"string","enum":["csv","json","markdown"],"default":"csv"},"output":{"type":"string"}},"required":["url","selector"]},"watch":{"properties":{"url":{"type":"string"},"selector":{"type":"string"},"interval":{"type":"integer","default":3600},"alert":{"type":"boolean"},"once":{"type":"boolean"}},"required":["url","selector"]},"batch":{"properties":{"urls":{"type":"string"},"selector":{"type":"string","default":"h2"},"delay":{"type":"number","default":1.0},"output":{"type":"string"}},"required":["urls"]}}}}
---

# Web Scraper

Fetch pages and extract text, tables, or specific elements for personal intelligence gathering.

## Quick start

```bash
python {baseDir}/scripts/web_scraper.py fetch --url "https://example.com" --selector "article" --output article.md
python {baseDir}/scripts/web_scraper.py price --url "https://store.example.com/item" --selector ".price" --threshold 100 --alert
python {baseDir}/scripts/web_scraper.py table --url "https://example.com/data" --selector "table" --format csv --output data.csv
```

## Common tasks

- Article extraction: `fetch --url <url> --selector "article" --limit 5`
- Price tracking: `price --url <url> --selector <css> --threshold 50`
- Table to CSV: `table --url <url> --selector "table" --format csv`
- Monitor page changes: `watch --url <url> --selector <css> --interval 3600 --alert`
- Bulk URLs: `batch --urls urls.txt --selector "h2" --delay 1 --output results.json`

## Output
- Markdown text (default).
- CSV/JSON for structured data (`--format csv|json`).
- Alert mode prints to stdout when threshold/change detected.

## Global flags

- `--user-agent <UA>` — override User-Agent (default: `SentinelBot/1.0`, env `SENTINEL_USER_AGENT`).
- `--retries N` — retries on 429/5xx/network errors with exponential backoff (default: 3).
- `--no-robots` — skip robots.txt check (use responsibly).

## Notes
- **robots.txt** is enforced by default; cached per host. Use `--no-robots` to bypass.
- **Retries**: 429 / 500-504 / connection / timeout trigger exponential backoff (1.5^attempt + jitter).
- **`watch` persistence**: hash stored under `state/skills/web_scraper_watch_<hash>.json` (or `$SENTINEL_STATE_DIR`); `--once` is suitable for cron / scheduled tasks.
- **`price` parsing** supports `1,234.56`, `1.234,56`, `1,234`, etc. (decimal heuristic by trailing 1–2 digits).
- **JS-heavy sites**: not supported (Playwright/Selenium not included).
- **Hebrew sites**: auto-detect encoding via `response.apparent_encoding`.
