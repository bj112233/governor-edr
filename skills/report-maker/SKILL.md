---
name: report-maker
description: "Generate reports via scripts/report_maker.py. Use command 'python', args 'scripts/report_maker.py --input <file_or_json> --format markdown --output <file>'. The --input value can be either (a) a path to an existing file, or (b) a valid inline JSON string. Supports markdown and html output. Trigger when asked to create a report, dashboard snippet, or export results. CRITICAL: You MUST provide the `command` field. Leave the `input` field EXACTLY empty ('') — the system automatically injects all previously gathered tool outputs via a temporary file. Do NOT invent or guess a file path for `input`. OUTPUT CONTRACT: When `output` parameter is OMITTED, the rendered report is returned directly as tool output text — use it immediately for final_answer, do NOT retry, do NOT call file-analyst to convert it (it is ALREADY markdown/html). When `output` parameter is specified, the report is saved to that file path and a confirmation message '✅ Report saved to <path>' is returned."
metadata: {"clawdbot":{"emoji":"📊","commands":["default","table","briefing","timeline","daily_digest","contract","watchlist","incident_report","security_audit"],"arg_template":"scripts/report_maker.py --template {command} {args}","timeout":60,"requires":{"bins":["python"],"python_libs":["jinja2","markdown","weasyprint"]},"install":[{"id":"pip-reports","kind":"pip","packages":["jinja2","markdown","weasyprint"],"label":"Install report generation dependencies"}],"commands_schema":{"default":{"properties":{"input":{"type":"string","description":"Leave this EXACTLY empty (''). The system automatically injects all previously gathered tool outputs here via a temporary file. Do NOT invent or guess a file path."},"inputs":{"type":"string","description":"Comma-separated paths to merge multiple files"},"stdin":{"type":"boolean","description":"Read input from stdin","default":false},"format":{"type":"string","enum":["markdown","html","pdf"],"default":"markdown"},"output":{"type":"string","description":"Output file path"}},"required":["input"]},"table":{"properties":{"input":{"type":"string","description":"Leave this EXACTLY empty (''). The system automatically injects all previously gathered tool outputs here via a temporary file. Do NOT invent or guess a file path."},"format":{"type":"string","enum":["markdown","html","pdf"],"default":"html"},"output":{"type":"string"}},"required":["input"]},"briefing":{"properties":{"input":{"type":"string","description":"Leave this EXACTLY empty (''). The system automatically injects all previously gathered tool outputs here via a temporary file. Do NOT invent or guess a file path."},"format":{"type":"string","enum":["markdown","html","pdf"],"default":"markdown"},"output":{"type":"string"}},"required":["input"]},"timeline":{"properties":{"input":{"type":"string","description":"Leave this EXACTLY empty (''). The system automatically injects all previously gathered tool outputs here via a temporary file. Do NOT invent or guess a file path."},"format":{"type":"string","enum":["markdown","html","pdf"],"default":"markdown"},"output":{"type":"string"}},"required":["input"]},"daily_digest":{"properties":{"input":{"type":"string","description":"Leave this EXACTLY empty (''). The system automatically injects all previously gathered tool outputs here via a temporary file. Do NOT invent or guess a file path."},"format":{"type":"string","enum":["markdown","html","pdf"],"default":"markdown"},"output":{"type":"string"}},"required":["input"]},"contract":{"properties":{"input":{"type":"string","description":"Leave this EXACTLY empty (''). The system automatically injects all previously gathered tool outputs here via a temporary file. Do NOT invent or guess a file path."},"format":{"type":"string","enum":["markdown","html","pdf"],"default":"markdown"},"output":{"type":"string"}},"required":["input"]},"watchlist":{"properties":{"input":{"type":"string","description":"Leave this EXACTLY empty (''). The system automatically injects all previously gathered tool outputs here via a temporary file. Do NOT invent or guess a file path."},"format":{"type":"string","enum":["markdown","html","pdf"],"default":"markdown"},"output":{"type":"string"}},"required":["input"]},"incident_report":{"properties":{"input":{"type":"string","description":"Leave this EXACTLY empty (''). The system automatically injects all previously gathered tool outputs here via a temporary file. Do NOT invent or guess a file path."},"format":{"type":"string","enum":["markdown","html","pdf"],"default":"markdown"},"output":{"type":"string"}},"required":["input"]},"security_audit":{"properties":{"input":{"type":"string","description":"Leave this EXACTLY empty (''). The system automatically injects all previously gathered tool outputs here via a temporary file. Do NOT invent or guess a file path."},"format":{"type":"string","enum":["markdown","html","pdf"],"default":"markdown"},"output":{"type":"string"}},"required":["input"]}}}}
---

# Report Maker

Turn raw data, summaries, or analysis into polished Markdown/HTML reports.

## Quick start

```bash
python {baseDir}/scripts/report_maker.py --input summaries.json --template default --format markdown --output report.md
python {baseDir}/scripts/report_maker.py --input data.csv --template table --format html --output report.html
python {baseDir}/scripts/report_maker.py --stdin --template briefing --format markdown > daily_brief.md
```

## Common tasks

- Daily digest: `--input news_summary.json --template default --format markdown`
- CSV table report: `--input data.csv --template table --format html`
- Multi-source merge: `--inputs part1.md,part2.md,part3.json --template default --format markdown`
- Briefing: `--input items.json --template briefing --format html --output brief.html`
- Timeline: `--input events.json --template timeline --format markdown`
- PDF export: `--input data.json --format pdf --output report.pdf` (requires `pip install weasyprint`)

## Templates

| Template | Use case |
|----------|----------|
| `default` | Title, date, bullet summaries |
| `table`   | Sortable HTML table from CSV/JSON |
| `briefing`| Executive summary with highlights |
| `timeline`| Chronological events |
| `daily_digest` | Daily summary of multiple sources |
| `contract` | Contract analysis report (legal) |
| `watchlist` | Stock/crypto watchlist report |
| `incident_report` | Security incident report |
| `security_audit` | Security audit findings report |

## Output
- Markdown: clean `.md` with frontmatter.
- HTML: styled, responsive table layout.
- PDF: print-ready (if WeasyPrint installed).

## Fallback Commands

If a command fails (e.g. missing input file or invalid JSON), the agent will try these safer alternatives automatically:

| Original | Fallback | Why |
|---|---|---|
| `incident_report` | `default` | `default` template works with stdin or minimal data, no structured input required |

## Notes
- All templates rendered inline (no Jinja2 file required).
- `briefing` and `timeline` accept JSON arrays; `timeline` sorts by `date`/`timestamp`/`time`/`published` if present.
- HTML output escapes all CSV/data values (`html.escape`) — safe against injection.
- Hebrew RTL: HTML template auto-includes `dir="rtl"` when Hebrew chars (U+0590..U+08FF) detected.
