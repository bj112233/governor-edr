---
name: file-analyst
description: "Analyze local files via scripts/file_analyst.py. Actions — summarize/contract/datasheet/extract/stats for PDF/DOCX/CSV/XLSX/TXT/JSON/MD; ocr/ocr_translate for images (jpg/png/webp/bmp/tiff) AND scanned PDFs (Tesseract 5.x); pdf_to_md for PDF→Markdown conversion (MarkItDown). Examples — 'summarize --path report.pdf', 'contract --path lease.pdf', 'datasheet --path tpa3255.pdf', 'ocr --path scan.jpg', 'ocr_translate --path image.png --to he', 'pdf_to_md --path report.pdf'. Trigger when asked to read, summarize, extract data from files, analyze a lease/rental contract (use 'contract'), analyze a technical datasheet / IC spec sheet (use 'datasheet'), read text from an image (use 'ocr'), or translate text inside an image (use 'ocr_translate'). CRITICAL: NEVER pass a file path that was not explicitly confirmed by a prior tool output (look for 'saved to' in tool output). Invented file paths will fail. Only use paths that were created by a tool or provided by the user."
metadata: {"clawdbot":{"emoji":"📄","commands":["summarize","extract","convert","stats","check","extract_tables","chart","contract","datasheet","analyze","ocr","ocr_translate","ocr_pdf","redact","batch","pdf_to_md"],"arg_template":"scripts/file_analyst.py {command} {args}","timeout":90,"requires":{"bins":["python"],"python_libs":["PyPDF2","pdfplumber","pdfminer.six","python-docx","openpyxl","pandas","pytesseract","Pillow","deep-translator","pymupdf"]},"install":[{"id":"pip-files","kind":"pip","packages":["PyPDF2","pdfplumber","pdfminer.six","python-docx","openpyxl","pandas","pytesseract","Pillow","deep-translator","pymupdf"],"label":"Install file analysis dependencies (baseline)"},{"id":"pip-ml-extras","kind":"pip","optional":true,"packages":["markitdown"],"label":"Optional ML extras (MarkItDown for PDF→Markdown)"}],"commands_schema":{"summarize":{"properties":{"path":{"type":"string","description":"Path to the file to analyze"},"output":{"type":"string","description":"Output file path (optional)"}},"required":["path"]},"extract":{"properties":{"path":{"type":"string","description":"Path to the file to analyze"},"output":{"type":"string","description":"Output file path (optional)"}},"required":["path"]},"convert":{"properties":{"path":{"type":"string","description":"Path to the file to analyze"},"output":{"type":"string","description":"Output file path (optional)"}},"required":["path"]},"stats":{"properties":{"path":{"type":"string","description":"Path to the file to analyze"},"output":{"type":"string","description":"Output file path (optional)"}},"required":["path"]},"check":{"properties":{"path":{"type":"string","description":"Path to the file to analyze"},"output":{"type":"string","description":"Output file path (optional)"}},"required":["path"]},"extract_tables":{"properties":{"path":{"type":"string","description":"Path to the file to analyze"},"output":{"type":"string","description":"Output file path (optional)"}},"required":["path"]},"chart":{"properties":{"path":{"type":"string","description":"Path to the file to analyze"},"output":{"type":"string","description":"Output file path (optional)"}},"required":["path"]},"contract":{"properties":{"path":{"type":"string","description":"Path to the file to analyze"},"output":{"type":"string","description":"Output file path (optional)"}},"required":["path"]},"datasheet":{"properties":{"path":{"type":"string","description":"Path to the file to analyze"},"output":{"type":"string","description":"Output file path (optional)"}},"required":["path"]},"analyze":{"properties":{"path":{"type":"string","description":"Path to the file to analyze"},"output":{"type":"string","description":"Output file path (optional)"}},"required":["path"]},"ocr":{"properties":{"path":{"type":"string","description":"Path to the file to analyze"},"output":{"type":"string","description":"Output file path (optional)"}},"required":["path"]},"ocr_translate":{"properties":{"path":{"type":"string","description":"Path to the file to analyze"},"output":{"type":"string","description":"Output file path (optional)"}},"required":["path"]},"ocr_pdf":{"properties":{"path":{"type":"string","description":"Path to the file to analyze"},"output":{"type":"string","description":"Output file path (optional)"}},"required":["path"]},"redact":{"properties":{"path":{"type":"string","description":"Path to the file to analyze"},"output":{"type":"string","description":"Output file path (optional)"}},"required":["path"]},"pdf_to_md":{"properties":{"path":{"type":"string","description":"Path to the file to analyze"},"output":{"type":"string","description":"Output file path (optional)"}},"required":["path"]},"batch":{"properties":{"dir":{"type":"string","description":"Directory to batch process"},"pattern":{"type":"string","default":"*"},"batch_action":{"type":"string","default":"summarize"}},"required":["dir"]}}}}
---

# File Analyst

Read and summarize documents, spreadsheets, and text files locally.

## Quick start

```bash
# 📄 טקסט ומסמכים
python {baseDir}/scripts/file_analyst.py summarize --path ~/Documents/report.pdf
python {baseDir}/scripts/file_analyst.py summarize --path ~/Documents/report.pdf --pages 5
python {baseDir}/scripts/file_analyst.py extract --path ~/Data/sales.csv --query "top 5 products by revenue"
python {baseDir}/scripts/file_analyst.py convert --path ~/Notes/meeting.docx --format markdown
python {baseDir}/scripts/file_analyst.py stats --path ~/Logs/access.json
python {baseDir}/scripts/file_analyst.py check --path ~/Documents/report.pdf  # בדיקת שלמות קובץ

# 📊 נתונים וטבלאות
python {baseDir}/scripts/file_analyst.py extract_tables --path ~/Data/financial.pdf --output tables.csv
python {baseDir}/scripts/file_analyst.py chart --path ~/Data/sales.csv --x-col date --y-cols revenue,profit --kind line

# 📋 חוזים ומסמכים משפטיים
python {baseDir}/scripts/file_analyst.py contract --path ~/Contracts/lease.pdf        # חוזה שכירות
python {baseDir}/scripts/file_analyst.py contract --path ~/Contracts/job_offer.pdf   # חוזה עבודה
python {baseDir}/scripts/file_analyst.py contract --path ~/Contracts/car_sale.pdf    # חוזה רכב
python {baseDir}/scripts/file_analyst.py contract --path ~/Contracts/nda.pdf         # הסכם סודיות

# 🔧 ניתוח טכני (Datasheets)
python {baseDir}/scripts/file_analyst.py datasheet --path ~/Docs/tpa3255.pdf
python {baseDir}/scripts/file_analyst.py datasheet --path ~/Docs/amplifier.pdf

# 🔍 OCR - חילוץ טקסט מתמונות ו-PDF סרוקים
python {baseDir}/scripts/file_analyst.py ocr --path ~/Pictures/scan.jpg
python {baseDir}/scripts/file_analyst.py ocr --path ~/Pictures/scan.jpg --ocr-engine tesseract
python {baseDir}/scripts/file_analyst.py ocr --path ~/Documents/scanned.pdf
python {baseDir}/scripts/file_analyst.py ocr_pdf --path ~/Documents/scanned.pdf --output extracted.txt
python {baseDir}/scripts/file_analyst.py ocr_translate --path ~/Pictures/sign.png --to he
python {baseDir}/scripts/file_analyst.py ocr_translate --path ~/Pictures/menu.jpg --to en --output menu_en.txt

# 📝 PDF → Markdown (MarkItDown only; --md-engine deprecated)
python {baseDir}/scripts/file_analyst.py pdf_to_md --path ~/Documents/report.pdf

# 🛡️ Redaction — מחיקה פיזית של תוכן ב-PDF (PyMuPDF).
# --pattern הוא regex; כל התאמה מקבלת redact_annot + apply_redactions —
# הגליפים של הטקסט מושמדים פיזית מהמסמך. הפלט הוא קובץ PDF תקף (לא טקסט גולמי).
python {baseDir}/scripts/file_analyst.py redact --path ~/Contracts/contract.pdf --pattern "\d{3}-\d{2}-\d{4}" --output redacted.pdf

# 📁 עיבוד אצווה (Batch)
python {baseDir}/scripts/file_analyst.py batch --dir ~/Downloads --pattern "*.pdf" --batch-action summarize
python {baseDir}/scripts/file_analyst.py batch --dir ~/Documents/Contracts --pattern "*.pdf" --batch-action contract
```

## פעולות נתמכות (16 actions)

| פעולה | תיאור | קבצים נתמכים |
|-------|-------|--------------|
| `summarize` | סיכום תוכן מסמך | PDF, DOCX, TXT, MD |
| `extract` | CSV/XLSX/JSON: שאילתה עם `--query`. PDF/DOCX/TXT: קטע טקסט גולמי של 3000 תווים (`--query` מתעלם) | CSV, XLSX, JSON, PDF, DOCX, TXT |
| `extract_tables` | חילוץ טבלאות מ-PDF | PDF |
| `convert` | המרת פורמט | DOCX→MD, JSON→CSV |
| `stats` | סטטיסטיקות קובץ | CSV, XLSX, JSON |
| `chart` | יצירת גרף מנתונים | CSV, XLSX |
| `check` | בדיקת שלמות/תקינות קובץ | הכל |
| `contract` | ניתוח חוזה משפטי | PDF, DOCX |
| `analyze` | ניתוח מסמך כללי (28 סוגים) | PDF, DOCX, TXT |
| `datasheet` | ניתוח מפרט טכני/IC | PDF, DOCX |
| `ocr` | חילוץ טקסט מתמונה (Tesseract 5.x) | JPG, PNG, PDF סרוק |
| `ocr_pdf` | OCR ל-PDF שלם | PDF סרוק |
| `ocr_translate` | OCR + תרגום | JPG, PNG, PDF |
| `pdf_to_md` | PDF → Markdown (MarkItDown only) | PDF |
| `redact` | מחיקה פיזית של תוכן ב-PDF לפי regex (PyMuPDF) | PDF |
| `batch` | עיבוד אצווה של תיקייה | הכל |

## Common tasks

- PDF summary: `summarize --path <pdf> --pages 5`
- CSV insights: `extract --path <csv> --query "group by column X, sum Y"`
- DOCX to MD: `convert --path <docx> --format markdown`
- JSON stats: `stats --path <json>`
- Table extraction: `extract_tables --path <pdf> --output tables.csv`
- Data visualization: `chart --path <csv> --x-col date --y-cols sales,revenue --kind line`
- Contract analysis: `contract --path <pdf|docx>` — auto-detects contract type (8 types) with legal scoring (good/bad/neutral)
- General document analysis: `analyze --path <file>` — auto-detects any of 28 document types (contracts, insurance, financial, legal, medical, corporate, technical) and extracts structured fields
- Datasheet analysis: `datasheet --path <pdf|docx>` — extracts features, specs, pinout, applications for IC / amplifier datasheets
- OCR translation: `ocr_translate --path <image> --to he` — extracts and translates text from images
- Bulk folder: `batch --dir ~/Downloads --pattern "*.pdf" --batch-action summarize`

## Supported formats

| Ext | Actions |
|-----|---------|
| .pdf | summarize, extract text, count pages, contract analysis, datasheet analysis, OCR (for scanned PDFs), PDF→MD |
| .docx | summarize, convert to md/txt, extract headings, contract analysis, datasheet analysis |
| .csv, .xlsx | query, stats, top-N, convert to md |
| .json | stats, flatten, convert to csv |
| .txt, .md | summarize, word count, grep |

## Output
- Plain text or Markdown summaries.
- JSON for `--format json` (useful for downstream report tools).

## Query syntax (CSV/XLSX only)

The `--query` flag is honored **only** for CSV/XLSX (and JSON stats). For
`extract` on PDF/DOCX/TXT/MD the flag is silently ignored and the command
returns the first 3000 characters of the extracted text — there is no
QA / NLP layer over unstructured documents in this skill. For semantic
query over a PDF, summarize the document first then ask the LLM.

- `top N by COL [asc|desc]` — sort by column, take top N (default desc).
- `group by COL <sum|mean|count|min|max> COL2` — aggregate.
- Any [`pandas.DataFrame.query`](https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.query.html) expression as fallback.

Examples (CSV/XLSX):
```bash
python scripts/file_analyst.py extract --path sales.csv --query "top 5 by revenue"
python scripts/file_analyst.py extract --path sales.csv --query "group by region sum revenue"
python scripts/file_analyst.py extract --path sales.csv --query "price > 1000"
```

## Notes
- Large PDFs: use `--pages N` to limit memory. `summarize` action auto-detects sections for large documents.
- Datasheets: `datasheet` extracts Features, Description, Key Specs, Pinout, Absolute Maximum Ratings, Applications.
- DOCX→Markdown (`convert --format markdown`) preserves headings, lists, and tables.
- Encrypted PDFs return a clear error.
- Scanned PDFs: all PDF actions (`summarize`, `contract`, `datasheet`, `extract`) auto-detect scanned/image-only PDFs and automatically run OCR via Tesseract 5.x (CPU-only, `heb_best.traineddata` for Hebrew). EasyOCR was removed — abandoned upstream, no Hebrew model, and its PyTorch dependency competed with the LLM for the 6GB VRAM budget. `--ocr-engine` accepts `auto`/`tesseract` (both resolve to Tesseract).
- PDF→Markdown (`pdf_to_md`): uses MarkItDown (Microsoft standard). The `--md-engine` flag is **deprecated** — only `markitdown` is implemented; `auto` resolves to the same engine. No alternative backend (e.g. MinerU) is wired in.
- Hebrew text: PDFs use a heuristic RTL fix; pdfplumber is preferred over PyPDF2.
- Translation: `ocr_translate` uses opus-mt (offline, MIT, BLEU 40-54 on Hebrew) as primary for en↔he, falling back to deep-translator (Google) for other pairs. Models auto-download from HuggingFace on first use (~300MB each, cached locally).
