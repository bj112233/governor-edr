import json
from pathlib import Path

d = Path("skills/news-monitor/config")
total = 0
for f in sorted(d.glob("feeds_*.json")):
    if f.name == "feeds_breaking.json":
        continue
    feeds = json.loads(f.read_text(encoding="utf-8")).get("feeds", [])
    name = f.stem.replace("feeds_", "")
    print(f"  {name}: {len(feeds)} feeds")
    total += len(feeds)
print(f"\nTotal: {total} feeds across {len(list(d.glob('feeds_*.json')))-1} profiles")
