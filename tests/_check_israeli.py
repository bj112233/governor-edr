import feedparser
import requests

feeds = [
    ("Maariv (news_feeds id=10)", "https://www.maariv.co.il/rss/rss.aspx?id=10"),
    ("Maariv RssFeedsTitle", "https://www.maariv.co.il/Rss/RssFeedsTitle"),
    ("JPost headlines", "https://www.jpost.com/rss/rssfeedsheadlines.aspx"),
    ("JPost defense", "https://www.jpost.com/rss/rssfeedsdefense.aspx"),
    ("Kan news", "https://www.kan.org.il/rss/news.aspx"),
    ("Israel Hayom", "https://www.israelhayom.co.il/rss.xml"),
    ("N12 news", "https://rcs.mako.co.il/rss/news-israel.xml"),
    ("Walla news", "https://rss.walla.co.il/feed/1"),
    ("Ynet מבזקים", "https://www.ynet.co.il/Integration/StoryRss1854.xml"),
    ("Ynet ראשי", "https://www.ynet.co.il/Integration/StoryRss2.xml"),
    ("Times of Israel", "https://www.timesofisrael.com/feed/"),
    (
        "Globes רכב",
        "https://www.globes.co.il/webservice/rss/rssfeeder.asmx/FeederNode?iID=1944",
    ),
    (
        'Globes נדל"ן',
        "https://www.globes.co.il/webservice/rss/rssfeeder.asmx/FeederNode?iID=2107",
    ),
    ("Calcalist Tech", "https://www.calcalist.co.il/GeneralRSS/0,16335,L-3704,00.xml"),
    ("Calcalist רכב", "https://www.calcalist.co.il/GeneralRSS/0,16335,L-3719,00.xml"),
    (
        "Calcalist בריאות",
        "https://www.calcalist.co.il/GeneralRSS/0,16335,L-3717,00.xml",
    ),
    ("Walla רכב", "https://rss.walla.co.il/feed/257"),
    ("Walla בריאות", "https://rss.walla.co.il/feed/251"),
    ("Walla ביטחון", "https://rss.walla.co.il/feed/2689"),
    ("Walla פוליטי", "https://rss.walla.co.il/feed/2686"),
]

out_lines = []
for name, url in feeds:
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200:
            out_lines.append(f"FAIL | {name:<35} | HTTP {r.status_code}")
            continue
        d = feedparser.parse(r.content)
        n = len(d.entries)
        if n == 0:
            out_lines.append(f"FAIL | {name:<35} | 0 entries")
        else:
            out_lines.append(
                f"OK   | {name:<35} | {n:>3} entries | {d.entries[0].get('title', '')[:50]}"
            )
    except Exception as e:
        out_lines.append(f"FAIL | {name:<35} | {type(e).__name__}: {e}")

with open("tools/_check_israeli_out.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(out_lines))
print("Done. Output written to tools/_check_israeli_out.txt")
