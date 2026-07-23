"""Bulk validate RSS feed URLs for all news topics. Print only working ones."""
import sys
import concurrent.futures as cf
import requests
import feedparser

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CANDIDATES = {
    "N1_news_il": [
        ("Ynet ראשי", "https://www.ynet.co.il/Integration/StoryRss2.xml"),
        ("Ynet מבזקים", "https://www.ynet.co.il/Integration/StoryRss1854.xml"),
        ("Walla! חדשות", "https://rss.walla.co.il/feed/1"),
        ("Maariv ראשי", "https://www.maariv.co.il/Rss/RssFeedsTitle"),
        ("N12 חדשות", "https://rcs.mako.co.il/rss/news-israel.xml"),
        ("Kan חדשות", "https://www.kan.org.il/rss/news.aspx"),
        ("Israel Hayom", "https://www.israelhayom.co.il/rss.xml"),
    ],
    "N2_cyber": [
        ("Bleeping Computer", "https://www.bleepingcomputer.com/feed/"),
        ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
        ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
        ("Dark Reading", "https://www.darkreading.com/rss.xml"),
        ("Schneier on Security", "https://www.schneier.com/feed/atom/"),
        ("SANS ISC", "https://isc.sans.edu/rssfeed.xml"),
        ("Ynet טכנולוגיה", "https://www.ynet.co.il/Integration/StoryRss544.xml"),
    ],
    "N3_tech_ai": [
        ("TechCrunch", "https://techcrunch.com/feed/"),
        ("Hacker News", "https://hnrss.org/frontpage"),
        ("The Verge", "https://www.theverge.com/rss/index.xml"),
        ("Ars Technica", "https://feeds.arstechnica.com/arstechnica/index"),
        ("Wired", "https://www.wired.com/feed/rss"),
        ("MIT Technology Review", "https://www.technologyreview.com/feed/"),
        ("Calcalist Tech", "https://www.calcalist.co.il/GeneralRSS/0,16335,L-3704,00.xml"),
    ],
    "N4_world": [
        ("BBC World", "https://feeds.bbci.co.uk/news/world/rss.xml"),
        ("Reuters Top News", "https://www.reutersagency.com/feed/?best-topics=top-news"),
        ("Al Jazeera", "https://www.aljazeera.com/xml/rss/all.xml"),
        ("AP Top News", "https://feeds.apnews.com/apf-topnews"),
        ("CNN World", "http://rss.cnn.com/rss/edition_world.rss"),
        ("The Guardian World", "https://www.theguardian.com/world/rss"),
    ],
    "N5_security_mil": [
        ("Ynet ביטחון", "https://www.ynet.co.il/Integration/StoryRss3.xml"),
        ("Walla! ביטחון", "https://rss.walla.co.il/feed/2689"),
        ("Times of Israel", "https://www.timesofisrael.com/feed/"),
        ("Defense News", "https://www.defensenews.com/arc/outboundfeeds/rss/?outputType=xml"),
        ("Jerusalem Post Defense", "https://www.jpost.com/rss/rssfeedsdefense.aspx"),
    ],
    "N6_politics_il": [
        ("Ynet פוליטיקה", "https://www.ynet.co.il/Integration/StoryRss194.xml"),
        ("Walla! פוליטי", "https://rss.walla.co.il/feed/2686"),
        ("Times of Israel Politics", "https://www.timesofisrael.com/topic/politics/feed/"),
        ("N12 פוליטי", "https://rcs.mako.co.il/rss/news-politics.xml"),
    ],
    "N7_sports": [
        ("Ynet ספורט", "https://www.ynet.co.il/Integration/StoryRss3.xml"),
        ("ONE", "https://www.one.co.il/Coop/RSSGenerator/RssFeed.aspx?type=GeneralRss"),
        ("Sport5", "https://www.sport5.co.il/rss.xml"),
        ("ESPN", "https://www.espn.com/espn/rss/news"),
        ("BBC Sport", "https://feeds.bbci.co.uk/sport/rss.xml"),
    ],
    "N8_health": [
        ("Ynet בריאות", "https://www.ynet.co.il/Integration/StoryRss1208.xml"),
        ("Walla! בריאות", "https://rss.walla.co.il/feed/251"),
        ("Calcalist בריאות", "https://www.calcalist.co.il/GeneralRSS/0,16335,L-3717,00.xml"),
        ("WHO", "https://www.who.int/rss-feeds/news-english.xml"),
        ("WebMD", "https://rssfeeds.webmd.com/rss/rss.aspx?RSSSource=RSS_PUBLIC"),
    ],
    "N9_auto": [
        ("Ynet רכב", "https://www.ynet.co.il/Integration/StoryRss550.xml"),
        ("Walla! רכב", "https://rss.walla.co.il/feed/257"),
        ("Auto Israel", "https://www.auto.co.il/feed/"),
        ("Calcalist רכב", "https://www.calcalist.co.il/GeneralRSS/0,16335,L-3719,00.xml"),
        ("Globes רכב", "https://www.globes.co.il/webservice/rss/rssfeeder.asmx/FeederNode?iID=1944"),
    ],
    "N10_realestate": [
        ("Globes נדל\"ן", "https://www.globes.co.il/webservice/rss/rssfeeder.asmx/FeederNode?iID=2107"),
        ("Calcalist נדל\"ן", "https://www.calcalist.co.il/GeneralRSS/0,16335,L-3691,00.xml"),
        ("TheMarker נדל\"ן", "https://www.themarker.com/cmlink/1.144"),
        ("Ynet נדל\"ן", "https://www.ynet.co.il/Integration/StoryRss61.xml"),
    ],
}


def check(name: str, url: str) -> tuple:
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200:
            return (name, url, 0, f"HTTP {r.status_code}")
        d = feedparser.parse(r.content)
        n = len(d.entries)
        if n == 0:
            return (name, url, 0, "0 entries")
        return (name, url, n, d.entries[0].get("title", "")[:50])
    except Exception as e:
        return (name, url, 0, f"{type(e).__name__}")


def main():
    for topic, feeds in CANDIDATES.items():
        print(f"\n=== {topic} ===")
        with cf.ThreadPoolExecutor(max_workers=8) as ex:
            results = list(ex.map(lambda f: check(*f), feeds))
        for name, url, n, msg in results:
            icon = "OK  " if n > 0 else "FAIL"
            print(f"  {icon} | {n:>3} | {name:<28} | {msg}")


if __name__ == "__main__":
    main()
