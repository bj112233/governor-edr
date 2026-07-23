import feedparser, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

feeds = [
    ('Ynet מבזקים', 'https://www.ynet.co.il/Integration/StoryRss1854.xml'),
    ('Walla מבזקים', 'https://rss.walla.co.il/feed/3?type=main'),
    ('Maariv מבזקים', 'https://www.maariv.co.il/Rss/RssChadashot'),
    ('Israel National News', 'https://www.israelnationalnews.com/Rss.aspx'),
    ('Jerusalem Post', 'https://www.jpost.com/Rss/RssFeedsFrontPage.aspx'),
    ('N12 חדשות', 'https://rcs.mako.co.il/rss/news-israel.xml'),
    ('Israel Hayom', 'https://www.israelhayom.co.il/rss.xml'),
    ('Haaretz חדשות', 'https://www.haaretz.co.il/srv/rss---feedly'),
]

for name, url in feeds:
    try:
        d = feedparser.parse(url)
        n = len(d.entries)
        status = d.get('status', '?')
        bozo = d.bozo if hasattr(d, 'bozo') else '?'
        err = str(d.get('bozo_exception', ''))[:80] if d.bozo else ''
        if n > 0:
            title = d.entries[0].get('title', '')[:60]
            print('OK  %s: %d items (status=%s)' % (name, n, status))
            print('    Latest: "%s"' % title)
        else:
            print('FAIL %s: 0 items (status=%s, bozo=%s) %s' % (name, status, bozo, err))
    except Exception as e:
        print('ERR  %s: %s: %s' % (name, type(e).__name__, e))
    print()
