import requests, feedparser

feeds = [
    ('Haaretz', 'https://www.haaretz.co.il/services/rss/allnews.xml'),
    ('Haaretz eng', 'https://www.haaretz.com/rss.xml'),
    ('Geektime', 'https://www.geektime.co.il/feed/'),
    ('Mako', 'https://rcs.mako.co.il/rss/news-israel.xml'),
    ('Channel13', 'https://13tv.co.il/rss/'),
    ('Israel National News', 'https://www.israelnationalnews.com/rss/'),
    ('Srugim', 'https://www.srugim.co.il/feed'),
    ('Walla Finance', 'https://rss.walla.co.il/feed/22'),
    ('Globes Tech', 'https://www.globes.co.il/webservice/rss/rssfeeder.asmx/FeederNode?iID=1905'),
    ('TheMarker', 'https://www.themarker.com/cmlink/1.145'),
    ('Calcalist', 'https://www.calcalist.co.il/GeneralRSS/0,16335,L-3679,00.xml'),
    ('INN', 'https://www.israelnationalnews.com/rss/'),
]

out = []
for name, url in feeds:
    try:
        r = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code != 200:
            out.append(f'FAIL | {name:<25} | HTTP {r.status_code}')
            continue
        d = feedparser.parse(r.content)
        n = len(d.entries)
        if n == 0:
            out.append(f'FAIL | {name:<25} | 0 entries')
        else:
            out.append(f'OK   | {name:<25} | {n:>3} entries | {d.entries[0].get("title", "")[:50]}')
    except Exception as e:
        out.append(f'FAIL | {name:<25} | {type(e).__name__}: {e}')

with open('tools/_check_extra_israeli_out.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(out))
print('Done')
