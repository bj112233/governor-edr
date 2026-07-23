import requests, feedparser, json

url = 'https://rcs.mako.co.il/rss/news-israel.xml'
r = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
print(f"Status: {r.status_code}")
print(f"Content-Length: {len(r.content)} bytes")
print(f"Content-Type: {r.headers.get('Content-Type', 'N/A')}")
print()

if r.status_code == 200:
    d = feedparser.parse(r.content)
    print(f"Entries count: {len(d.entries)}")
    print(f"Feed title: {d.feed.get('title', 'N/A')}")
    print()
    for i, entry in enumerate(d.entries[:5]):
        print(f"--- Entry {i+1} ---")
        print(f"Title: {entry.get('title', 'N/A')}")
        print(f"Link: {entry.get('link', 'N/A')}")
        print(f"Published: {entry.get('published', 'N/A')}")
        print()
else:
    print(f"Failed: HTTP {r.status_code}")
    print(r.text[:500])
