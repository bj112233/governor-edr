"""Quick integration test for ScheduledNewsService with skill profiles."""
import sys
sys.path.insert(0, ".")
import asyncio
from services.scheduled_news import get_news_service


async def test():
    svc = get_news_service()
    await svc.load_config()
    print(f"Profiles loaded: {len(svc.profiles)}")
    print(f"Delivery config: {svc.delivery_config}")
    print()

    # Fetch all feeds
    items = await svc.fetch_all_feeds()
    total = sum(len(v) for v in items.values())
    print(f"Fetched {total} items from {len(items)} categories:")
    for k, v in items.items():
        print(f"  {k}: {len(v)} items")

    # Format digest
    msg = svc.format_html_digest(items)
    print(f"\nDigest length: {len(msg)} chars")
    print("--- PREVIEW (first 1000 chars) ---")
    print(msg[:1000])


if __name__ == "__main__":
    asyncio.run(test())
