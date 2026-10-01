"""
One-off cleanup: find (and optionally delete) stray notification rows with
garbled titles like "cdsnig" sitting in in_app_notifications from a one-off
manual broadcast. Run with --delete to remove the matches; without it, this
only lists what it found.
"""
import asyncio
import re
import sys
from motor.motor_asyncio import AsyncIOMotorClient

# A short run of consonants/letters with no vowels/spaces isn't a real title.
GARBLED_RE = re.compile(r'^[a-z]{4,10}$')

async def find_garbled_notifications(delete: bool):
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['test_database']

    notifications = await db.in_app_notifications.find({}, {"_id": 0}).to_list(None)
    suspects = [n for n in notifications if GARBLED_RE.match(str(n.get('title') or '').strip())]

    print(f"Found {len(suspects)} suspicious notification(s):\n")
    for n in suspects:
        print(f"id={n.get('id')} user_id={n.get('user_id')} title={n.get('title')!r} "
              f"source={n.get('source')} created_at={n.get('created_at')}")

    if delete and suspects:
        ids = [n['id'] for n in suspects if n.get('id')]
        result = await db.in_app_notifications.delete_many({"id": {"$in": ids}})
        print(f"\nDeleted {result.deleted_count} notification(s).")

    client.close()

asyncio.run(find_garbled_notifications(delete='--delete' in sys.argv))
