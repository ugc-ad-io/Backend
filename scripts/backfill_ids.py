"""
One-time migration: backfill the string `id` field on any document that lacks it.

Root cause of recurring `KeyError: 'id'` 500s (Google auth, /admin/deals,
/admin/shipping/requests, ...): legacy records (created by the Node backend or
older code) have a Mongo ObjectId `_id` but no string `id`, while the Python code
keys everything off `id`. This sets `id = str(_id)` wherever `id` is missing.

Safe + idempotent: only touches documents missing `id`; never overwrites an
existing `id`; adds a metadata field only. Skips Mongo system collections.

Run:  python scripts/backfill_ids.py
"""
import os
import sys
from pathlib import Path
from pymongo import MongoClient
from dotenv import load_dotenv

sys.stdout.reconfigure(encoding="utf-8")
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ.get("DB_NAME", "test_database")

client = MongoClient(MONGO_URL)
db = client[DB_NAME]

print(f"DB: {DB_NAME}\n")
total = 0
for name in sorted(db.list_collection_names()):
    if name.startswith("system."):
        continue
    col = db[name]
    missing = col.count_documents({"id": {"$exists": False}})
    if missing == 0:
        print(f"  {name:<28} ok (0 missing)")
        continue
    fixed = 0
    for doc in col.find({"id": {"$exists": False}}, {"_id": 1}):
        col.update_one({"_id": doc["_id"]}, {"$set": {"id": str(doc["_id"])}})
        fixed += 1
    total += fixed
    print(f"  {name:<28} backfilled {fixed} / {missing}")

print(f"\nTOTAL documents backfilled: {total}")
client.close()
