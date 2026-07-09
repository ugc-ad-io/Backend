"""READ-ONLY: inspect current DB state before any dummy-data cleanup. Changes nothing."""
import asyncio, os, sys
from pathlib import Path
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

try: sys.stdout.reconfigure(encoding="utf-8")
except Exception: pass

ROOT = Path(__file__).parent
load_dotenv(ROOT / ".env")
MONGO = os.environ.get("MONGO_URL") or os.environ.get("MONGODB_URI") or "mongodb://localhost:27017"
DB = os.environ.get("DB_NAME") or "test_database"
KEEP = ["test@gmail.com", "testbrand@test.com"]


async def main():
    db = AsyncIOMotorClient(MONGO)[DB]
    print(f"DB: {DB}\n")

    for email in KEEP:
        u = await db.users.find_one({"email": email}, {"_id": 0, "id": 1, "email": 1, "role": 1, "nickname": 1})
        print(f"KEEP account {email}: {'FOUND — ' + str(u) if u else 'NOT FOUND'}")

    total_users = await db.users.count_documents({})
    creators = await db.users.count_documents({"role": "creator"})
    brands = await db.users.count_documents({"role": "business"})
    # Heuristic markers the seed injected:
    seeded_photo = await db.users.count_documents({"profile_photo": {"$regex": "pravatar", "$options": "i"}})
    seeded_portfolio = await db.users.count_documents({"portfolio.0": {"$exists": True}})
    print(f"\nUsers: {total_users} total | {creators} creators | {brands} brands")
    print(f"Users with pravatar photo (seed marker): {seeded_photo}")
    print(f"Users with a portfolio array: {seeded_portfolio}")

    print("\nseed_dummy-tagged docs:")
    for coll in ["campaigns", "escrow", "shipments", "work_submissions", "reviews",
                 "in_app_notifications", "wallet_ledger"]:
        n = await db[coll].count_documents({"seed_dummy": True})
        print(f"  {coll}: {n}")

    print("\nAll user emails (role):")
    async for u in db.users.find({}, {"_id": 0, "email": 1, "role": 1}).limit(60):
        print(f"  {u.get('email')}  ({u.get('role')})")


asyncio.run(main())
