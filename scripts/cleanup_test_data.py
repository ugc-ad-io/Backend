"""
Remove QA/test data created by automated test runs.

Test accounts were all created with @example.com emails. This finds those users
and removes them plus everything they generated (campaigns, deals, escrow,
shipments, work, messages, notifications, disputes, receipts).

Usage:
    python scripts/cleanup_test_data.py           # DRY RUN — shows what it would delete
    python scripts/cleanup_test_data.py --delete  # actually delete
"""
import os
import sys
from pathlib import Path
from pymongo import MongoClient
from dotenv import load_dotenv

sys.stdout.reconfigure(encoding="utf-8")
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

DO_DELETE = "--delete" in sys.argv
TEST_EMAIL = {"$regex": r"@example\.com$", "$options": "i"}

db = MongoClient(os.environ["MONGO_URL"])[os.environ.get("DB_NAME", "test_database")]

users = list(db.users.find({"email": TEST_EMAIL}, {"_id": 0, "id": 1, "email": 1, "role": 1}))
uids = [u["id"] for u in users if u.get("id")]

print(f"MODE: {'DELETE' if DO_DELETE else 'DRY RUN (nothing will be removed)'}\n")
print(f"Test users found (@example.com): {len(users)}")
for u in users[:15]:
    print(f"   - {u.get('email')}  [{u.get('role')}]")
if len(users) > 15:
    print(f"   … and {len(users) - 15} more")

if not uids:
    print("\nNothing to clean.")
    raise SystemExit

# Campaigns owned by / assigned to test users
camps = list(db.campaigns.find(
    {"$or": [{"business_id": {"$in": uids}}, {"selected_creator": {"$in": uids}}]},
    {"_id": 0, "id": 1, "title": 1},
))
cids = [c["id"] for c in camps if c.get("id")]
print(f"\nCampaigns from test users: {len(cids)}")

# Everything hanging off those users/campaigns
plan = [
    ("campaigns",                {"id": {"$in": cids}}),
    ("escrow",                   {"$or": [{"campaign_id": {"$in": cids}}, {"business_id": {"$in": uids}}, {"creator_id": {"$in": uids}}]}),
    ("shipments",                {"campaign_id": {"$in": cids}}),
    ("work_submissions",         {"$or": [{"campaign_id": {"$in": cids}}, {"creator_id": {"$in": uids}}]}),
    ("deal_messages",            {"campaign_id": {"$in": cids}}),
    ("deal_activity",            {"campaign_id": {"$in": cids}}),
    ("deal_receipts",            {"campaign_id": {"$in": cids}}),
    ("deal_action_cards",        {"campaign_id": {"$in": cids}}),
    ("deal_content_submissions", {"campaign_id": {"$in": cids}}),
    ("deals",                    {"$or": [{"campaign_id": {"$in": cids}}, {"creator_id": {"$in": uids}}, {"business_id": {"$in": uids}}]}),
    ("disputes",                 {"$or": [{"campaign_id": {"$in": cids}}, {"raised_by": {"$in": uids}}]}),
    ("messages",                 {"$or": [{"sender_id": {"$in": uids}}, {"recipient_id": {"$in": uids}}]}),
    ("chat_action_cards",        {"$or": [{"sender_id": {"$in": uids}}, {"recipient_id": {"$in": uids}}]}),
    ("threads",                  {"participants": {"$in": uids}}),
    ("in_app_notifications",     {"user_id": {"$in": uids}}),
    ("notifications",            {"user_id": {"$in": uids}}),
    ("violations",               {"user_id": {"$in": uids}}),
    ("chat_strikes",             {"user_id": {"$in": uids}}),
    ("withdrawals",              {"user_id": {"$in": uids}}),
    ("payout_receipts",          {"$or": [{"user_id": {"$in": uids}}, {"campaign_id": {"$in": cids}}]}),
    ("wallet_ledger",            {"user_id": {"$in": uids}}),
    ("payment_transactions",     {"user_id": {"$in": uids}}),
    ("users",                    {"id": {"$in": uids}}),
]

print("\nWould remove:" if not DO_DELETE else "\nRemoving:")
total = 0
for coll, query in plan:
    if coll not in db.list_collection_names():
        continue
    n = db[coll].count_documents(query)
    if n == 0:
        continue
    total += n
    if DO_DELETE:
        db[coll].delete_many(query)
    print(f"   {coll:<26} {n}")

print(f"\n{'DELETED' if DO_DELETE else 'WOULD DELETE'} {total} documents "
      f"across {len(users)} test users.")
if not DO_DELETE:
    print("\nRe-run with --delete to apply.")
