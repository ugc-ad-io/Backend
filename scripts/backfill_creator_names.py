"""
One-time backfill: give creators a real NAME instead of an auto-generated handle.

Early accounts got a nickname like "@FierceDragon774" / "LuckyTiger764" (the old
adjective+animal+number generator) and never a real name, so brand cards and the
dashboard showed the handle. This assigns a realistic placeholder first+last name
to every creator whose nickname still looks like an auto handle AND who has no
real name typed on their profile.

Safe + idempotent:
  - Only touches creators whose nickname matches the auto-handle pattern.
  - Skips anyone who already has a real profile name (profile.fullName / full_name).
  - Sets nickname + full_name to the new name; leaves username/id/public_creator_id
    untouched (internal identifiers).

Run:  python scripts/backfill_creator_names.py
Dry run (no writes):  python scripts/backfill_creator_names.py --dry
"""
import os
import re
import sys
import random
from pathlib import Path
from pymongo import MongoClient
from dotenv import load_dotenv

sys.stdout.reconfigure(encoding="utf-8")
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

DRY = "--dry" in sys.argv
MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ.get("DB_NAME", "test_database")
client = MongoClient(MONGO_URL)
db = client[DB_NAME]

# The two generators that ever produced handles.
ADJ = ['Lucky', 'Happy', 'Bright', 'Swift', 'Bold', 'Cool', 'Smart', 'Quick', 'Brave', 'Wise',
       'Noble', 'Fierce', 'Mighty', 'Grand', 'Royal', 'Elite', 'Prime', 'Alpha', 'Stellar', 'Epic']
NOUN = ['Tiger', 'Eagle', 'Lion', 'Wolf', 'Bear', 'Fox', 'Hawk', 'Panther', 'Falcon', 'Dragon',
        'Phoenix', 'Raven', 'Cobra', 'Shark', 'Viper', 'Leopard', 'Cheetah', 'Lynx', 'Puma', 'Jaguar']
HANDLE_RE = re.compile(r"^@?(?:" + "|".join(ADJ) + r")(?:" + "|".join(NOUN) + r")\d{2,4}$", re.I)

FIRST = ['Aarav', 'Vivaan', 'Aditya', 'Arjun', 'Reyansh', 'Rohan', 'Kabir', 'Ishaan', 'Dev', 'Krishna',
         'Ananya', 'Diya', 'Aadhya', 'Saanvi', 'Priya', 'Ira', 'Myra', 'Riya', 'Kiara', 'Meera',
         'Neha', 'Kunal', 'Nikhil', 'Sara', 'Aisha', 'Tara', 'Karan', 'Sana', 'Yash', 'Zoya']
LAST = ['Sharma', 'Verma', 'Gupta', 'Patel', 'Reddy', 'Nair', 'Iyer', 'Rao', 'Mehta', 'Jain',
        'Khan', 'Singh', 'Das', 'Bose', 'Kapoor', 'Malhotra', 'Chopra', 'Menon', 'Shah', 'Roy']


def has_real_name(u: dict) -> bool:
    p = u.get("profile") or {}
    for v in (p.get("fullName"), p.get("full_name"), u.get("full_name")):
        if isinstance(v, str) and v.strip():
            return True
    return False


def looks_like_handle(nick) -> bool:
    return isinstance(nick, str) and bool(HANDLE_RE.match(nick.strip()))


print(f"DB: {DB_NAME}  {'(DRY RUN)' if DRY else ''}\n")
used = set(FIRST)  # keep assigned names varied
changed = skipped = 0
for u in db.users.find({"role": "creator"}, {"id": 1, "nickname": 1, "full_name": 1, "profile": 1, "email": 1}):
    nick = u.get("nickname")
    if has_real_name(u) or not looks_like_handle(nick):
        skipped += 1
        continue
    name = f"{random.choice(FIRST)} {random.choice(LAST)}"
    print(f"  {str(u.get('email') or u.get('id'))[:34]:<34}  {nick!r:>22}  ->  {name}")
    if not DRY:
        db.users.update_one({"id": u["id"]}, {"$set": {"nickname": name, "full_name": name}})
    changed += 1

print(f"\nDone. {changed} creators renamed, {skipped} skipped (already had a real name / not an auto handle).")
if DRY:
    print("This was a DRY RUN — no writes. Re-run without --dry to apply.")
