"""
Dev helper: credit a brand's wallet directly in the live (FastAPI) database.

This talks to the SAME MongoDB the running server.py uses (MONGO_URL / DB_NAME
from Backend/.env), and updates the user's `balance` field — the value the
chat gate checks (MIN_BRAND_CHAT_BALANCE = 2500).

Usage (run from the Backend/ folder):
    python scripts/add_wallet.py <email> [amount]         # add amount (default 5000)
    python scripts/add_wallet.py <email> <amount> set     # SET balance to amount
    python scripts/add_wallet.py --list                   # list business users + balances

Examples:
    python scripts/add_wallet.py brand@test.com           # +5000
    python scripts/add_wallet.py brand@test.com 25000     # +25000
    python scripts/add_wallet.py brand@test.com 25000 set # set to exactly 25000
"""
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from pymongo import MongoClient

ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")

MIN_CHAT_BALANCE = 2500


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(1)

    client = MongoClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]

    if args[0] == "--list":
        users = db.users.find({"role": "business"}, {"_id": 0, "email": 1, "balance": 1, "nickname": 1})
        print("Business users:")
        for u in users:
            bal = float(u.get("balance") or 0)
            unlocked = "unlocked" if bal >= MIN_CHAT_BALANCE else "LOCKED"
            print(f"  {u.get('email'):35} INR {bal:>12,.0f}  ({unlocked})")
        return

    email = args[0]
    amount = float(args[1]) if len(args) > 1 else 5000.0
    set_mode = len(args) > 2 and args[2].lower() == "set"

    user = db.users.find_one({"email": {"$regex": f"^{email}$", "$options": "i"}})
    if not user:
        print(f'No user found with email "{email}". Sign up first, then re-run.')
        print("Tip: python scripts/add_wallet.py --list")
        sys.exit(1)

    before = float(user.get("balance") or 0)
    new_balance = amount if set_mode else before + amount
    db.users.update_one({"id": user["id"]}, {"$set": {"balance": new_balance}})

    print(f"OK  {user.get('email')} ({user.get('role')})")
    print(f"    balance: INR {before:,.0f} -> INR {new_balance:,.0f}")
    print(f"    chat unlocked: {'YES (>= INR 2,500)' if new_balance >= MIN_CHAT_BALANCE else 'no'}")


if __name__ == "__main__":
    main()
