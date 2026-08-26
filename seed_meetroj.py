"""
seed_meetroj.py -- Dummy data for ONE creator account: meetroj441@gmail.com.

Scoped on purpose: unlike seed_dummy.py (which rewrites EVERY creator and brand
profile), this touches only the target creator and uses the owner's own brand
account (meetroj512@gmail.com / Levis) as the counterparty, so no real user's
profile, campaign or review is modified.

Fills: Active Work (Requests/Active/Completed/Cancelled), Browse Campaigns,
My Deals, Earnings, Reviews.

Every generated doc is tagged {"seed_meetroj": True}.
Safe to re-run -- tagged docs are deleted first.
Undo with:  python seed_meetroj.py --clean

Run:  python seed_meetroj.py
"""
import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

MONGO_URL = os.environ.get("MONGO_URL") or os.environ.get("MONGODB_URI")
DB_NAME = os.environ.get("DB_NAME") or "test_database"

CREATOR_EMAIL = "meetroj441@gmail.com"
BRAND_EMAIL = "meetroj512@gmail.com"   # owner's own brand account (Levis)
TAG = "seed_meetroj"

# Collections this script writes to -- also the exact cleanup surface.
COLLECTIONS = ["campaigns", "escrow", "shipments", "work_submissions",
               "reviews", "in_app_notifications", "wallet_ledger"]


def now():
    return datetime.now(timezone.utc)


def iso(dt=None):
    return (dt or now()).isoformat()


def days_ago(n):
    return iso(now() - timedelta(days=n))


def days_ahead(n):
    return iso(now() + timedelta(days=n))


def thumb(slug):
    return f"https://picsum.photos/seed/{slug}/600/800"


SAMPLE_VIDEOS = [
    "https://storage.googleapis.com/gtv-videos-bucket/sample/ForBiggerBlazes.mp4",
    "https://storage.googleapis.com/gtv-videos-bucket/sample/ForBiggerFun.mp4",
    "https://storage.googleapis.com/gtv-videos-bucket/sample/ForBiggerJoyrides.mp4",
    "https://storage.googleapis.com/gtv-videos-bucket/sample/ElephantsDream.mp4",
]


async def clean(db):
    total = 0
    for coll in COLLECTIONS:
        res = await db[coll].delete_many({TAG: True})
        if res.deleted_count:
            print(f"  removed {res.deleted_count} from {coll}")
            total += res.deleted_count
    return total


async def main():
    argv = sys.argv[1:]
    clean_only = "--clean" in argv

    if not MONGO_URL:
        print("! MONGO_URL missing from .env. Aborting.")
        return

    client = AsyncIOMotorClient(MONGO_URL)
    db = client[DB_NAME]
    print(f"-> DB: {DB_NAME}")

    creator = await db.users.find_one({"email": CREATOR_EMAIL})
    if not creator:
        print(f"! Creator {CREATOR_EMAIL} not found. Aborting.")
        client.close()
        return
    brand = await db.users.find_one({"email": BRAND_EMAIL})
    if not brand:
        print(f"! Brand {BRAND_EMAIL} not found. Aborting.")
        client.close()
        return

    cid = creator["id"]
    bid_ = brand["id"]
    bprof = brand.get("profile") or {}
    bname = bprof.get("business_name") or brand.get("nickname") or "Levis"
    bhandle = brand.get("nickname") or "levis"
    blogo = bprof.get("logo") or bprof.get("profile_photo") or brand.get("profile_photo") or ""

    print(f"-> Creator: {creator.get('nickname')} ({cid})")
    print(f"-> Brand:   {bname} ({bid_})")

    print("-> Cleaning previous seed...")
    removed = await clean(db)
    if clean_only:
        print(f"Cleaned {removed} docs. Resetting creator profile stats...")
        await db.users.update_one({"id": cid}, {"$set": {
            "balance": 0.0, "average_rating": None, "total_reviews": None,
        }})
        print("Done -- account back to empty.")
        client.close()
        return

    def campaign(title, product, status, **extra):
        """Base campaign shaped like the real ones the frontend reads."""
        doc = {
            "id": str(uuid.uuid4()),
            TAG: True,
            "business_id": bid_,
            "business_nickname": bhandle,
            "brand_name": bname,
            "brand_handle": bhandle,
            "brand_logo_url": blogo,
            "brand_logo": blogo,
            "title": title,
            "status": status,
            "requires_shipment": True,
            "shipment_required": True,
            "product_name": product,
            "product_category": "Fashion",
            "product_description": f"A hero {product.lower()} -- the star of this campaign.",
            "objectives": ["Awareness", "Conversions"],
            "industry_type": "fashion",
            "category": "Fashion",
            "target_audience": "Urban 22-35 who care about denim and everyday style.",
            "budget_min": 2000.0,
            "budget_max": 4000.0,
            "per_video_budget": 3000.0,
            "total_budget": 3000.0,
            "currency": "INR",
            "creators_wanted": 1,
            "estimated_delivery_days": 5,
            "deliverable_items": [{"type": "Reel", "quantity": 1, "duration": "20s",
                                   "aspect_ratios": ["9:16"], "raw_required": False}],
            "product_shipping_by": days_ahead(3),
            "draft_delivery_by": days_ahead(7),
            "final_delivery_by": days_ahead(10),
            "created_at": days_ago(5),
            "updated_at": iso(),
        }
        doc.update(extra)
        return doc

    def hire(doc):
        """Mark our creator as hired -- both fields, since reads use either."""
        doc["selected_creators"] = [cid]
        doc["selected_creator"] = cid
        return doc

    def escrow_doc(camp_id, amount, status, released_at=None, created=10):
        gross = float(amount)
        commission = round(gross * 0.20, 2)
        return {
            "id": str(uuid.uuid4()), TAG: True,
            "campaign_id": camp_id, "business_id": bid_, "creator_id": cid,
            "amount": gross, "brand_commission_amount": commission,
            "brand_commission_percent": 20, "brand_charged": gross + commission,
            "brand_total": gross + commission, "currency": "INR",
            "status": status,
            "payout_status": "released" if status == "released" else "scheduled",
            "funded": True, "net_payable": round(gross - commission, 2),
            "created_at": days_ago(created), "updated_at": iso(),
            "released_at": released_at,
            "estimated_payout_at": days_ahead(7) if status == "held" else None,
            "deductions": [{"label": "Platform commission (20%)", "amount": commission}],
        }

    campaigns, escrows, shipments, submissions, reviews, ledger = [], [], [], [], [], []

    # -- 1. ACTIVE WORK -> "Requests" tab (booking_status pending_creator) ----
    req = hire(campaign("Denim Drop - Creator Invite", "511 Slim Jeans", "in_progress",
                        booking_status="pending_creator", direct_booking=True))
    req["created_at"] = days_ago(1)
    campaigns.append(req)
    escrows.append(escrow_doc(req["id"], 3500, "held", created=1))

    # -- 2. ACTIVE WORK -> "Active" tab --------------------------------------
    # (a) in_progress + shipment in transit
    a1 = hire(campaign("Summer Denim Reel", "Trucker Jacket", "in_progress",
                       work_started_at=days_ago(3)))
    campaigns.append(a1)
    escrows.append(escrow_doc(a1["id"], 3000, "held", created=3))
    shipments.append({
        TAG: True, "campaign_id": a1["id"], "tracking_number": "IND1234567890",
        "courier_name": "Delhivery", "courier_status": "in_transit", "status": "in_transit",
        "courier_tracking_url": "https://www.delhivery.com/track/package/IND1234567890",
        "expected_delivery": days_ahead(2), "expected_delivery_at": days_ahead(2),
        "shipment_checklist": {"sealed": True, "correct_item": True, "working": True},
        "updated_at": iso(),
    })

    # (b) work_submitted -- awaiting brand review
    a2 = hire(campaign("Everyday Denim Story", "Slim Fit Shirt", "work_submitted",
                       work_started_at=days_ago(8)))
    campaigns.append(a2)
    escrows.append(escrow_doc(a2["id"], 2500, "held", created=8))
    shipments.append({
        TAG: True, "campaign_id": a2["id"], "tracking_number": "IND5544332211",
        "courier_name": "Bluedart", "courier_status": "received", "status": "received",
        "expected_delivery": days_ago(5), "received_at": days_ago(5),
        "shipment_checklist": {"sealed": True, "correct_item": True, "working": True},
        "updated_at": iso(),
    })
    submissions.append({
        "id": str(uuid.uuid4()), TAG: True, "campaign_id": a2["id"], "creator_id": cid,
        "work_files": [SAMPLE_VIDEOS[1]], "thumbnail": thumb("mr-a2"),
        "description": "Final reel -- hook in first 3s, product shots, CTA at the end.",
        "status": "pending", "submitted_at": days_ago(1),
        "created_at": days_ago(1), "revisions": [],
    })

    # -- 3. ACTIVE WORK -> "Completed" tab (2 deals, both paid + reviewed) ---
    done_specs = [
        ("Festive Denim Edit", "Denim Jacket", 4000, 20, 3),
        ("Monsoon Style Reel", "Cargo Pants", 3000, 40, 25),
    ]
    for idx, (title, product, amount, created, released) in enumerate(done_specs):
        d = hire(campaign(title, product, "completed",
                          work_started_at=days_ago(created),
                          completed_at=days_ago(released)))
        d["created_at"] = days_ago(created + 2)
        campaigns.append(d)
        escrows.append(escrow_doc(d["id"], amount, "released",
                                  released_at=days_ago(released), created=created))
        shipments.append({
            TAG: True, "campaign_id": d["id"], "tracking_number": f"IND99887766{idx}",
            "courier_name": "Bluedart", "courier_status": "received", "status": "received",
            "expected_delivery": days_ago(created - 2), "received_at": days_ago(created - 3),
            "unboxing_video": SAMPLE_VIDEOS[0], "unboxing_video_url": SAMPLE_VIDEOS[0],
            "shipment_checklist": {"sealed": True, "correct_item": True, "working": True},
            "updated_at": iso(),
        })
        submissions.append({
            "id": str(uuid.uuid4()), TAG: True, "campaign_id": d["id"], "creator_id": cid,
            "work_files": [SAMPLE_VIDEOS[idx % len(SAMPLE_VIDEOS)]], "thumbnail": thumb(f"mr-d{idx}"),
            "description": "Delivered as per brief -- approved by the brand.",
            "status": "approved", "submitted_at": days_ago(released + 3),
            "approved_at": days_ago(released), "created_at": days_ago(released + 3), "revisions": [],
        })
        net = round(amount * 0.8, 2)
        ledger.append({
            "id": str(uuid.uuid4()), TAG: True, "user_id": cid, "type": "Payout",
            "direction": "credit", "amount": net, "status": "success", "campaign_id": d["id"],
            "description": f"Payout released for '{title}'",
            "date": days_ago(released), "created_at": days_ago(released),
        })

    # -- 4. ACTIVE WORK -> "Cancelled" tab -----------------------------------
    canc = hire(campaign("Winter Layers Promo", "Puffer Jacket", "cancelled",
                         cancelled_at=days_ago(12),
                         cancellation_reason="Brand paused the campaign -- product launch pushed."))
    canc["created_at"] = days_ago(18)
    campaigns.append(canc)

    # -- 5. REVIEWS -> brand-left reviews on our creator ----------------------
    review_texts = [
        (5, "Fantastic to work with -- nailed the brief and delivered a day early. "
            "The hook in the first 3 seconds performed really well for us."),
        (4, "Good quality content and clear communication. Needed one small revision "
            "on the CTA, handled quickly and professionally."),
    ]
    completed_camps = [c for c in campaigns if c["status"] == "completed"]
    for (rating, text), camp in zip(review_texts, completed_camps):
        reviews.append({
            "id": str(uuid.uuid4()), TAG: True, "campaign_id": camp["id"],
            "creator_id": cid, "business_id": bid_, "reviewer_id": bid_,
            "reviewee_role": "creator", "rating": rating, "review": text,
            "created_at": days_ago(2),
        })

    # -- 6. BROWSE CAMPAIGNS -> open briefs the creator can bid on ------------
    # Not hired, status active, slots open -> isOpenForBids() == True
    browse_specs = [
        ("Denim Care Routine Reel", "Denim Care Kit", 2500.0),
        ("Street Style Lookbook", "Oversized Denim Shirt", 3500.0),
        ("Back to Campus Denim", "Straight Fit Jeans", 3000.0),
    ]
    for title, product, budget in browse_specs:
        b = campaign(title, product, "active",
                     per_video_budget=budget, total_budget=budget,
                     budget_min=budget - 500, budget_max=budget + 500)
        b["bids"] = []
        b["selected_creators"] = []
        campaigns.append(b)

    # -- 7. Notifications ----------------------------------------------------
    notes = [
        ("New booking request", f"{bname} invited you to 'Denim Drop - Creator Invite'. Respond to accept.", "info", "/active-work"),
        ("Product on the way", "Your product for 'Summer Denim Reel' has been shipped.", "info", "/my-deals"),
        ("Payment released", "Rs. 3,200 has been released to your wallet for 'Festive Denim Edit'.", "success", "/payouts"),
        ("New 5-star review", f"{bname} left you a 5-star review. Nice work!", "success", "/reviews"),
    ]

    # -- write ---------------------------------------------------------------
    await db.campaigns.insert_many(campaigns)
    await db.escrow.insert_many(escrows)
    await db.shipments.insert_many(shipments)
    await db.work_submissions.insert_many(submissions)
    await db.reviews.insert_many(reviews)
    await db.wallet_ledger.insert_many(ledger)
    await db.in_app_notifications.insert_many([{
        "id": str(uuid.uuid4()), TAG: True, "user_id": cid, "title": t, "message": m,
        "type": ty, "link": lk, "read": False, "created_at": days_ago(i), "created_by": "system",
    } for i, (t, m, ty, lk) in enumerate(notes)])

    # -- creator wallet + rating rollup (only this account) -------------------
    wallet = round(sum(l["amount"] for l in ledger), 2)
    avg = round(sum(r["rating"] for r in reviews) / len(reviews), 1)
    await db.users.update_one({"id": cid}, {"$set": {
        "balance": wallet,
        "average_rating": avg,
        "total_reviews": len(reviews),
        "deliverables_completed": len(completed_camps),
    }})

    hired = len([c for c in campaigns if c.get("selected_creator") == cid])
    print("\nSeeded for " + CREATOR_EMAIL)
    print(f"    Active Work -> Requests(1) Active(2) Completed({len(completed_camps)}) Cancelled(1)")
    print(f"    Browse Campaigns -> {len(browse_specs)} open briefs")
    print(f"    My Deals -> {hired} deals")
    print(f"    Earnings -> balance Rs.{wallet:,.0f}, {len(ledger)} payouts, 3 in escrow")
    print(f"    Reviews -> {len(reviews)} (avg {avg} stars)")
    print("\n  Undo anytime:  python seed_meetroj.py --clean")
    client.close()


if __name__ == "__main__":
    asyncio.run(main())
