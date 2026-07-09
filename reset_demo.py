"""
reset_demo.py — Make ONLY test@gmail.com (creator) and testbrand@test.com (brand)
hold demo data. Everything else is cleaned:

  • all campaigns / escrow / shipments / work_submissions / reviews / wallet_ledger
    and in-app notifications are wiped (fresh slate),
  • every other creator/brand profile is reset to empty + wallet zeroed,
  • admins are left completely untouched,
  • the two KEEP accounts get rich profiles + a full deal flow between them.

Run:  python reset_demo.py
"""
import asyncio, os, sys, uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

try: sys.stdout.reconfigure(encoding="utf-8")
except Exception: pass

ROOT = Path(__file__).parent
load_dotenv(ROOT / ".env")
MONGO = os.environ.get("MONGO_URL") or os.environ.get("MONGODB_URI") or "mongodb://localhost:27017"
DB = os.environ.get("DB_NAME") or "test_database"

KEEP_CREATOR = "test@gmail.com"
KEEP_BRAND = "testbrand@test.com"
TXN_COLLECTIONS = ["campaigns", "escrow", "shipments", "work_submissions",
                   "reviews", "wallet_ledger", "in_app_notifications", "deal_receipts",
                   "deal_activity", "deal_messages", "chat_action_cards", "disputes"]

now = lambda: datetime.now(timezone.utc)
iso = lambda dt=None: (dt or now()).isoformat()
days_ago = lambda n: iso(now() - timedelta(days=n))
days_ahead = lambda n: iso(now() + timedelta(days=n))
avatar = lambda n: f"https://i.pravatar.cc/300?img={(n % 70) + 1}"
banner = lambda s: f"https://picsum.photos/seed/{s}/1200/320"
thumb = lambda s: f"https://picsum.photos/seed/{s}/600/800"
VIDS = ["https://storage.googleapis.com/gtv-videos-bucket/sample/ForBiggerBlazes.mp4",
        "https://storage.googleapis.com/gtv-videos-bucket/sample/ForBiggerFun.mp4",
        "https://storage.googleapis.com/gtv-videos-bucket/sample/ForBiggerJoyrides.mp4",
        "https://storage.googleapis.com/gtv-videos-bucket/sample/ElephantsDream.mp4"]


def creator_portfolio():
    titles = ["Skincare Routine Reel", "Product Unboxing", "GRWM Feature", "Testimonial Cut"]
    return [{
        "title": titles[i], "description": "Sample UGC deliverable for a D2C brand campaign.",
        "video_url": VIDS[i % len(VIDS)], "url": VIDS[i % len(VIDS)], "original_url": VIDS[i % len(VIDS)],
        "thumbnail": thumb(f"pf{i}"), "deliverable_type": "video",
        "cost": [1500, 2000, 2500, 3000][i], "duration": ["0:20", "0:30", "0:45", "1:00"][i],
    } for i in range(4)]


def brief_text(product, handle):
    return "\n".join([
        f"Campaign: {product} Launch Push", f"Brand: @{handle}", "Category: Beauty",
        f"Product: {product}", f"Product description: A hero {product.lower()} that hydrates and protects.",
        "Hook: Stop scrolling — your skin will thank you.", "Key message: Visible results in 7 days.",
        "Objectives: Awareness, Conversions", "Target audience: Urban women 22-35 into clean skincare.",
        "Budget visibility: Visible to creators", "", "Deliverables:",
        "1. 1 x Reel (9:16, under 30s); duration 20s; ratios 9:16; raw files not required", "",
        "Must include: product visible 3s minimum; CTA Visit website; hashtags #ad #skincare; brand tag yes",
        "Required phrases: clinically tested, visible in 7 days", "Required shots: close-up, application shot",
        "Must avoid: competitors no; profanity no; political/religious no",
        "Style guidance: tones Casual; pacing Punchy; music Trending",
        "Usage rights: platforms Instagram, TikTok; duration 3 months; exclusivity 15 days",
        f"Timeline: ship by {days_ahead(3)[:10]}; draft by {days_ahead(7)[:10]}; final by {days_ahead(10)[:10]}",
        "Budget: fixed Rs. 2000",
    ])


async def main():
    db = AsyncIOMotorClient(MONGO)[DB]
    print(f"→ DB: {DB}")

    creator = await db.users.find_one({"email": KEEP_CREATOR}, {"_id": 0})
    brand = await db.users.find_one({"email": KEEP_BRAND}, {"_id": 0})
    if not creator or not brand:
        print(f"! Missing KEEP account(s): creator={bool(creator)} brand={bool(brand)}. Aborting.")
        return
    keep_ids = {creator["id"], brand["id"]}

    # ── 1. Wipe all transactional data (fresh slate) ────────────────────────
    for coll in TXN_COLLECTIONS:
        res = await db[coll].delete_many({})
        print(f"  wiped {res.deleted_count} docs from {coll}")

    # ── 2. Reset every OTHER creator/brand profile; zero wallet. Admins safe. ─
    others = await db.users.find(
        {"role": {"$in": ["creator", "business"]}}, {"_id": 0, "id": 1}
    ).to_list(1000)
    others = [u for u in others if u.get("id") and u["id"] not in keep_ids]
    for u in others:
        await db.users.update_one({"id": u["id"]}, {
            "$set": {"profile": {}, "portfolio": [], "profile_photo": "", "banner": "",
                     "balance": 0, "average_rating": 0, "total_reviews": 0, "updated_at": iso()},
            "$unset": {"skills": "", "languages": ""},
        })
    print(f"✓ Cleared {len(others)} other creator/brand profiles (admins untouched)")

    # ── 3. Enrich the KEEP creator ──────────────────────────────────────────
    cnick = creator.get("nickname") or "creator"
    cprofile = {
        "profile_picture": avatar(3), "profile_photo": avatar(3), "banner": banner("keep-creator"),
        "bio": "UGC creator specialising in short-form beauty & skincare content that converts. 200+ videos delivered.",
        "gender": "Female", "age": 26, "city": "Mumbai", "state": "Maharashtra", "country": "India",
        "address": {"full_name": "Test Creator", "phone": "+919876543210", "line1": "12 Sunrise Apartments",
                    "line2": "MG Road", "city": "Mumbai", "state": "Maharashtra", "pincode": "400001", "country": "India"},
        "category": "Beauty", "primary_category": "Beauty", "tags": ["Beauty", "Skincare", "UGC"],
        "content_style": "Casual & authentic", "level": "Rising",
        "languages": ["English", "Hindi"], "content_languages": ["English", "Hindi"],
        "portfolio": creator_portfolio(),
        "rate_card": {"expected_payout": 2000, "payout_period": "per video"},
        "social_links": {"instagram": f"https://instagram.com/{cnick}", "youtube": f"https://youtube.com/@{cnick}"},
        "followers": 18500, "skills": ["Script Writing", "Acting", "Video Editing"],
        "quality_tier": "A", "receive_briefs": True, "deliverables_completed": 12, "terms_agreed": True,
    }
    await db.users.update_one({"id": creator["id"]}, {"$set": {
        "profile_completed": True, "approval_status": "approved", "creator_directory_visible": True,
        "curated_brand_visible": True, "profile_photo": avatar(3), "banner": banner("keep-creator"),
        "level": "Rising", "balance": 11600, "average_rating": 4.8, "total_reviews": 9,
        "portfolio": cprofile["portfolio"], "skills": cprofile["skills"], "languages": cprofile["languages"],
        "profile": {**(creator.get("profile") or {}), **cprofile},
    }})
    print(f"✓ Seeded creator {KEEP_CREATOR}")

    # ── 4. Enrich the KEEP brand ────────────────────────────────────────────
    bname = (brand.get("profile") or {}).get("business_name") or brand.get("nickname") or "Test Brand"
    bhandle = brand.get("nickname") or "Test Brand"
    bprofile = {
        "business_name": bname, "nickname": bhandle, "logo": avatar(25), "banner": banner("keep-brand"),
        "brand_logo_url": avatar(25), "profile_photo": avatar(25), "contact_person": "Brand Manager",
        "work_email": KEEP_BRAND, "phone_number": "+919988776655", "website": "https://testbrand.com",
        "website_url": "https://testbrand.com", "business_type": "Private Limited",
        "business_category": "Beauty & Personal Care", "industry_category": "Beauty & Personal Care",
        "product_type": "Physical product", "bio": "Clean, dermatologist-tested skincare for everyday radiance.",
        "description": "Clean, dermatologist-tested skincare for everyday radiance.",
        "gst_number": "27ABCDE1234F1Z5", "billing_address": "20 Corporate Park, Bengaluru, Karnataka",
        "city": "Bengaluru", "state": "Karnataka", "country": "India",
        "address": {"full_name": bname, "phone": "+919988776655", "line1": "20 Corporate Park",
                    "line2": "Business District", "city": "Bengaluru", "state": "Karnataka", "pincode": "560001", "country": "India"},
        "social_links": {"instagram": "https://instagram.com/testbrand"},
    }
    await db.users.update_one({"id": brand["id"]}, {"$set": {
        "profile_completed": True, "approval_status": "approved", "profile_photo": avatar(25),
        "banner": banner("keep-brand"), "balance": 100000, "average_rating": 4.7,
        "total_reviews": 5, "total_campaigns": 3, "profile": {**(brand.get("profile") or {}), **bprofile},
    }})
    print(f"✓ Seeded brand {KEEP_BRAND}")

    # ── 5. Deal flow between the two ────────────────────────────────────────
    blogo = avatar(25)

    def base(title, product, status):
        return {"id": str(uuid.uuid4()), "seed_dummy": True, "business_id": brand["id"],
                "business_nickname": bhandle, "brand_name": bname, "brand_handle": bhandle, "brand_logo_url": blogo,
                "title": title, "status": status, "requires_shipment": True, "shipment_required": True,
                "product_name": product, "product_category": "Beauty",
                "product_description": f"A hero {product.lower()} — the star of this campaign.",
                "brief_text": brief_text(product, bhandle), "objectives": ["Awareness", "Conversions"],
                "industry_type": "skincare", "category": "Beauty",
                "target_audience": "Urban women 22-35 into clean skincare.",
                "budget_min": 1500.0, "budget_max": 2000.0, "per_video_budget": 2000.0, "total_budget": 2000.0,
                "currency": "INR", "estimated_delivery_days": 5,
                "deliverable_items": [{"type": "Reel", "quantity": 1, "duration": "20s",
                                       "aspect_ratios": ["9:16"], "raw_required": False}],
                "product_shipping_by": days_ahead(3), "draft_delivery_by": days_ahead(7),
                "final_delivery_by": days_ahead(10), "created_at": days_ago(4), "updated_at": iso()}

    def bid(amount, days):
        return {"id": str(uuid.uuid4()), "creator_id": creator["id"], "creator_nickname": cnick,
                "amount": float(amount), "proposal": "Hi! I love this product and my audience is a perfect fit. "
                "I'll deliver a punchy, conversion-focused reel with a strong hook and clean product shots.",
                "estimated_delivery_days": days, "submitted_at": days_ago(2), "status": "pending"}

    # (a) open campaign with a bid
    op = base("Summer Glow Reel", "Vitamin C Serum", "active"); op["bids"] = [bid(1800, 2)]
    await db.campaigns.insert_one(op)

    # (b) in-progress shipped deal
    pr = base("Hydration Hero Launch", "Hydra Boost Cream", "in_progress")
    pr["selected_creator"] = creator["id"]; pr["work_started_at"] = days_ago(3); pr["bids"] = [bid(2000, 3)]
    eid = str(uuid.uuid4()); pr["escrow_id"] = eid
    await db.campaigns.insert_one(pr)
    await db.escrow.insert_one({"id": eid, "seed_dummy": True, "campaign_id": pr["id"], "business_id": brand["id"],
        "creator_id": creator["id"], "amount": 2000.0, "brand_commission_amount": 400.0, "brand_commission_percent": 20,
        "brand_charged": 2400.0, "currency": "INR", "status": "held", "payout_status": "scheduled", "funded": True,
        "net_payable": 1600.0, "created_at": days_ago(3), "updated_at": iso(), "estimated_payout_at": days_ahead(7),
        "deductions": [{"label": "Platform commission (20%)", "amount": 400.0}]})
    await db.shipments.insert_one({"seed_dummy": True, "campaign_id": pr["id"], "tracking_number": "IND1234567890",
        "courier_name": "Delhivery", "courier_status": "in_transit", "status": "in_transit",
        "expected_delivery": days_ahead(2), "shipment_checklist": {"sealed": True, "correct_item": True, "working": True},
        "updated_at": iso()})

    # (c) completed deal + review + payout
    dn = base("Radiance Routine", "Night Repair Oil", "completed")
    dn["selected_creator"] = creator["id"]; dn["work_started_at"] = days_ago(20); dn["completed_at"] = days_ago(2)
    dn["bids"] = [bid(2000, 3)]; deid = str(uuid.uuid4()); dn["escrow_id"] = deid
    await db.campaigns.insert_one(dn)
    await db.escrow.insert_one({"id": deid, "seed_dummy": True, "campaign_id": dn["id"], "business_id": brand["id"],
        "creator_id": creator["id"], "amount": 2000.0, "brand_commission_amount": 400.0, "brand_commission_percent": 20,
        "brand_charged": 2400.0, "currency": "INR", "status": "released", "payout_status": "released", "funded": True,
        "net_payable": 1600.0, "created_at": days_ago(20), "released_at": days_ago(2), "updated_at": iso(),
        "deductions": [{"label": "Platform commission (20%)", "amount": 400.0}]})
    await db.shipments.insert_one({"seed_dummy": True, "campaign_id": dn["id"], "tracking_number": "IND9988776655",
        "courier_name": "Bluedart", "courier_status": "received", "status": "received", "expected_delivery": days_ago(15),
        "received_at": days_ago(14), "unboxing_video": VIDS[0], "unboxing_video_url": VIDS[0],
        "shipment_checklist": {"sealed": True, "correct_item": True, "working": True}, "updated_at": iso()})
    await db.work_submissions.insert_one({"id": str(uuid.uuid4()), "seed_dummy": True, "campaign_id": dn["id"],
        "creator_id": creator["id"], "work_files": [VIDS[1]], "description": "Final reel per brief — hook, product, CTA.",
        "status": "approved", "submitted_at": days_ago(5), "approved_at": days_ago(2), "created_at": days_ago(5), "revisions": []})
    await db.reviews.insert_many([
        {"id": str(uuid.uuid4()), "seed_dummy": True, "campaign_id": dn["id"], "creator_id": creator["id"],
         "business_id": brand["id"], "reviewer_id": brand["id"], "reviewee_role": "creator", "rating": 5,
         "review": "Fantastic to work with — nailed the brief and delivered early!", "created_at": days_ago(1)},
        {"id": str(uuid.uuid4()), "seed_dummy": True, "campaign_id": dn["id"], "creator_id": creator["id"],
         "business_id": brand["id"], "reviewer_id": creator["id"], "reviewee_role": "business", "rating": 5,
         "review": "Clear brief, fast approvals and prompt payment. Great brand.", "created_at": days_ago(1)}])
    await db.wallet_ledger.insert_one({"id": str(uuid.uuid4()), "seed_dummy": True, "user_id": creator["id"],
        "type": "Payout", "direction": "credit", "amount": 1600.0, "status": "success", "campaign_id": dn["id"],
        "description": "Payout released for 'Radiance Routine'", "date": days_ago(2), "created_at": days_ago(2)})

    # (d) notifications for the two
    notes = [
        (brand["id"], "New bid on your campaign", f"{cnick} placed a bid of ₹1,800 on 'Summer Glow Reel'.", "info", "/dashboard/business/pending-bids"),
        (brand["id"], "Payment held in escrow", "₹2,000 for 'Hydration Hero Launch' is now held in escrow.", "success", "/dashboard/business/wallet"),
        (brand["id"], "Content submitted for review", f"{cnick} submitted content for 'Radiance Routine'.", "info", "/dashboard/business/work-review"),
        (creator["id"], "You've been selected!", "You were selected for 'Hydration Hero Launch'. Payment is in escrow.", "success", "/my-deals"),
        (creator["id"], "Product on the way", "The brand's product for 'Hydration Hero Launch' has been shipped to you.", "info", "/my-deals"),
        (creator["id"], "Payment released", "₹1,600 has been released to your wallet for 'Radiance Routine'.", "success", "/payouts"),
    ]
    await db.in_app_notifications.insert_many([{"id": str(uuid.uuid4()), "seed_dummy": True, "user_id": uid,
        "title": t, "message": m, "type": ty, "link": lk, "read": False, "created_at": days_ago(i % 3),
        "created_by": "system"} for i, (uid, t, m, ty, lk) in enumerate(notes)])

    print("✓ Seeded deal flow between the two accounts (open bid + shipped deal + completed deal + reviews + payout)")
    print("✓ Done — only test@gmail.com and testbrand@test.com have demo data now.")


if __name__ == "__main__":
    asyncio.run(main())
