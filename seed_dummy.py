"""
seed_dummy.py — Populate existing creator & brand profiles with rich dummy data
and build a full deal flow (campaigns, bids, an active shipped deal, a completed
deal with review, notifications, wallet balances) so every screen has data to test.

Safe to re-run: all generated docs are tagged {"seed_dummy": True} and removed
before re-seeding. Profile enrichment is an idempotent $set.

Run:  python seed_dummy.py
"""
import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")  # Windows consoles default to cp1252
except Exception:
    pass

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

MONGO_URL = os.environ.get("MONGO_URL") or os.environ.get("MONGODB_URI") or "mongodb://localhost:27017"
DB_NAME = os.environ.get("DB_NAME") or "test_database"


def now():
    return datetime.now(timezone.utc)


def iso(dt=None):
    return (dt or now()).isoformat()


def days_ago(n):
    return iso(now() - timedelta(days=n))


def days_ahead(n):
    return iso(now() + timedelta(days=n))


# ── sample asset URLs (public, load without local files) ────────────────────
def avatar(n):
    return f"https://i.pravatar.cc/300?img={(n % 70) + 1}"


def banner(slug):
    return f"https://picsum.photos/seed/{slug}/1200/320"


def thumb(slug):
    return f"https://picsum.photos/seed/{slug}/600/800"


SAMPLE_VIDEOS = [
    "https://storage.googleapis.com/gtv-videos-bucket/sample/ForBiggerBlazes.mp4",
    "https://storage.googleapis.com/gtv-videos-bucket/sample/ForBiggerFun.mp4",
    "https://storage.googleapis.com/gtv-videos-bucket/sample/ForBiggerJoyrides.mp4",
    "https://storage.googleapis.com/gtv-videos-bucket/sample/ElephantsDream.mp4",
    "https://storage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4",
]

# ── dummy content pools ─────────────────────────────────────────────────────
CREATOR_BIOS = [
    "UGC creator specialising in short-form beauty & skincare content that converts. 200+ brand videos delivered.",
    "Fitness & wellness creator. I turn products into scroll-stopping reels with a punchy hook in the first 3 seconds.",
    "Tech & gadget reviewer. Clean, honest unboxings and demos that make features easy to understand.",
    "Food & lifestyle storyteller. Warm, homey aesthetic with strong CTAs and natural product placement.",
    "Fashion & style creator. Trend-led try-on hauls and get-ready-with-me content for D2C brands.",
]
CATEGORIES = ["Beauty", "Fitness", "Tech", "Food", "Fashion", "Lifestyle", "Travel"]
SKILLS_POOL = ["Script Writing", "Voiceovers", "Acting", "Videography (DOP)", "Video Editing", "Modelling"]
LANGS_POOL = ["English", "Hindi", "Marathi", "Tamil", "Telugu", "Bengali", "Kannada"]
CITIES = [("Mumbai", "Maharashtra"), ("Bengaluru", "Karnataka"), ("Delhi", "Delhi"),
          ("Pune", "Maharashtra"), ("Chennai", "Tamil Nadu"), ("Hyderabad", "Telangana")]
CONTENT_STYLES = ["Casual & authentic", "Polished & premium", "High-energy & punchy", "Warm & aspirational"]

BRAND_NAMES = ["GlowLab", "PeakForm Nutrition", "NovaTech", "Fresh & Co", "Urban Thread", "Bloom Home"]
BRAND_BIOS = [
    "Clean, dermatologist-tested skincare for everyday radiance.",
    "Performance nutrition for athletes and everyday movers.",
    "Smart home gadgets that make life effortless.",
    "Wholesome snacks made with real ingredients.",
    "Sustainable everyday fashion for the modern wardrobe.",
]
BUSINESS_TYPES = ["Private Limited", "LLP", "Sole Proprietorship"]
BUSINESS_CATEGORIES = ["Beauty & Personal Care", "Health & Fitness", "Electronics", "Food & Beverage", "Fashion"]


def creator_portfolio(seed):
    items = []
    for i in range(4):
        items.append({
            "title": ["Skincare Routine Reel", "Product Unboxing", "GRWM Feature", "Testimonial Cut"][i % 4],
            "description": "Sample UGC deliverable produced for a D2C brand campaign.",
            "video_url": SAMPLE_VIDEOS[i % len(SAMPLE_VIDEOS)],
            "url": SAMPLE_VIDEOS[i % len(SAMPLE_VIDEOS)],
            "original_url": SAMPLE_VIDEOS[i % len(SAMPLE_VIDEOS)],
            "thumbnail": thumb(f"{seed}-pf{i}"),
            "deliverable_type": "video",
            "cost": [1500, 2000, 2500, 3000][i % 4],
            "duration": ["0:20", "0:30", "0:45", "1:00"][i % 4],
        })
    return items


def build_brief_text(product, brand_handle):
    return "\n".join([
        f"Campaign: {product} Launch Push",
        f"Brand: @{brand_handle}",
        "Category: Beauty",
        f"Product: {product}",
        f"Product description: A hero {product.lower()} that hydrates and protects — the star of this campaign.",
        "Hook: Stop scrolling — your skin will thank you.",
        "Key message: Visible results in 7 days, clinically tested.",
        "Objectives: Awareness, Conversions",
        "Target audience: Urban women 22-35 who care about clean, effective skincare.",
        "Budget visibility: Visible to creators",
        "",
        "Deliverables:",
        "1. 1 x Reel (9:16, under 30s); duration 20s; ratios 9:16; raw files not required",
        "",
        "Must include: product visible 3s minimum; verbal mention brand name; CTA Visit website; hashtags #ad #skincare; brand tag yes",
        "Required phrases: clinically tested, visible in 7 days",
        "Required shots: close-up of product, application shot",
        "Must avoid: competitors no; profanity no; political/religious no",
        "Style guidance: tones Casual; pacing Punchy; music Trending",
        "Usage rights: platforms Instagram, TikTok; duration 3 months; exclusivity 15 days",
        "Timeline: ship by " + days_ahead(3)[:10] + "; draft by " + days_ahead(7)[:10] + "; final by " + days_ahead(10)[:10],
        "Budget: fixed Rs. 2000",
    ])


async def main():
    client = AsyncIOMotorClient(MONGO_URL)
    db = client[DB_NAME]
    print(f"→ Connected to {DB_NAME}")

    # ── 0. Clean previous seed artifacts ────────────────────────────────────
    for coll in ["campaigns", "escrow", "shipments", "work_submissions", "reviews",
                 "in_app_notifications", "wallet_ledger"]:
        res = await db[coll].delete_many({"seed_dummy": True})
        if res.deleted_count:
            print(f"  cleaned {res.deleted_count} old seeded docs from {coll}")

    creators = await db.users.find({"role": "creator"}, {"_id": 0}).to_list(500)
    brands = await db.users.find({"role": "business"}, {"_id": 0}).to_list(500)
    print(f"→ Found {len(creators)} creators, {len(brands)} brands")

    if not creators or not brands:
        print("! Need at least one creator and one brand account. Aborting.")
        client.close()
        return

    # ── 1. Enrich every creator profile ─────────────────────────────────────
    for i, c in enumerate(creators):
        city, state = CITIES[i % len(CITIES)]
        nick = c.get("nickname") or f"creator{i+1}"
        portfolio = creator_portfolio(nick)
        rating = round(4.3 + (i % 6) * 0.1, 1)
        prof = {
            "profile_picture": avatar(i),
            "profile_photo": avatar(i),
            "banner": banner(f"cre-{nick}"),
            "bio": CREATOR_BIOS[i % len(CREATOR_BIOS)],
            "gender": ["Female", "Male", "Female", "Male"][i % 4],
            "age": 22 + (i % 12),
            "city": city, "state": state, "country": "India",
            "address": {
                "full_name": f"Creator {i+1}", "phone": f"+9198{(70000000 + i):08d}",
                "line1": f"{10 + i} Sunrise Apartments", "line2": "MG Road",
                "city": city, "state": state, "pincode": f"4000{(10 + i) % 90:02d}", "country": "India",
            },
            "category": CATEGORIES[i % len(CATEGORIES)],
            "primary_category": CATEGORIES[i % len(CATEGORIES)],
            "tags": [CATEGORIES[i % len(CATEGORIES)], CATEGORIES[(i + 2) % len(CATEGORIES)], "UGC"],
            "content_style": CONTENT_STYLES[i % len(CONTENT_STYLES)],
            "level": "Rising",
            "languages": LANGS_POOL[: 2 + (i % 3)],
            "content_languages": LANGS_POOL[: 2 + (i % 3)],
            "portfolio": portfolio,
            "rate_card": {"expected_payout": [1500, 2000, 2500, 3000][i % 4], "payout_period": "per video"},
            "social_links": {
                "instagram": f"https://instagram.com/{nick}",
                "youtube": f"https://youtube.com/@{nick}",
                "tiktok": f"https://tiktok.com/@{nick}",
            },
            "followers": 5000 + i * 1350,
            "skills": SKILLS_POOL[: 3 + (i % 3)],
            "quality_tier": ["A", "B", "A", "S"][i % 4],
            "receive_briefs": True,
            "deliverables_completed": 3 + (i % 20),
            "terms_agreed": True,
        }
        await db.users.update_one({"id": c["id"]}, {"$set": {
            "profile_completed": True,
            "approval_status": "approved",
            "creator_directory_visible": True,
            "curated_brand_visible": True,
            "profile_photo": avatar(i),
            "banner": banner(f"cre-{nick}"),
            "level": "Rising",
            "balance": 5000 + i * 1500,
            "average_rating": rating,
            "total_reviews": 4 + (i % 15),
            "portfolio": portfolio,
            "skills": SKILLS_POOL[: 3 + (i % 3)],
            "languages": prof["languages"],
            "profile": {**(c.get("profile") or {}), **prof},
        }})
    print(f"✓ Enriched {len(creators)} creator profiles")

    # ── 2. Enrich every brand profile ───────────────────────────────────────
    for i, b in enumerate(brands):
        city, state = CITIES[i % len(CITIES)]
        name = (b.get("profile") or {}).get("business_name") or BRAND_NAMES[i % len(BRAND_NAMES)]
        prof = {
            "business_name": name,
            "nickname": b.get("nickname") or name,
            "logo": avatar(i + 20),
            "banner": banner(f"brand-{i}"),
            "brand_logo_url": avatar(i + 20),
            "profile_photo": avatar(i + 20),
            "contact_person": f"Brand Manager {i+1}",
            "work_email": b.get("email") or f"brand{i+1}@demo.com",
            "phone_number": f"+9199{(80000000 + i):08d}",
            "website": f"https://{name.lower().replace(' ', '')}.com",
            "website_url": f"https://{name.lower().replace(' ', '')}.com",
            "business_type": BUSINESS_TYPES[i % len(BUSINESS_TYPES)],
            "business_category": BUSINESS_CATEGORIES[i % len(BUSINESS_CATEGORIES)],
            "industry_category": BUSINESS_CATEGORIES[i % len(BUSINESS_CATEGORIES)],
            "product_type": "Physical product",
            "bio": BRAND_BIOS[i % len(BRAND_BIOS)],
            "description": BRAND_BIOS[i % len(BRAND_BIOS)],
            "gst_number": f"27ABCDE{1234 + i}F1Z{i % 10}",
            "billing_address": f"{20 + i} Corporate Park, {city}, {state}",
            "city": city, "state": state, "country": "India",
            "address": {
                "full_name": name, "phone": f"+9199{(80000000 + i):08d}",
                "line1": f"{20 + i} Corporate Park", "line2": "Business District",
                "city": city, "state": state, "pincode": f"5600{(10 + i) % 90:02d}", "country": "India",
            },
            "social_links": {"instagram": f"https://instagram.com/{name.lower().replace(' ', '')}"},
        }
        await db.users.update_one({"id": b["id"]}, {"$set": {
            "profile_completed": True,
            "approval_status": "approved",
            "profile_photo": avatar(i + 20),
            "banner": banner(f"brand-{i}"),
            "balance": 100000,
            "average_rating": round(4.4 + (i % 5) * 0.1, 1),
            "total_reviews": 3 + (i % 10),
            "total_campaigns": 2 + (i % 6),
            "profile": {**(b.get("profile") or {}), **prof},
        }})
    print(f"✓ Enriched {len(brands)} brand profiles")

    # ── 3. Build a full deal flow between the first brand & first creators ───
    brand = brands[0]
    bname = (brand.get("profile") or {}).get("business_name") or BRAND_NAMES[0]
    bhandle = brand.get("nickname") or "brand"
    blogo = avatar(20)
    c1 = creators[0]
    c2 = creators[1] if len(creators) > 1 else creators[0]

    def base_campaign(title, product, status):
        return {
            "id": str(uuid.uuid4()),
            "seed_dummy": True,
            "business_id": brand["id"],
            "business_nickname": bhandle,
            "brand_name": bname,
            "brand_handle": bhandle,
            "brand_logo_url": blogo,
            "title": title,
            "status": status,
            "requires_shipment": True,
            "shipment_required": True,
            "product_name": product,
            "product_category": "Beauty",
            "product_description": f"A hero {product.lower()} — the star of this campaign.",
            "brief_text": build_brief_text(product, bhandle),
            "objectives": ["Awareness", "Conversions"],
            "industry_type": "skincare",
            "category": "Beauty",
            "target_audience": "Urban women 22-35 who care about clean skincare.",
            "budget_min": 1500.0,
            "budget_max": 2000.0,
            "per_video_budget": 2000.0,
            "total_budget": 2000.0,
            "currency": "INR",
            "estimated_delivery_days": 5,
            "deliverable_items": [{"type": "Reel", "quantity": 1, "duration": "20s",
                                   "aspect_ratios": ["9:16"], "raw_required": False}],
            "product_shipping_by": days_ahead(3),
            "draft_delivery_by": days_ahead(7),
            "final_delivery_by": days_ahead(10),
            "created_at": days_ago(4),
            "updated_at": iso(),
        }

    def bid_doc(creator, amount, days):
        return {
            "id": str(uuid.uuid4()),
            "creator_id": creator["id"],
            "creator_nickname": creator.get("nickname", "creator"),
            "amount": float(amount),
            "proposal": "Hi! I love this product and my audience is a perfect fit. I'll deliver a punchy, "
                        "conversion-focused reel with a strong hook and clean product shots. Excited to collaborate!",
            "estimated_delivery_days": days,
            "submitted_at": days_ago(2),
            "status": "pending",
        }

    # (a) OPEN campaign with bids — powers Creator Bids (brand) + My Bids (creator)
    open_camp = base_campaign("Summer Glow Reel", "Vitamin C Serum", "active")
    open_camp["bids"] = [bid_doc(c1, 1800, 2), bid_doc(c2, 2000, 3)]
    await db.campaigns.insert_one(open_camp)

    # (b) IN-PROGRESS deal, shipped/in-transit — powers Deal Room, Shipping, My Deals
    prog = base_campaign("Hydration Hero Launch", "Hydra Boost Cream", "in_progress")
    prog["selected_creator"] = c1["id"]
    prog["work_started_at"] = days_ago(3)
    prog["bids"] = [bid_doc(c1, 2000, 3)]
    escrow_id = str(uuid.uuid4())
    prog["escrow_id"] = escrow_id
    await db.campaigns.insert_one(prog)
    await db.escrow.insert_one({
        "id": escrow_id, "seed_dummy": True, "campaign_id": prog["id"],
        "business_id": brand["id"], "creator_id": c1["id"], "amount": 2000.0,
        "brand_commission_amount": 400.0, "brand_commission_percent": 20, "brand_charged": 2400.0,
        "brand_total": 2400.0, "currency": "INR", "status": "held", "payout_status": "scheduled",
        "funded": True, "net_payable": 1600.0, "created_at": days_ago(3), "updated_at": iso(),
        "estimated_payout_at": days_ahead(7),
        "deductions": [{"label": "Platform commission (20%)", "amount": 400.0}],
    })
    await db.shipments.insert_one({
        "seed_dummy": True, "campaign_id": prog["id"], "tracking_number": "IND1234567890",
        "courier_name": "Delhivery", "courier_status": "in_transit", "status": "in_transit",
        "courier_tracking_url": "https://www.delhivery.com/track/package/IND1234567890",
        "expected_delivery": days_ahead(2), "expected_delivery_at": days_ahead(2),
        "shipment_checklist": {"sealed": True, "correct_item": True, "working": True},
        "updated_at": iso(),
    })

    # (c) COMPLETED deal with approved work + review + released payout
    done = base_campaign("Radiance Routine", "Night Repair Oil", "completed")
    done["selected_creator"] = c2["id"]
    done["work_started_at"] = days_ago(20)
    done["completed_at"] = days_ago(2)
    done["bids"] = [bid_doc(c2, 2000, 3)]
    done_escrow = str(uuid.uuid4())
    done["escrow_id"] = done_escrow
    await db.campaigns.insert_one(done)
    await db.escrow.insert_one({
        "id": done_escrow, "seed_dummy": True, "campaign_id": done["id"],
        "business_id": brand["id"], "creator_id": c2["id"], "amount": 2000.0,
        "brand_commission_amount": 400.0, "brand_commission_percent": 20, "brand_charged": 2400.0,
        "currency": "INR", "status": "released", "payout_status": "released", "funded": True,
        "net_payable": 1600.0, "created_at": days_ago(20), "released_at": days_ago(2), "updated_at": iso(),
        "deductions": [{"label": "Platform commission (20%)", "amount": 400.0}],
    })
    await db.shipments.insert_one({
        "seed_dummy": True, "campaign_id": done["id"], "tracking_number": "IND9988776655",
        "courier_name": "Bluedart", "courier_status": "received", "status": "received",
        "expected_delivery": days_ago(15), "received_at": days_ago(14),
        "unboxing_video": SAMPLE_VIDEOS[0], "unboxing_video_url": SAMPLE_VIDEOS[0],
        "shipment_checklist": {"sealed": True, "correct_item": True, "working": True}, "updated_at": iso(),
    })
    await db.work_submissions.insert_one({
        "id": str(uuid.uuid4()), "seed_dummy": True, "campaign_id": done["id"], "creator_id": c2["id"],
        "work_files": [SAMPLE_VIDEOS[1]], "description": "Final reel as per brief — hook, product shots, CTA.",
        "status": "approved", "submitted_at": days_ago(5), "approved_at": days_ago(2),
        "created_at": days_ago(5), "revisions": [],
    })
    # reviews both ways
    await db.reviews.insert_many([
        {"id": str(uuid.uuid4()), "seed_dummy": True, "campaign_id": done["id"], "creator_id": c2["id"],
         "business_id": brand["id"], "reviewer_id": brand["id"], "reviewee_role": "creator", "rating": 5,
         "review": "Fantastic to work with — nailed the brief and delivered early. Highly recommend!",
         "created_at": days_ago(1)},
        {"id": str(uuid.uuid4()), "seed_dummy": True, "campaign_id": done["id"], "creator_id": c2["id"],
         "business_id": brand["id"], "reviewer_id": c2["id"], "reviewee_role": "business", "rating": 5,
         "review": "Clear brief, fast approvals and prompt payment. Great brand to collaborate with.",
         "created_at": days_ago(1)},
    ])
    # wallet ledger payout for the creator
    await db.wallet_ledger.insert_one({
        "id": str(uuid.uuid4()), "seed_dummy": True, "user_id": c2["id"], "type": "Payout",
        "direction": "credit", "amount": 1600.0, "status": "success", "campaign_id": done["id"],
        "description": "Payout released for 'Radiance Routine'", "date": days_ago(2), "created_at": days_ago(2),
    })

    # ── 4. Notifications for all three parties ──────────────────────────────
    notes = [
        (brand["id"], "New bid on your campaign", f"{c1.get('nickname','A creator')} placed a bid of ₹1,800 on 'Summer Glow Reel'.", "info", "/dashboard/business/pending-bids"),
        (brand["id"], "Payment held in escrow", "₹2,000 for 'Hydration Hero Launch' is now held in escrow.", "success", "/dashboard/business/wallet"),
        (brand["id"], "Content submitted for review", f"{c2.get('nickname','The creator')} submitted content for 'Radiance Routine'.", "info", "/dashboard/business/work-review"),
        (c1["id"], "Product on the way", "The brand's product for 'Hydration Hero Launch' has been shipped to you.", "info", "/my-deals"),
        (c1["id"], "You've been selected!", "You were selected for 'Hydration Hero Launch'. Payment is in escrow.", "success", "/my-deals"),
        (c2["id"], "Payment released", "₹1,600 has been released to your wallet for 'Radiance Routine'.", "success", "/payouts"),
        (c2["id"], "New 5★ review", "The brand left you a 5-star review. Nice work!", "success", "/my-deals"),
    ]
    await db.in_app_notifications.insert_many([{
        "id": str(uuid.uuid4()), "seed_dummy": True, "user_id": uid, "title": t, "message": m,
        "type": ty, "link": lk, "read": False, "created_at": days_ago(idx % 3), "created_by": "system",
    } for idx, (uid, t, m, ty, lk) in enumerate(notes)])

    print("✓ Seeded deal flow:")
    print(f"    • Open campaign 'Summer Glow Reel' with 2 bids (brand {bhandle})")
    print(f"    • In-progress shipped deal 'Hydration Hero Launch' → {c1.get('nickname')}")
    print(f"    • Completed deal 'Radiance Routine' + review + payout → {c2.get('nickname')}")
    print(f"    • {len(notes)} notifications")
    print("✓ Done. Log in as your brand/creator accounts to see populated data.")
    client.close()


if __name__ == "__main__":
    asyncio.run(main())
