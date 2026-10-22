"""A creator's counter on a PRIVATE brief, once accepted, renegotiates that brief: one deal, not two.
Runs the real routes against an in-memory database."""
import os

import pytest

pytest.importorskip("mongomock_motor")
pytest.importorskip("httpx")

import asyncio  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402
from mongomock_motor import AsyncMongoMockClient  # noqa: E402

import server  # noqa: E402


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("RESEND_API_KEY", "")  # never send real email from a test
    monkeypatch.setattr(server, "db", AsyncMongoMockClient()["private_counter"])
    loop = asyncio.new_event_loop()
    client = TestClient(server.app, follow_redirects=False)
    run = loop.run_until_complete

    def call(method, path, token=None, **kw):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return client.request(method, "/api" + path, headers=headers, **kw)

    def signup(role, n):
        b = call("POST", "/auth/signup", json={"email": f"pc-{role}-{n}@example.com", "password": "Passw0rd!x", "role": role,
                                               "phone": f"98765{46000 + n}", "dial_code": "+91", "name": f"P{n}"}).json()
        return b["token"], b["user_id"]

    brand_t, brand = signup("business", 1)
    creator_t, creator = signup("creator", 1)
    call("PUT", "/profile/business", brand_t, json={"business_description": "x", "product_type": "Skincare", "industry_category": "Beauty & Cosmetics"})
    call("PUT", "/profile/creator", creator_t, json={"bio": "b", "tags": ["beauty"], "fullName": "Cre One", "rate_card": {"expected_payout": "2500"}})
    run(server.db.users.insert_one({"id": "adm", "email": "adm@example.com", "role": "admin", "admin_role": "super_admin",
                                    "approval_status": "approved", "profile_completed": True}))
    admin_t = server.create_token("adm", "adm@example.com", "admin")
    for uid in (brand, creator):
        call("POST", "/admin/approve-profile", admin_t, json={"item_id": uid, "action": "approve"})
    run(server.db.users.update_one({"id": brand}, {"$set": {"balance": 100000.0}}))
    run(server.db.users.update_one({"id": creator}, {"$set": {"kyc": {"status": "verified"}}}))

    def balance():
        return round(run(server.db.users.find_one({"id": brand})).get("balance", 0), 2)

    def counter_and_accept(price, wallet=None, budget=1000, explicit=False):
        """Publish a private brief, approve it, creator counters at `price`, brand accepts."""
        # A private brief is priced at the creator's own rate, whatever the brand sends,
        # so `budget` is set as that rate.
        run(server.db.users.update_one({"id": creator}, {"$set": {"profile.rate_card.expected_payout": str(budget)}}))
        payload = {
            "status": "pending_approval", "title": "White label perfume", "product_name": "Perfume",
            "product_category": "Beauty & Cosmetics", "category": "Beauty & Cosmetics",
            "product_description": "A white label perfume range for daily wear.", "campaign_hook": "Show the unboxing and first spritz.",
            "key_message": "Long lasting everyday fragrance.", "brief_type": "Reel", "video_format": "Reel", "aspect_ratio": "9:16",
            "duration_seconds": 30, "creator_level": "New", "content_quality_tier": "standard", "brief_text": "Authentic unboxing.",
            "target_audience": "Women 20-35 who enjoy fragrances and daily self care routines.", "objectives": ["Awareness"],
            "tone_tags": ["warm"], "free_revisions": 2, "revision_limit": 2, "due_date": "2027-01-20", "deadline": "2027-01-20",
            "currency": "INR", "product_type": "digital", "requires_shipment": False, "shipment_option": "no",
            "draft_delivery_by": "2027-01-20", "budget_min": budget, "budget_max": budget, "per_video_budget": budget, "total_budget": budget,
            "selected_creator": creator, "visibility": "private",
            "deliverable_items": [{"type": "Reel", "quantity": 1, "duration": "30 seconds", "aspect_ratios": ["9:16"],
                                   "raw_required": True, "edited_required": False}],
        }
        orig_id = call("POST", "/campaigns", brand_t, json=payload).json()["campaign_id"]
        call("POST", "/admin/approve-campaign", admin_t, json={"item_id": orig_id, "action": "approve"})
        inv = run(server.db.chat_action_cards.find_one({"type": "private_invitation", "deal_id": orig_id}, {"_id": 0}))
        card = call("POST", "/chat/action-cards", creator_t, json={"recipient_id": brand, "type": "counter_offer", "deal_id": orig_id if explicit else None, "fields": {
            "modified_price": price, "revisions": "1", "timeline": "2027-02-10", "usage_rights": "Organic social",
            "diff_vs_original": "A different price because the brief asks for custom set design and a long script." * 2}}).json()["action_card"]
        if not explicit:
            call("POST", f"/chat/action-cards/{inv['id']}/respond", creator_t, json={"action": "counter"})
        if wallet is not None:
            run(server.db.users.update_one({"id": brand}, {"$set": {"balance": wallet}}))
        before = balance()
        resp = call("POST", f"/chat/action-cards/{card['id']}/respond", brand_t, json={"action": "accept"})
        return orig_id, before, resp

    def my_deals():
        out = call("GET", "/deals/my", creator_t).json()
        return out if isinstance(out, list) else out.get("deals", [])

    yield type("Env", (), dict(run=run, db=server.db, counter_and_accept=staticmethod(counter_and_accept),
                               balance=staticmethod(balance), my_deals=staticmethod(my_deals), creator=creator,
                               brand=brand, brand_t=brand_t, call=staticmethod(call)))
    loop.close()


def test_accepted_counter_is_the_only_deal(env):
    orig_id, before, resp = env.counter_and_accept(3000)
    assert resp.status_code == 200, resp.text
    campaigns = env.run(env.db.campaigns.find({}, {"_id": 0}).to_list(50))
    assert [c["id"] for c in campaigns] == [orig_id]          # no second "Direct deal"
    assert campaigns[0]["status"] == server.CampaignStatus.IN_PROGRESS
    assert campaigns[0]["total_budget"] == 3000
    held = env.run(env.db.escrow.find({"status": "held"}, {"_id": 0}).to_list(10))
    assert len(held) == 1 and held[0]["amount"] == 3000
    assert env.run(env.db.escrow.count_documents({"status": "reserved"})) == 0   # reservation consumed
    assert len(env.my_deals()) == 1


def test_brand_pays_only_the_difference_from_the_reserved_budget(env):
    orig_id, before, _ = env.counter_and_accept(3000)
    # publishing reserved the brief's 1000; the counter costs 3000 + 600 fee, so only 2600 more is charged
    assert env.balance() == pytest.approx(before - (3000 + server.brand_commission(3000) - 1000))


def test_lower_counter_refunds_the_surplus(env):
    orig_id, before, resp = env.counter_and_accept(2500, budget=5000)   # 2500 + 500 fee < 5000 reserved
    assert resp.status_code == 200, resp.text
    assert env.balance() == pytest.approx(before + 5000 - (2500 + server.brand_commission(2500)))
    assert len(env.my_deals()) == 1


def test_short_wallet_asks_for_top_up_and_creates_nothing(env):
    orig_id, before, resp = env.counter_and_accept(3000, wallet=10)
    assert resp.status_code == 402
    campaign = env.run(env.db.campaigns.find_one({"id": orig_id}, {"_id": 0}))
    assert campaign["status"] != server.CampaignStatus.IN_PROGRESS
    assert env.run(env.db.escrow.count_documents({"status": "held"})) == 0



def test_explicit_counter_keeps_original_campaign_and_agreed_date(env):
    orig_id, _, resp = env.counter_and_accept(3000, explicit=True)
    assert resp.status_code == 200, resp.text
    campaigns = env.run(env.db.campaigns.find({}, {"_id": 0}).to_list(50))
    assert len(campaigns) == 1 and campaigns[0]["id"] == orig_id
    assert campaigns[0]["deadline"] == "2027-02-10"
    assert campaigns[0]["draft_delivery_by"] == "2027-02-10"


def test_creator_is_notified_when_the_brand_sends_a_counter_offer(env):
    """A brand-sent counter used to reach the creator with no notification at all."""
    resp = env.call("POST", "/chat/action-cards", env.brand_t, json={"recipient_id": env.creator, "type": "counter_offer", "fields": {
        "modified_price": 2500, "revisions": "1", "timeline": "7 days", "usage_rights": "Organic social",
        "diff_vs_original": "The timeline is tight and we need a slightly higher price for it."}})
    assert resp.status_code == 200, resp.text
    notes = env.run(env.db.in_app_notifications.find({"user_id": env.creator, "title": "You've received a counteroffer"}).to_list(5))
    assert len(notes) == 1 and "2,500" in notes[0]["message"] and notes[0]["link"] == f"/messages?conv={env.brand}"


def test_header_unread_badge_matches_the_messages_list(env):
    env.run(env.db.messages.insert_many([
        {"id": "m1", "sender_id": env.creator, "recipient_id": env.brand, "content": "hi", "read": False, "created_at": "2027-01-01T00:00:00+00:00"},
        {"id": "m2", "sender_id": "system", "recipient_id": env.brand, "content": "welcome", "read": False, "created_at": "2027-01-01T00:00:01+00:00"},
    ]))
    badge = env.call("GET", "/chat/unread-count", env.brand_t).json()["unread_count"]
    listed = sum(c["unread_count"] for c in env.call("GET", "/chat/conversations", env.brand_t).json())
    assert badge == listed == 1


def test_login_accepts_email_or_the_mobile_number(env):
    # The fixture gives the brand and creator one shared number; a shared number must NOT sign in.
    assert env.call("POST", "/auth/login", json={"email": "9876546001", "password": "Passw0rd!x"}).status_code == 401
    env.run(env.db.users.update_one({"id": env.creator}, {"$set": {"phone": "9000000000"}}))
    by_email = env.call("POST", "/auth/login", json={"email": "pc-business-1@example.com", "password": "Passw0rd!x"})
    by_phone = env.call("POST", "/auth/login", json={"email": "+91 98765 46001", "password": "Passw0rd!x"})
    wrong = env.call("POST", "/auth/login", json={"email": "9876546001", "password": "nope"})
    assert by_email.status_code == by_phone.status_code == 200
    assert by_phone.json()["user_id"] == by_email.json()["user_id"] == env.brand
    assert wrong.status_code == 401


def test_creator_deals_list_newest_first(env):
    def camp(cid, when):
        return {"id": cid, "title": cid, "status": "active", "business_id": env.brand, "selected_creator": env.creator,
                "selected_creators": [env.creator], "created_at": when, "updated_at": when, "visibility": "public"}
    env.run(env.db.campaigns.insert_many([camp("old", "2026-01-01T00:00:00+00:00"), camp("newest", "2026-10-01T00:00:00+00:00"),
                                          camp("mid", "2026-05-01T00:00:00+00:00")]))
    creator_t = env.call("POST", "/auth/login", json={"email": "pc-creator-1@example.com", "password": "Passw0rd!x"}).json()["token"]
    rows = env.call("GET", "/deals/my", creator_t).json()
    assert [r["campaign"]["id"] for r in rows] == ["newest", "mid", "old"]


def test_nobody_can_bid_on_a_private_brief(env, monkeypatch):
    monkeypatch.setattr(server, "creator_profile_missing", lambda user: [])  # get past the profile gate
    env.run(env.db.campaigns.insert_one({"id": "pb", "title": "Private tee", "status": "active", "visibility": "private",
                                         "business_id": env.brand, "selected_creator": env.creator, "selected_creators": [env.creator]}))
    creator_t = env.call("POST", "/auth/login", json={"email": "pc-creator-1@example.com", "password": "Passw0rd!x"}).json()["token"]
    resp = env.call("POST", "/campaigns/pb/bid", creator_t, json={"campaign_id": "pb", "amount": 1000, "proposal": "I would love to do this", "estimated_delivery_days": 3})
    assert resp.status_code == 400 and "private brief" in resp.text
    assert env.run(env.db.campaigns.find_one({"id": "pb"})).get("bids") in (None, [])
