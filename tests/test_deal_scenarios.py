"""Ten deal types, end to end, against the real FastAPI routes and an in-memory database.

    1 Private brief (raw)                        2 Private brief (raw + edit)
    3 Single creator (raw)                       4 Single creator (raw + edit)
    5 Multiple creators (raw)                    6 Multiple creators (raw + edit)
    7 Single creator, several deliverables (raw) 8 ... (raw + edit)
    9 Single creator, qty 3 of one deliverable   10 ... (raw + edit)

"raw + edit" means the brand asked for an edited cut as well. The owner's wording is
"edited by UGC.ad", so the primary variant is edited_by="ugc". The creator-edits variant
(edited_by="creator", paid via editing_fee_per_video) is covered next to it because the
same fields drive escrow and the state machine differently.

Nothing here touches a real database: `server.db` is replaced by mongomock-motor, e-mail is
disabled and no network call is made. Run with the env recipe in TESTER_REPORT.md.

Tests that demonstrate a production bug are marked xfail(strict=False, reason="BUG: ...").
"""
import asyncio
import copy
import uuid

import pytest

pytest.importorskip("mongomock_motor")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402
from mongomock_motor import AsyncMongoMockClient  # noqa: E402

import campaign_helpers as ch  # noqa: E402
import server  # noqa: E402

FULL_PROFILE = {
    "age": 24, "gender": "female", "bodyType": "slim", "skinTone": "medium",
    "city": "Indore", "state": "MP", "pincode": "452010", "languages": ["Hindi", "English"],
}
RAW_ONLY = dict(raw_required=True, edited_required=False)
UGC_EDIT = dict(raw_required=True, edited_required=True, edited_by="ugc")
CREATOR_EDIT = dict(raw_required=True, edited_required=True, edited_by="creator")


def row(kind="Reel", quantity=1, **flags):
    return {"type": kind, "quantity": quantity, "duration": "30 seconds", "aspect_ratios": ["9:16"],
            **(flags or RAW_ONLY)}


# ---------------------------------------------------------------------------------------------
# Scenario table. Every scenario is a dict of the real campaign fields it maps to.
# ---------------------------------------------------------------------------------------------
def scenario(rows, creators=1, private=False):
    return {"rows": rows, "creators": creators, "private": private}


SCENARIOS = {
    1: scenario([row(**RAW_ONLY)], private=True),
    2: scenario([row(**UGC_EDIT)], private=True),
    3: scenario([row(**RAW_ONLY)]),
    4: scenario([row(**UGC_EDIT)]),
    5: scenario([row(**RAW_ONLY)], creators=3),
    6: scenario([row(**UGC_EDIT)], creators=3),
    7: scenario([row("Reel", 1, **RAW_ONLY), row("Static post", 1, **RAW_ONLY)]),
    8: scenario([row("Reel", 1, **UGC_EDIT), row("Static post", 1, **UGC_EDIT)]),
    9: scenario([row("Reel", 3, **RAW_ONLY)]),
    10: scenario([row("Reel", 3, **UGC_EDIT)]),
}
PER_VIDEO = 1000.0          # the brand's per-asset budget (private briefs: the creator's own rate)
EDIT_FEE = 300.0            # editing_fee_per_video, only paid for creator-edited rows


def qty(sc):
    return sum(r["quantity"] for r in sc["rows"])


def expected_fee(sc):
    if sc["creators"] >= 11:
        return 3000.0
    if sc["creators"] > 1:
        return 1500.0
    return 1500.0 if qty(sc) > 1 else 500.0


def expected_slot(sc, editing_fee=0.0):
    edited = sum(r["quantity"] for r in sc["rows"] if r.get("edited_required") and r.get("edited_by") == "creator")
    return PER_VIDEO * qty(sc) + editing_fee * edited


def is_edit(sc):
    return any(r.get("edited_required") for r in sc["rows"])


# ---------------------------------------------------------------------------------------------
# World: users, token helpers and one method per step of the deal.
# ---------------------------------------------------------------------------------------------
class World:
    def __init__(self, monkeypatch):
        monkeypatch.setenv("RESEND_API_KEY", "")
        monkeypatch.setattr(server, "db", AsyncMongoMockClient()["deals_" + uuid.uuid4().hex[:8]])
        self.db = server.db
        self.loop = asyncio.new_event_loop()
        self.run = self.loop.run_until_complete
        self.client = TestClient(server.app, follow_redirects=False)
        self.n = 0
        self.run(self.db.users.insert_one({
            "id": "adm", "email": "adm@example.com", "role": "admin", "admin_role": "super_admin",
            "approval_status": "approved", "profile_completed": True}))
        self.admin_t = server.create_token("adm", "adm@example.com", "admin")
        self.brand_t, self.brand = self.add_brand()

    def close(self):
        self.loop.close()

    # -- plumbing ---------------------------------------------------------------------------
    def call(self, method, path, token=None, **kw):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.client.request(method, "/api" + path, headers=headers, **kw)

    def add_brand(self, balance=1_000_000.0):
        self.n += 1
        uid = f"brand-{self.n}"
        self.run(self.db.users.insert_one({
            "id": uid, "email": f"{uid}@example.com", "role": "business", "nickname": f"Brand{self.n}",
            "approval_status": "approved", "profile_completed": True, "balance": balance,
            "profile": {"business_name": f"Brand {self.n}"}}))
        return server.create_token(uid, f"{uid}@example.com", "business"), uid

    def add_creator(self, rate=PER_VIDEO, editing=EDIT_FEE):
        self.n += 1
        uid = f"creator-{self.n}"
        doc = {
            "id": uid, "email": f"{uid}@example.com", "role": "creator", "nickname": f"cr{self.n}",
            "approval_status": "approved", "profile_completed": True, "balance": 0.0,
            "kyc": {"status": "verified"}, "profile_photo": "/uploads/me.jpg", "portfolio": ["/uploads/i.mp4"],
            "profile": {**copy.deepcopy(FULL_PROFILE),
                        "rate_card": {"raw_payout": str(int(rate)), "editing_payout": str(int(editing))}},
        }
        self.run(self.db.users.insert_one(doc))
        return server.create_token(uid, doc["email"], "creator"), uid

    def balance(self, uid):
        return round((self.run(self.db.users.find_one({"id": uid})) or {}).get("balance") or 0, 2)

    def set_balance(self, uid, amount):
        self.run(self.db.users.update_one({"id": uid}, {"$set": {"balance": amount}}))

    def campaign(self, cid):
        return self.run(self.db.campaigns.find_one({"id": cid}, {"_id": 0}))

    def escrows(self, cid):
        return self.run(self.db.escrow.find({"campaign_id": cid}, {"_id": 0}).to_list(50))

    # -- brief ------------------------------------------------------------------------------
    def payload(self, sc, **over):
        body = {
            "status": "pending_approval", "title": "Scenario brief", "product_name": "Serum",
            "product_category": "Beauty & Cosmetics", "category": "Beauty & Cosmetics",
            "product_description": "A vitamin C serum for everyday use.",
            "campaign_hook": "Show the first application.", "key_message": "Glow in a week.",
            "brief_type": "Reel", "video_format": "Reel", "aspect_ratio": "9:16", "duration_seconds": 30,
            "creator_level": "New", "content_quality_tier": "standard", "brief_text": "Authentic review.",
            "target_audience": "Women 20-35 who care about skincare routines.", "objectives": ["Awareness"],
            "tone_tags": ["warm"], "free_revisions": 2, "revision_limit": 2,
            "due_date": "2027-01-20", "deadline": "2027-01-20", "draft_delivery_by": "2027-01-20",
            "final_delivery_by": "2027-02-10" if is_edit(sc) else None,
            "currency": "INR", "product_type": "digital", "requires_shipment": False, "shipment_option": "no",
            "budget_mode": "fixed", "budget_min": PER_VIDEO, "budget_max": PER_VIDEO, "per_video_budget": PER_VIDEO,
            "deliverable_items": copy.deepcopy(sc["rows"]),
        }
        if not is_edit(sc):
            body.pop("final_delivery_by")
        if any(r.get("edited_by") == "creator" and r.get("edited_required") for r in sc["rows"]):
            body["editing_fee_per_video"] = EDIT_FEE
        if sc["creators"] > 1:
            body["creators_wanted"] = sc["creators"]
        body.update(over)
        return body

    def publish(self, sc, token=None, **over):
        return self.call("POST", "/campaigns", token or self.brand_t, json=self.payload(sc, **over))

    def approve(self, cid):
        return self.call("POST", "/admin/approve-campaign", self.admin_t, json={"item_id": cid, "action": "approve"})

    # -- public hiring ----------------------------------------------------------------------
    def bid(self, cid, token, amount=PER_VIDEO, **kw):
        return self.call("POST", f"/campaigns/{cid}/bid", token, json={
            "campaign_id": cid, "amount": amount, "proposal": "I can do this well", "estimated_delivery_days": 5, **kw})

    def hire(self, cid, creator_id, token=None):
        return self.call("POST", f"/campaigns/{cid}/select-creator?creator_id={creator_id}", token or self.brand_t)

    # -- delivery ---------------------------------------------------------------------------
    def submit(self, cid, token, index=0, url=None):
        return self.call("POST", f"/deals/{cid}/content", token, json={
            "video_url": url or f"https://cdn.example.com/{uuid.uuid4().hex}.mp4", "deliverable_index": index})

    def works(self, cid, creator_id=None, **flt):
        q = {"campaign_id": cid, **flt}
        if creator_id:
            q["creator_id"] = creator_id
        return self.run(self.db.work_submissions.find(q, {"_id": 0}).sort("submitted_at", 1).to_list(100))

    def approve_work(self, work_id, token=None):
        return self.call("POST", f"/work/{work_id}/approve", token or self.brand_t)

    def edit_done(self, work_id):
        return self.call("POST", f"/admin/editing-queue/{work_id}/complete", self.admin_t,
                         json={"edited_file_url": f"https://cdn.example.com/edit-{work_id[:6]}.mp4"})

    def detail(self, cid, token):
        r = self.call("GET", f"/deals/{cid}/detail", token)
        assert r.status_code == 200, r.text
        return r.json()

    def ledger(self, uid, kind):
        return self.run(self.db.wallet_ledger.find({"user_id": uid, "type": kind}, {"_id": 0}).to_list(50))

    # -- whole-deal drivers -----------------------------------------------------------------
    def start(self, n, sc=None, bid_each=True, **publish_over):
        """Publish, admin-approve, then hire (public) or accept the invitation (private)."""
        sc = sc or SCENARIOS[n]
        ctx = Ctx(sc=sc, n=n, initial=self.balance(self.brand))
        if sc["private"]:
            ct, c = self.add_creator()
            ctx.creators = [(ct, c)]
            r = self.publish(sc, selected_creator=c, visibility="private", **publish_over)
            assert r.status_code == 200, r.text
            ctx.cid = r.json()["campaign_id"]
            ctx.after_publish = self.balance(self.brand)
            assert self.approve(ctx.cid).status_code == 200
            card = self.run(self.db.chat_action_cards.find_one(
                {"type": "private_invitation", "deal_id": ctx.cid}, {"_id": 0}))
            assert card, "approving a private brief must deliver the invitation card"
            ctx.card = card
            r = self.call("POST", f"/chat/action-cards/{card['id']}/respond", ct, json={"action": "accept"})
            assert r.status_code == 200, r.text
            return ctx
        ctx.creators = [self.add_creator() for _ in range(sc["creators"])]
        r = self.publish(sc, **publish_over)
        assert r.status_code == 200, r.text
        ctx.cid = r.json()["campaign_id"]
        ctx.after_publish = self.balance(self.brand)
        assert self.approve(ctx.cid).status_code == 200
        if bid_each:
            for ct, c in ctx.creators:
                self.place_bid(ctx, ct)
                r = self.hire(ctx.cid, c)
                assert r.status_code == 200, r.text
        return ctx

    def place_bid(self, ctx, token, factor=1.0):
        rows = ctx.sc["rows"]
        per = round(PER_VIDEO * factor, 2)
        if any(r.get("edited_required") and r.get("edited_by") == "creator" for r in rows):
            r = self.bid(ctx.cid, token, amount=per + EDIT_FEE, raw_amount=per, edited_amount=EDIT_FEE)
        else:
            r = self.bid(ctx.cid, token, amount=per)
        assert r.status_code == 200, r.text

    def submit_all(self, ctx, only=None):
        out = []
        for ct, c in ctx.creators:
            if only and c != only:
                continue
            for i in range(qty(ctx.sc)):
                r = self.submit(ctx.cid, ct, i)
                assert r.status_code == 200, r.text
                out.append(r.json())
        return out

    def approve_pending(self, ctx, creator_id=None, status="submitted"):
        results = []
        for wk in self.works(ctx.cid, creator_id, status=status):
            r = self.approve_work(wk["id"])
            assert r.status_code == 200, r.text
            results.append(r.json())
        return results

    def finish_edits(self, ctx, creator_id=None):
        for wk in self.works(ctx.cid, creator_id, status="awaiting_edit"):
            r = self.edit_done(wk["id"])
            assert r.status_code == 200, r.text

    def money_view(self, ctx):
        """Every rupee: brand + creators + what the platform kept + what is still in escrow."""
        esc = self.escrows(ctx.cid)
        released = [e for e in esc if e.get("status") == "released"]
        platform = sum(x["amount"] for x in self.ledger(self.brand, "listing_fee"))
        platform += sum(float(e.get("brand_commission_amount") or 0) + float(e.get("commission_amount") or 0)
                        + float(e.get("tds_amount") or 0) + float(e.get("penalty_amount") or 0) for e in released)
        in_escrow = sum(float(e.get("brand_charged") or e.get("reserved_amount") or e.get("amount") or 0)
                        for e in esc if e.get("status") in ("held", "reserved", "on_hold"))
        refunded_pool = 0.0
        brand = self.balance(self.brand)
        creators = sum(self.balance(c) for _, c in ctx.creators)
        return {"brand": brand, "creators": creators, "platform": round(platform, 2),
                "in_escrow": round(in_escrow, 2), "sum": round(brand + creators + platform + in_escrow + refunded_pool, 2),
                "escrows": esc}


class Ctx:
    def __init__(self, sc, n, initial):
        self.sc, self.n, self.initial = sc, n, initial
        self.creators, self.cid, self.after_publish, self.card = [], None, None, None


@pytest.fixture
def w(monkeypatch):
    world = World(monkeypatch)
    yield world
    world.close()


def gross_each(sc):
    """What one hired creator is paid before the 20% creator commission (PER_VIDEO x assets)."""
    return PER_VIDEO * qty(sc) + (EDIT_FEE * sum(r["quantity"] for r in sc["rows"]
                                                 if r.get("edited_required") and r.get("edited_by") == "creator"))


# ---------------------------------------------------------------------------------------------
# The ten scenario classes share the checks below. A subclass only sets N.
# ---------------------------------------------------------------------------------------------
class _Base:
    N = 0

    @property
    def sc(self):
        return SCENARIOS[self.N]

    # ---- (a) creation / validation / storage ----------------------------------------------
    def test_a_creation_stores_the_right_fields(self, w):
        sc = self.sc
        ct, c = w.add_creator()
        over = {"selected_creator": c, "visibility": "private"} if sc["private"] else {}
        r = w.publish(sc, **over)
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "pending_approval"
        stored = w.campaign(r.json()["campaign_id"])
        assert stored["status"] == "pending_approval"
        assert [(x["type"], x["quantity"], x["raw_required"], x["edited_required"]) for x in stored["deliverable_items"]] == \
               [(x["type"], x["quantity"], x["raw_required"], x["edited_required"]) for x in sc["rows"]]
        for stored_row, row_ in zip(stored["deliverable_items"], sc["rows"]):
            assert (stored_row.get("edited_by") or "creator") == (row_.get("edited_by") or "creator")
        assert server.total_deliverable_quantity(stored) == qty(sc)
        assert server.campaign_creators_wanted(stored) == (1 if sc["private"] else sc["creators"])
        assert stored["per_video_budget"] == PER_VIDEO
        if sc["private"]:
            assert stored["visibility"] == "private" and stored["selected_creator"] == c
            assert stored["creators_wanted"] == 1
        else:
            assert stored.get("visibility") in (None, "public")
            assert not stored.get("selected_creator")
        assert stored["business_id"] == w.brand and stored["created_by"] == w.brand
        # admin approval makes a normal brief ACTIVE
        assert w.approve(stored["id"]).status_code == 200
        assert w.campaign(stored["id"])["status"] == "active"

    @pytest.mark.parametrize("patch, status", [
        ({"deliverable_items": []}, 400),                       # nothing to deliver
        ({"title": ""}, 400),                                   # required field blank
        ({"creators_wanted": 0}, 422),                          # at least one creator
        ({"deliverable_items": [{"type": "Reel", "quantity": 0, "raw_required": True}]}, 422),
        ({"deliverable_items": [{"type": "Reel", "quantity": 6, "raw_required": True}]}, 422),   # wizard cap is 5
    ])
    def test_a_invalid_briefs_are_rejected_and_charge_nothing(self, w, patch, status):
        before = w.balance(w.brand)
        r = w.publish(self.sc, **patch)
        assert r.status_code == status, r.text
        assert w.balance(w.brand) == before
        assert w.run(w.db.escrow.count_documents({})) == 0

    def test_a_draft_then_submit_costs_the_same_as_publishing_directly(self, w):
        sc = self.sc
        ct, c = w.add_creator()
        over = {"selected_creator": c, "visibility": "private"} if sc["private"] else {}
        before = w.balance(w.brand)
        body = w.payload(sc, **over)
        body.pop("status")
        r = w.call("POST", "/campaigns/draft", w.brand_t, json=body)
        assert r.status_code == 200, r.text
        cid = r.json()["campaign_id"]
        assert w.balance(w.brand) == before            # a draft holds nothing
        r = w.call("POST", f"/campaigns/{cid}/submit", w.brand_t)
        assert r.status_code == 200, r.text
        slot = expected_slot(sc, EDIT_FEE)
        assert before - w.balance(w.brand) == pytest.approx(slot * (1 if sc["private"] else sc["creators"]) + expected_fee(sc))

    # ---- (b) listing fee ----------------------------------------------------------------------
    def test_b_listing_fee_tier(self, w):
        sc = self.sc
        ct, c = w.add_creator()
        over = {"selected_creator": c, "visibility": "private"} if sc["private"] else {}
        r = w.publish(sc, **over)
        cid = r.json()["campaign_id"]
        stored = w.campaign(cid)
        assert server.campaign_listing_fee(stored) == expected_fee(sc)
        fee_rows = w.ledger(w.brand, "listing_fee")
        assert len(fee_rows) == 1 and fee_rows[0]["amount"] == expected_fee(sc)
        assert fee_rows[0]["campaign_id"] == cid and fee_rows[0]["direction"] == "debit"

    # ---- (c) budget and escrow ---------------------------------------------------------------
    def test_c_budget_hold_and_wallet_debit_at_publish(self, w):
        sc = self.sc
        ct, c = w.add_creator()
        over = {"selected_creator": c, "visibility": "private"} if sc["private"] else {}
        before = w.balance(w.brand)
        cid = w.publish(sc, **over).json()["campaign_id"]
        stored = w.campaign(cid)
        creators = 1 if sc["private"] else sc["creators"]
        slot = expected_slot(sc, EDIT_FEE)
        assert server.campaign_slot_budget(stored) == slot
        assert server.campaign_budget_total(stored) == slot * creators
        [pool] = w.escrows(cid)
        assert (pool["status"], pool["creator_id"]) == ("reserved", None)
        assert pool["amount"] == pool["reserved_amount"] == slot * creators
        assert pool["slot_amount"] == slot and pool["slots_total"] == creators and pool["slots_filled"] == 0
        assert before - w.balance(w.brand) == slot * creators + expected_fee(sc)

    def test_c_publish_with_too_little_wallet_is_refused_without_side_effects(self, w):
        sc = self.sc
        ct, c = w.add_creator()
        over = {"selected_creator": c, "visibility": "private"} if sc["private"] else {}
        need = expected_slot(sc, EDIT_FEE) * (1 if sc["private"] else sc["creators"])
        # enough for the hold but NOT for the listing fee -> the hold must be rolled back
        w.set_balance(w.brand, need + expected_fee(sc) - 1)
        r = w.publish(sc, **over)
        assert r.status_code == 400, r.text
        assert w.balance(w.brand) == need + expected_fee(sc) - 1
        assert w.run(w.db.escrow.count_documents({"status": "reserved"})) == 0 or \
            w.run(w.db.escrow.count_documents({"status": "refunded"})) == 1

    # ---- (e) content: slots, indexes, duplicates --------------------------------------------
    def test_e_required_count_and_slot_rules(self, w):
        sc = self.sc
        ctx = w.start(self.N)
        ct, c = ctx.creators[0]
        d = w.detail(ctx.cid, ct)
        assert d["content_submission"]["required_count"] == qty(sc)
        assert d["content_submission"]["submitted_count"] == 0
        for bad in (qty(sc), qty(sc) + 4, -1):
            r = w.submit(ctx.cid, ct, bad)
            assert r.status_code == 400, (bad, r.text)
            assert "out of range" in r.text or "Missing required assets" in r.text   # edited briefs report the missing raw file first
        assert w.works(ctx.cid, c) == []
        for i in range(qty(sc)):
            assert w.submit(ctx.cid, ct, i).status_code == 200
            assert w.detail(ctx.cid, ct)["content_submission"]["submitted_count"] == i + 1
        # same slot again: no second row, no second work item
        rows_before = len(w.works(ctx.cid, c))
        r = w.submit(ctx.cid, ct, 0)
        assert r.status_code == 200 and "already submitted" in r.json()["message"].lower()
        assert len(w.works(ctx.cid, c)) == rows_before == qty(sc)
        assert sorted(x["deliverable_index"] for x in w.works(ctx.cid, c)) == list(range(qty(sc)))

    # ---- (g) money ---------------------------------------------------------------------------
    def test_g_full_deal_pays_every_creator_and_no_money_is_created_or_lost(self, w):
        sc = self.sc
        ctx = w.start(self.N)
        w.submit_all(ctx)
        w.approve_pending(ctx)
        if is_edit(sc) and not any(r.get("edited_by") == "creator" for r in sc["rows"]):
            w.finish_edits(ctx)
            w.approve_pending(ctx)
        view = w.money_view(ctx)
        g = gross_each(sc)
        creators = 1 if sc["private"] else sc["creators"]
        assert len(ctx.creators) == creators
        for _, c in ctx.creators:
            assert w.balance(c) == pytest.approx(g * 0.8)                       # 20% creator commission
        assert view["in_escrow"] == 0
        assert view["sum"] == pytest.approx(ctx.initial)                        # nothing created, nothing lost
        assert view["platform"] == pytest.approx(expected_fee(sc) + creators * g * 0.4)
        assert all(e["status"] == "released" for e in view["escrows"])
        assert w.campaign(ctx.cid)["status"] == "completed"
        assert w.balance(w.brand) >= 0


# Mixins -------------------------------------------------------------------------------------
class _PublicExtras:
    """Applying, hiring, bid ceiling and the refund of what a cheaper bid leaves unused."""

    def test_d_apply_and_hire_flow(self, w):
        sc = self.sc
        ctx = w.start(self.N)
        stored = w.campaign(ctx.cid)
        assert sorted(stored["selected_creators"]) == sorted(c for _, c in ctx.creators)
        assert stored["status"] == "in_progress"
        assert len(stored["bids"]) == sc["creators"]
        assert all(b["deliverable_quantity"] == qty(sc) for b in stored["bids"])
        held = [e for e in w.escrows(ctx.cid) if e["status"] == "held"]
        assert sorted(e["creator_id"] for e in held) == sorted(c for _, c in ctx.creators)
        g = gross_each(sc)
        for e in held:
            assert e["amount"] == g and e["brand_charged"] == g * 1.2 and e["brand_commission_amount"] == g * 0.2
        # the pool is fully consumed, the brand paid reserve + commission + listing fee
        assert not [e for e in w.escrows(ctx.cid) if e["status"] == "reserved"]
        assert ctx.initial - w.balance(w.brand) == pytest.approx(sc["creators"] * g * 1.2 + expected_fee(sc))

    def test_d_slot_cap_and_double_hire(self, w):
        sc = self.sc
        ctx = w.start(self.N, bid_each=False)
        extra = [w.add_creator() for _ in range(2)]
        everyone = ctx.creators + extra
        for ct, _ in everyone:
            w.place_bid(ctx, ct)
        for ct, c in ctx.creators:
            assert w.hire(ctx.cid, c).status_code == 200
        # every slot is taken: further hires are refused, with or without a bid
        for ct, c in extra:
            r = w.hire(ctx.cid, c)
            assert r.status_code == 400 and "slot" in r.text.lower(), r.text
        r = w.hire(ctx.cid, ctx.creators[0][1])
        assert r.status_code == 400 and "already" in r.text.lower()
        assert len(w.campaign(ctx.cid)["selected_creators"]) == sc["creators"]
        assert len([e for e in w.escrows(ctx.cid) if e["status"] == "held"]) == sc["creators"]

    def test_d_non_bidder_cannot_be_hired_and_late_bids_are_closed(self, w):
        ctx = w.start(self.N)
        ct, c = w.add_creator()
        assert w.hire(ctx.cid, c).status_code == 404
        r = w.bid(ctx.cid, ct)
        assert r.status_code == 400 and "not available" in r.text

    def test_c_bid_above_the_budget_is_refused_and_at_the_ceiling_accepted(self, w):
        sc = self.sc
        ctx = w.start(self.N, bid_each=False)
        ct, c = ctx.creators[0]
        creator_edit = any(r.get("edited_by") == "creator" and r.get("edited_required") for r in sc["rows"])
        if creator_edit:
            over = w.bid(ctx.cid, ct, amount=1, raw_amount=PER_VIDEO + 1, edited_amount=EDIT_FEE)
        else:
            over = w.bid(ctx.cid, ct, amount=PER_VIDEO + 1)
        assert over.status_code == 400 and "cannot exceed" in over.text
        w.place_bid(ctx, ct)                                    # exactly at the ceiling
        stored = w.campaign(ctx.cid)
        assert stored["bids"][0]["amount"] == gross_each(sc)    # bid amount is the total for ALL assets

    def test_g_cheaper_bid_returns_the_unused_part_of_the_hold(self, w):
        sc = self.sc
        ctx = w.start(self.N, bid_each=False)
        ct, c = ctx.creators[0]
        w.place_bid(ctx, ct, factor=0.8)
        before = w.balance(w.brand)
        r = w.hire(ctx.cid, c)
        assert r.status_code == 200, r.text
        slot = expected_slot(sc, EDIT_FEE)
        deal = round(gross_each(sc) - 0.2 * PER_VIDEO * qty(sc), 2)      # only the raw part shrinks
        if any(x.get("edited_by") == "creator" and x.get("edited_required") for x in sc["rows"]):
            deal = round(0.8 * PER_VIDEO * qty(sc) + EDIT_FEE * qty(sc), 2)
        charged = round(deal * 1.2, 2)
        refund = round(slot - charged, 2)
        assert refund > 0
        assert w.balance(w.brand) == pytest.approx(before + refund)
        assert r.json()["amount_charged"] == charged and r.json()["funded"] is True

    def test_g_rejected_brief_gets_the_hold_back_but_not_the_listing_fee(self, w):
        sc = self.sc
        before = w.balance(w.brand)
        cid = w.publish(sc).json()["campaign_id"]
        r = w.call("POST", "/admin/approve-campaign", w.admin_t, json={"item_id": cid, "action": "reject", "reason": "no"})
        assert r.status_code == 200, r.text
        assert before - w.balance(w.brand) == expected_fee(sc)          # hold refunded, fee kept
        assert [e["status"] for e in w.escrows(cid)] == ["refunded"]


class _MultiCreatorExtras:
    """More than one creator: each has their own escrow, deal and payout."""

    def test_d_one_creators_approval_never_pays_the_others(self, w):
        sc = self.sc
        ctx = w.start(self.N)
        (a_t, a), (b_t, b), (c_t, c3) = ctx.creators
        w.submit_all(ctx, only=a)
        w.approve_pending(ctx, a)
        if is_edit(sc):
            w.finish_edits(ctx, a)
            w.approve_pending(ctx, a)
        assert w.balance(a) == pytest.approx(gross_each(sc) * 0.8)
        assert w.balance(b) == 0 and w.balance(c3) == 0
        by = {e["creator_id"]: e["status"] for e in w.escrows(ctx.cid)}
        assert by == {a: "released", b: "held", c3: "held"}
        assert w.campaign(ctx.cid)["status"] != "completed"             # two creators still owe work
        # B's deal is still waiting for content
        assert w.detail(ctx.cid, b_t)["current_state"] == "Received - Content in Progress"

    def test_g_finish_hiring_early_refunds_only_the_unfilled_slots(self, w):
        sc = self.sc
        ctx = w.start(self.N, bid_each=False)
        for ct, _ in ctx.creators[:2]:
            w.place_bid(ctx, ct)
        for _, c in ctx.creators[:2]:
            assert w.hire(ctx.cid, c).status_code == 200
        before = w.balance(w.brand)
        r = w.call("POST", f"/campaigns/{ctx.cid}/finish-hiring", w.brand_t)
        assert r.status_code == 200, r.text
        slot = expected_slot(sc, EDIT_FEE)
        assert w.balance(w.brand) == pytest.approx(before + slot)       # exactly one unfilled slot
        stored = w.campaign(ctx.cid)
        assert stored["creators_wanted"] == 2 and stored["status"] == "in_progress"
        refunds = w.ledger(w.brand, "budget_refund")
        assert len(refunds) == 1 and refunds[0]["amount"] == slot
        # a second call has nothing to close
        assert w.call("POST", f"/campaigns/{ctx.cid}/finish-hiring", w.brand_t).status_code == 400
        # and the two hired creators still get paid in full
        w.submit_all(ctx, only=ctx.creators[0][1])
        w.submit_all(ctx, only=ctx.creators[1][1])
        w.approve_pending(ctx)
        if is_edit(sc):
            w.finish_edits(ctx)
            w.approve_pending(ctx)
        view = w.money_view(ctx)
        assert view["in_escrow"] == 0 and w.campaign(ctx.cid)["status"] == "completed"
        both = sum(w.balance(c) for _, c in ctx.creators[:2])
        assert both == pytest.approx(2 * gross_each(sc) * 0.8)
        assert view["brand"] + both + view["platform"] == pytest.approx(ctx.initial)


# What the brief wizard shows the brand, scenario by scenario (hold, 20% fee, listing fee, total).
# The same table is asserted against the website code in src/utils/dealScenarios.test.js.
CALC_TABLE = {
    1: dict(hold=1000, commission=200, listing=500, total=1700),
    2: dict(hold=1000, commission=200, listing=500, total=1700),
    3: dict(hold=1000, commission=200, listing=500, total=1700),
    4: dict(hold=1000, commission=200, listing=500, total=1700),
    5: dict(hold=3000, commission=600, listing=1500, total=5100),
    6: dict(hold=3000, commission=600, listing=1500, total=5100),
    7: dict(hold=2000, commission=400, listing=1500, total=3900),
    8: dict(hold=2000, commission=400, listing=1500, total=3900),
    9: dict(hold=3000, commission=600, listing=1500, total=5100),
    10: dict(hold=3000, commission=600, listing=1500, total=5100),
}

PRIVATE_BUG = ("BUG: accepting a private brief leaves the escrow 'reserved' with creator_id=None "
               "(activate_deal_from_card returns early, server.py ~l.8944-8951), so approval pays nothing")


def xfail_copy(fn, reason):
    """Same test body, xfail mark on a private copy so the shared test is not marked everywhere."""
    def wrapper(self, w):
        return fn(self, w)
    wrapper.__name__ = fn.__name__
    return pytest.mark.xfail(strict=False, reason=reason)(wrapper)


class _PayoutAndCalc:
    def test_e_payout_waits_for_every_slot(self, w):
        sc = self.sc
        ctx = w.start(self.N)
        ct, c = ctx.creators[0]
        w.submit_all(ctx, only=c)
        works = w.works(ctx.cid, c)
        assert len(works) == qty(sc)
        for wk in works[:-1]:
            r = w.approve_work(wk["id"])
            assert r.status_code == 200
            if qty(sc) > 1:
                assert r.json()["payout_status"] == "awaiting_remaining_deliverables"
        if qty(sc) > 1:
            assert w.balance(c) == 0
            assert [e["status"] for e in w.escrows(ctx.cid) if e["creator_id"] == c] == ["held"]
            # approving the same slot twice must not count it twice
            again = w.approve_work(works[0]["id"])
            assert again.status_code == 200 and w.balance(c) == 0
        last = w.approve_work(works[-1]["id"])
        assert last.status_code == 200
        assert w.balance(c) == pytest.approx(gross_each(sc) * 0.8)
        # a re-approval never pays twice
        w.approve_work(works[-1]["id"])
        assert w.balance(c) == pytest.approx(gross_each(sc) * 0.8)

    def test_h_wizard_numbers_match_the_backend(self, w):
        sc = self.sc
        stored = {"deliverable_items": sc["rows"], "per_video_budget": PER_VIDEO,
                  "creators_wanted": 1 if sc["private"] else sc["creators"]}
        t = CALC_TABLE[self.N]
        hold = server.campaign_budget_total(stored)
        assert hold == t["hold"]
        assert round(server.brand_commission(hold)) == t["commission"]
        assert server.campaign_listing_fee(stored) == t["listing"]
        assert hold + round(server.brand_commission(hold)) + server.campaign_listing_fee(stored) == t["total"]


class _RawOnlyExtras:
    def test_f_raw_only_deal_never_enters_the_editing_state(self, w):
        sc = self.sc
        ctx = w.start(self.N)
        ct, c = ctx.creators[0]
        d = w.detail(ctx.cid, ct)
        assert d["current_state"] == "Received - Content in Progress" and d["can_submit_content"] is True
        assert d["edit_flow"] is None
        assert d["content_submission"]["required_assets"]["raw_only"] is True
        assert d["content_submission"]["required_assets"]["raw_footage"] is False   # one file per slot
        w.submit_all(ctx, only=c)
        assert all(x["stage"] is None for x in w.works(ctx.cid, c))
        assert w.detail(ctx.cid, ct)["current_state"] == "Content Submitted - Awaiting Review"
        w.approve_pending(ctx, c)
        assert w.works(ctx.cid, c, status="awaiting_edit") == []
        q = w.call("GET", "/admin/editing-queue", w.admin_t).json()
        assert [x for x in q if x["campaign_id"] == ctx.cid] == []
        assert w.detail(ctx.cid, ct)["current_state"] == "Paid - Complete"
        # nothing more can be uploaded once the final video is approved
        r = w.submit(ctx.cid, ct, 0)
        assert r.status_code == 400 and "already approved" in r.text

    def test_f_revision_then_resubmission_then_approval(self, w):
        sc = self.sc
        ctx = w.start(self.N)
        ct, c = ctx.creators[0]
        w.submit_all(ctx, only=c)
        first = w.works(ctx.cid, c)[0]
        r = w.call("POST", f"/work/{first['id']}/request-revision", w.brand_t, json={"feedback": "Brighter lighting please"})
        assert r.status_code == 200 and r.json()["fee_charged"] == 0
        r = w.submit(ctx.cid, ct, 0)
        assert r.status_code == 200 and r.json()["version"] == 2, r.text
        w.approve_pending(ctx, c)
        assert w.balance(c) == pytest.approx(gross_each(sc) * 0.8)


class _EditExtras:
    """Raw footage first, then the edited cut by UGC.ad (edited_by='ugc')."""

    def test_f_raw_then_ugc_editing_then_delivery_then_completion(self, w):
        sc = self.sc
        ctx = w.start(self.N)
        ct, c = ctx.creators[0]
        d = w.detail(ctx.cid, ct)
        assert d["current_state"] == "Received - Content in Progress" and d["can_submit_content"] is True
        assert d["edit_flow"]["mode"] == "ugc" and d["edit_flow"]["stage"] == "raw"
        assert d["content_submission"]["required_assets"]["raw_only"] is False
        w.submit_all(ctx, only=c)
        assert {x["stage"] for x in w.works(ctx.cid, c)} == {"raw"}
        assert w.detail(ctx.cid, ct)["current_state"] == "Content Submitted - Awaiting Review"
        # approving the raws pays the creator now and sends every slot to UGC.ad
        w.approve_pending(ctx, c)
        assert w.balance(c) == pytest.approx(gross_each(sc) * 0.8)
        jobs = w.works(ctx.cid, c, status="awaiting_edit")
        assert len(jobs) == qty(sc) and sorted(j["deliverable_index"] for j in jobs) == list(range(qty(sc)))
        d = w.detail(ctx.cid, ct)
        assert d["current_state"] == "Raw Approved - UGC.ad Editing"
        assert w.campaign(ctx.cid)["status"] == "in_progress"       # not finished: the cut is still to come
        q = [x for x in w.call("GET", "/admin/editing-queue", w.admin_t).json() if x["campaign_id"] == ctx.cid]
        assert len(q) == qty(sc)
        # the creator has nothing more to upload
        r = w.submit(ctx.cid, ct, 0)
        assert r.status_code == 400 and "editing" in r.text
        # the brand cannot review or approve a cut that does not exist yet
        assert w.approve_work(jobs[0]["id"]).status_code == 400
        assert w.call("POST", f"/work/{jobs[0]['id']}/request-revision", w.brand_t, json={"feedback": "x"}).status_code == 400
        # UGC.ad delivers the cuts
        w.finish_edits(ctx, c)
        assert w.detail(ctx.cid, ct)["current_state"] == "Content Submitted - Awaiting Review"
        assert all(x["edited_files"] for x in w.works(ctx.cid, c, status="submitted"))
        # revision on the edited cut goes back to the editors, free, creator not involved
        brand_before = w.balance(w.brand)
        target = w.works(ctx.cid, c, status="submitted")[0]
        r = w.call("POST", f"/work/{target['id']}/request-revision", w.brand_t, json={"feedback": "Trim the intro"})
        assert r.status_code == 200 and r.json()["fee"] == 0
        assert w.balance(w.brand) == brand_before
        assert [x["id"] for x in w.works(ctx.cid, c, status="awaiting_edit")] == [target["id"]]
        assert w.edit_done(target["id"]).status_code == 200
        # final approval completes the brief and does not pay the creator a second time
        w.approve_pending(ctx, c)
        assert w.balance(c) == pytest.approx(gross_each(sc) * 0.8)
        assert w.campaign(ctx.cid)["status"] == ("completed" if len(ctx.creators) == 1 else "in_progress")
        assert w.detail(ctx.cid, ct)["current_state"] == "Paid - Complete"
        view = w.money_view(ctx)
        assert view["sum"] == pytest.approx(ctx.initial)

    def test_c_creator_edit_variant_pays_the_editing_fee_and_needs_two_uploads_per_slot(self, w):
        """Same scenario, but the CREATOR cuts the edit: editing_fee_per_video is held and paid."""
        base = self.sc
        sc2 = scenario([dict(r, edited_by="creator") for r in base["rows"]], base["creators"], base["private"])
        ctx = w.start(self.N, sc=sc2)
        stored = w.campaign(ctx.cid)
        creators = 1 if sc2["private"] else sc2["creators"]
        slot = (PER_VIDEO + EDIT_FEE) * qty(sc2)
        assert server.creator_editing_quantity(stored) == qty(sc2)
        assert stored["editing_fee_per_video"] == EDIT_FEE
        assert server.campaign_slot_budget(stored) == slot
        assert ctx.initial - ctx.after_publish == pytest.approx(slot * creators + expected_fee(sc2))
        for ct, c in ctx.creators:
            w.submit_all(ctx, only=c)
            assert {x["stage"] for x in w.works(ctx.cid, c)} == {"raw"}
            w.approve_pending(ctx, c)
            # raw is only step 1: no money yet, the creator now owes the edited cut
            assert w.balance(c) == 0
            d = w.detail(ctx.cid, ct)
            assert d["current_state"] == "Raw Approved - Edited Video Due" and d["can_submit_content"] is True
            assert d["edit_flow"]["stage"] == "edited"
            for i in range(qty(sc2)):
                r = w.submit(ctx.cid, ct, i)
                assert r.status_code == 200 and r.json()["stage"] == "edited", r.text
            w.approve_pending(ctx, c)
            assert w.balance(c) == pytest.approx(slot * 0.8)
        view = w.money_view(ctx)
        assert view["in_escrow"] == 0 and view["sum"] == pytest.approx(ctx.initial)
        assert w.campaign(ctx.cid)["status"] == "completed"
        assert view["platform"] == pytest.approx(expected_fee(sc2) + creators * slot * 0.4)

    def test_f_edit_mode_per_slot(self, w):
        camp = {"id": "x", "deliverable_items": [dict(row(**CREATOR_EDIT), quantity=2)]}
        assert server.edit_mode(camp) == "creator" and server.edit_mode(camp, 1) == "creator"
        assert server.edit_mode(camp, 2) is None                      # beyond the last slot
        camp["deliverable_items"][0]["edited_by"] = "ugc"
        assert server.edit_mode(camp) == "ugc"


class _MultiSlotExtras:
    """More than one asset per creator: quantities of one deliverable, or several deliverable rows."""

    def test_e_slots_map_to_rows_in_order(self, w):
        sc = self.sc
        assert server.total_deliverable_quantity({"deliverable_items": sc["rows"]}) == qty(sc)
        offset = 0
        for r_ in sc["rows"]:
            for k in range(r_["quantity"]):
                meta = ch.work_review_metadata({"deliverable_items": sc["rows"]}, {"deliverable_index": offset + k})
                assert meta["campaign_details"].get("video_format") == r_["type"]
            offset += r_["quantity"]

    @pytest.mark.xfail(strict=False, reason=(
        "BUG: /business/work-review returns ONE row per (campaign, creator) - the newest slot - and "
        "/deals/{id}/approve approves only the newest work item, so the website Work Review cannot "
        "approve slots 0..N-2 (server.py l.13190-13200, l.13005-13018)"))
    def test_e_brand_work_review_routes_can_approve_every_slot(self, w):
        sc = self.sc
        ctx = w.start(self.N)
        ct, c = ctx.creators[0]
        w.submit_all(ctx, only=c)
        rows = w.call("GET", "/business/work-review", w.brand_t).json()
        mine = [x for x in rows if x["campaignId"] == ctx.cid]
        assert len(mine) == qty(sc), f"work review shows {len(mine)} row(s) for {qty(sc)} submitted slots"
        for x in mine:
            w.call("POST", f"/deals/{x['id']}/approve", w.brand_t)
        assert w.balance(c) == pytest.approx(gross_each(sc) * 0.8)

    @pytest.mark.xfail(strict=False, reason=(
        "BUG: calling the website's approve endpoint once per slot never approves slots 0..N-2 (it always "
        "takes the newest work item), so the creator is never paid (server.py l.13005-13018)"))
    def test_e_deal_room_approve_called_per_slot_approves_every_slot(self, w):
        sc = self.sc
        ctx = w.start(self.N)
        ct, c = ctx.creators[0]
        w.submit_all(ctx, only=c)
        for _ in range(qty(sc)):
            assert w.call("POST", f"/deals/{ctx.cid}/approve", w.brand_t).status_code == 200
        assert len(w.works(ctx.cid, c, status="approved")) == qty(sc)

    @pytest.mark.xfail(strict=False, reason=(
        "BUG: can_submit_content is False as soon as slot 0 is submitted (state comes from the newest work "
        "doc), so a UI that honours it can never upload slots 1..N-1 (server.py l.3666)"))
    def test_e_creator_may_keep_uploading_remaining_slots(self, w):
        ctx = w.start(self.N)
        ct, c = ctx.creators[0]
        assert w.submit(ctx.cid, ct, 0).status_code == 200
        assert w.detail(ctx.cid, ct)["can_submit_content"] is True

    @pytest.mark.xfail(strict=False, reason=(
        "BUG: POST /work/submit (used by the native app) hard-codes deliverable_index=0, so quantity>1 / "
        "multi-row briefs can only ever deliver one asset (server.py l.10098)"))
    def test_e_work_submit_endpoint_can_deliver_more_than_one_slot(self, w):
        ctx = w.start(self.N)
        ct, c = ctx.creators[0]
        for k in range(qty(self.sc)):
            r = w.call("POST", "/work/submit", ct, json={
                "campaign_id": ctx.cid, "work_files": [f"https://cdn.example.com/slot{k}.mp4"]})
            assert r.status_code == 200
        assert sorted(x["deliverable_index"] for x in w.works(ctx.cid, c)) == list(range(qty(self.sc)))

    @pytest.mark.xfail(strict=False, reason=(
        "BUG: request_revision flags the highest-version 'submitted' row of the CREATOR (not of the slot), so a "
        "revision on slot N-1 flags another slot's row; the resubmission of slot N-1 is then dropped as "
        "'Content already submitted' (server.py l.11184-11193, l.11653-11654)"))
    def test_f_revision_on_a_later_slot_can_be_resubmitted(self, w):
        sc = self.sc
        ctx = w.start(self.N)
        ct, c = ctx.creators[0]
        w.submit_all(ctx, only=c)
        last = w.works(ctx.cid, c)[-1]
        assert last["deliverable_index"] == qty(sc) - 1
        r = w.call("POST", f"/work/{last['id']}/request-revision", w.brand_t, json={"feedback": "Re-shoot the end"})
        assert r.status_code == 200
        r = w.submit(ctx.cid, ct, qty(sc) - 1)
        assert r.status_code == 200 and r.json().get("version") == 2, r.text


class _PrivateExtras:
    """A brief addressed to ONE creator: invitation card, accept/decline, price taken from the creator."""

    def test_d_only_the_named_creator_can_see_or_answer_it(self, w):
        sc = self.sc
        ct, c = w.add_creator()
        other_t, other = w.add_creator()
        cid = w.publish(sc, selected_creator=c, visibility="private").json()["campaign_id"]
        w.approve(cid)
        assert w.campaign(cid)["status"] == "active"
        card = w.run(w.db.chat_action_cards.find_one({"type": "private_invitation", "deal_id": cid}, {"_id": 0}))
        assert card["recipient_id"] == c and card["status"] == "open"
        assert card["fields"]["budget"] == PER_VIDEO and card["fields"]["deliverable_summary"].startswith(f"{sc['rows'][0]['quantity']} x")
        # exactly one invitation, even if approval is replayed
        assert w.run(w.db.chat_action_cards.count_documents({"type": "private_invitation", "deal_id": cid})) == 1
        # another creator: cannot open it, bid on it, answer it, or find it in Browse
        assert w.call("GET", f"/campaigns/{cid}", other_t).status_code == 404
        r = w.bid(cid, other_t)
        assert r.status_code == 400 and "private" in r.text.lower()
        assert w.call("POST", f"/chat/action-cards/{card['id']}/respond", other_t, json={"action": "accept"}).status_code == 403
        browse = w.call("GET", "/campaigns", other_t).json()
        assert cid not in [x["id"] for x in (browse if isinstance(browse, list) else browse.get("campaigns", []))]
        # the brand cannot "hire" through the bid route: there is nothing to bid on
        assert w.hire(cid, c).status_code == 404
        # before the answer the deal is not a deal in progress
        assert w.detail(cid, ct)["current_state"] == "Awaiting Creator Response"

    def test_d_client_cannot_change_the_price_creators_wanted_or_audience(self, w):
        sc = self.sc
        ct, c = w.add_creator(rate=1200, editing=250)
        cid = w.publish(sc, selected_creator=c, visibility="private", budget_min=1, budget_max=1,
                        per_video_budget=1, creators_wanted=9).json()["campaign_id"]
        stored = w.campaign(cid)
        assert stored["per_video_budget"] == stored["budget_max"] == stored["budget_min"] == 1200
        assert stored["creators_wanted"] == 1 and stored["budget_mode"] == "fixed"
        assert stored["editing_fee_per_video"] == 250
        [pool] = w.escrows(cid)
        assert pool["amount"] == server.campaign_slot_budget(stored)
        assert pool["amount"] == 1200 * qty(sc) + 250 * server.creator_editing_quantity(stored)

    def test_d_creator_without_a_price_or_unknown_creator_is_refused(self, w):
        sc = self.sc
        ct, c = w.add_creator(rate=0, editing=0)
        r = w.publish(sc, selected_creator=c, visibility="private")
        assert r.status_code == 400 and "price" in r.text
        r = w.publish(sc, selected_creator="nobody", visibility="private")
        assert r.status_code == 404
        assert w.run(w.db.escrow.count_documents({})) == 0

    def test_d_declining_refunds_the_hold_and_closes_the_brief(self, w):
        sc = self.sc
        ct, c = w.add_creator()
        before = w.balance(w.brand)
        cid = w.publish(sc, selected_creator=c, visibility="private").json()["campaign_id"]
        w.approve(cid)
        card = w.run(w.db.chat_action_cards.find_one({"type": "private_invitation", "deal_id": cid}, {"_id": 0}))
        r = w.call("POST", f"/chat/action-cards/{card['id']}/respond", ct,
                   json={"action": "reject", "decline_reason": server.DECLINE_REASONS[0]})
        assert r.status_code == 200, r.text
        assert w.campaign(cid)["status"] == "rejected"
        assert [e["status"] for e in w.escrows(cid)] == ["refunded"]
        assert before - w.balance(w.brand) == expected_fee(sc)         # hold back, listing fee kept
        # declining twice is refused
        assert w.call("POST", f"/chat/action-cards/{card['id']}/respond", ct,
                      json={"action": "reject", "decline_reason": server.DECLINE_REASONS[0]}).status_code == 400

    def test_d_accepting_turns_the_reservation_into_a_held_escrow_for_the_creator(self, w):
        sc = self.sc
        ctx = w.start(self.N)
        ct, c = ctx.creators[0]
        held = [e for e in w.escrows(ctx.cid) if e["status"] == "held" and e["creator_id"] == c]
        assert len(held) == 1 and held[0]["amount"] == gross_each(sc)
        assert w.campaign(ctx.cid)["status"] == "in_progress"

    @pytest.mark.xfail(strict=False, reason=(
        "BUG: a creator can upload content to a private brief before accepting it; the deal still says "
        "'Awaiting Creator Response' (submit_deal_content does not check the invitation, server.py l.11602)"))
    def test_d_content_is_refused_until_the_invitation_is_accepted(self, w):
        ct, c = w.add_creator()
        cid = w.publish(self.sc, selected_creator=c, visibility="private").json()["campaign_id"]
        w.approve(cid)
        r = w.submit(cid, ct, 0)
        assert r.status_code in (400, 403, 409), r.text

    @pytest.mark.xfail(strict=False, reason=(
        "BUG: PATCH /campaigns/{id} on a private DRAFT accepts per_video_budget / creators_wanted from the "
        "client; only POST /campaigns and /campaigns/draft re-price from the creator's rate card, so /submit "
        "holds the tampered amount while the invitation card still shows the real price (server.py l.7120-7159)"))
    def test_a_patching_a_private_draft_cannot_change_the_price(self, w):
        sc = self.sc
        ct, c = w.add_creator()
        body = w.payload(sc, selected_creator=c, visibility="private")
        body.pop("status")
        cid = w.call("POST", "/campaigns/draft", w.brand_t, json=body).json()["campaign_id"]
        w.call("PATCH", f"/campaigns/{cid}", w.brand_t, json={"per_video_budget": 1, "budget_min": 1, "budget_max": 1})
        before = w.balance(w.brand)
        assert w.call("POST", f"/campaigns/{cid}/submit", w.brand_t).status_code == 200
        [pool] = w.escrows(cid)
        assert pool["amount"] == expected_slot(sc, EDIT_FEE) or pool["amount"] == PER_VIDEO * qty(sc), pool


PAYOUT_TESTS = ("test_g_full_deal_pays_every_creator_and_no_money_is_created_or_lost",
                "test_e_payout_waits_for_every_slot",
                "test_f_raw_only_deal_never_enters_the_editing_state",
                "test_f_revision_then_resubmission_then_approval",
                "test_f_raw_then_ugc_editing_then_delivery_then_completion",
                "test_c_creator_edit_variant_pays_the_editing_fee_and_needs_two_uploads_per_slot",
                "test_d_accepting_turns_the_reservation_into_a_held_escrow_for_the_creator")


def private_bug(cls):
    for name in PAYOUT_TESTS:
        fn = getattr(cls, name, None)
        if fn is not None:
            setattr(cls, name, xfail_copy(fn, PRIVATE_BUG))
    return cls


# ---------------------------------------------------------------------------------------------
# The ten scenarios
# ---------------------------------------------------------------------------------------------
@private_bug
class TestScenario01PrivateBriefRaw(_Base, _PayoutAndCalc, _RawOnlyExtras, _PrivateExtras):
    N = 1


@private_bug
class TestScenario02PrivateBriefRawPlusEdit(_Base, _PayoutAndCalc, _EditExtras, _PrivateExtras):
    N = 2


class TestScenario03SingleCreatorRaw(_Base, _PayoutAndCalc, _RawOnlyExtras, _PublicExtras):
    N = 3

    @pytest.mark.xfail(strict=False, reason=(
        "BUG: select_creator() has no status check, so hiring on a PAUSED brief silently flips it back to "
        "in_progress and bypasses the admin pause (server.py l.8217-8340)"))
    def test_d_a_paused_brief_cannot_be_hired_on(self, w):
        ctx = w.start(3, bid_each=False)
        ct, c = ctx.creators[0]
        w.place_bid(ctx, ct)
        r = w.call("POST", f"/admin/campaigns/{ctx.cid}/pause", w.admin_t, json={"reason": "check"})
        assert r.status_code == 200, r.text
        assert w.campaign(ctx.cid)["status"] == "paused"
        w.hire(ctx.cid, c)
        assert w.campaign(ctx.cid)["status"] == "paused"

    @pytest.mark.xfail(strict=False, reason=(
        "BUG: when the wallet cannot cover the brand's 20% fee at hire time the hire still goes through "
        "(funded=False) and the fee is never collected later, yet release_scheduled_payout() books the full "
        "brand_fee as platform revenue - the books show money the platform never received (server.py "
        "l.8264-8279, l.10817-10822)"))
    def test_g_uncollected_brand_fee_is_not_booked_as_revenue(self, w):
        sc = self.sc
        ctx = w.start(3, bid_each=False)
        ct, c = ctx.creators[0]
        w.place_bid(ctx, ct)
        w.set_balance(w.brand, 0)                         # nothing left for the 20% fee
        r = w.hire(ctx.cid, c)
        assert r.status_code == 200 and r.json()["funded"] is False
        w.submit_all(ctx)
        w.approve_pending(ctx)
        revenue = w.run(w.db.platform_revenue.find({"campaign_id": ctx.cid}, {"_id": 0}).to_list(10))
        booked = sum(x["brand_fee"] + x["creator_fee"] for x in revenue)
        really_kept = expected_slot(sc) - w.balance(c)      # the only money that was ever held for this deal
        assert booked == pytest.approx(really_kept), (booked, really_kept)


class TestScenario04SingleCreatorRawPlusEdit(_Base, _PayoutAndCalc, _EditExtras, _PublicExtras):
    N = 4


class TestScenario05MultipleCreatorsRaw(_Base, _PayoutAndCalc, _RawOnlyExtras, _PublicExtras, _MultiCreatorExtras):
    N = 5


class TestScenario06MultipleCreatorsRawPlusEdit(_Base, _PayoutAndCalc, _EditExtras, _PublicExtras, _MultiCreatorExtras):
    N = 6


class TestScenario07SingleCreatorMultipleDeliverablesRaw(_Base, _PayoutAndCalc, _RawOnlyExtras, _PublicExtras, _MultiSlotExtras):
    N = 7


class TestScenario08SingleCreatorMultipleDeliverablesRawPlusEdit(_Base, _PayoutAndCalc, _EditExtras, _PublicExtras, _MultiSlotExtras):
    N = 8

    @pytest.mark.xfail(strict=False, reason=(
        "BUG: in a brief that mixes a raw-only row with an edited row, get_required_assets() turns raw_only off "
        "for the WHOLE brief, so the raw-only slot demands a second 'raw_footage_url' file "
        "(server.py l.3061-3076, l.11635)"))
    def test_e_mixed_rows_raw_only_slot_needs_just_one_file(self, w):
        sc = scenario([row("Reel", 1, **RAW_ONLY), row("Static post", 1, **UGC_EDIT)])
        ctx = w.start(8, sc=sc)
        ct, c = ctx.creators[0]
        r = w.submit(ctx.cid, ct, 0)                       # slot 0 = the raw-only Reel
        assert r.status_code == 200, r.text

    def test_e_mixed_rows_each_slot_follows_its_own_row(self, w):
        sc = scenario([row("Reel", 1, **RAW_ONLY), row("Static post", 1, **UGC_EDIT)])
        ctx = w.start(8, sc=sc)
        stored = w.campaign(ctx.cid)
        assert server.edit_mode(stored, 0) is None and server.edit_mode(stored, 1) == "ugc"
        assert server.total_deliverable_quantity(stored) == 2

    @pytest.mark.xfail(strict=False, reason=(
        "BUG: campaign_rollup_status() marks the brief 'completed' once every escrow is paid and no cut is "
        "awaiting_edit - it ignores edited cuts that are delivered but still SUBMITTED for brand review, so "
        "the brief shows Completed / Paid - Complete while edited videos are still unreviewed "
        "(server.py l.10591-10613)"))
    def test_f_brief_is_not_complete_while_edited_cuts_still_await_review(self, w):
        ctx = w.start(8)
        ct, c = ctx.creators[0]
        w.submit_all(ctx, only=c)
        w.approve_pending(ctx, c)
        w.finish_edits(ctx, c)
        first = w.works(ctx.cid, c, status="submitted")[0]
        assert w.approve_work(first["id"]).status_code == 200
        assert len(w.works(ctx.cid, c, status="submitted")) == qty(self.sc) - 1
        assert w.campaign(ctx.cid)["status"] != "completed"
        assert w.detail(ctx.cid, ct)["current_state"] != "Paid - Complete"


class TestScenario09SingleCreatorMultipleQuantitiesRaw(_Base, _PayoutAndCalc, _RawOnlyExtras, _PublicExtras, _MultiSlotExtras):
    N = 9


class TestScenario10SingleCreatorMultipleQuantitiesRawPlusEdit(_Base, _PayoutAndCalc, _EditExtras, _PublicExtras, _MultiSlotExtras):
    N = 10

    @pytest.mark.xfail(strict=False, reason="BUG: brief marked completed while edited cuts still await brand review (see scenario 8)")
    def test_f_brief_is_not_complete_while_edited_cuts_still_await_review(self, w):
        ctx = w.start(10)
        ct, c = ctx.creators[0]
        w.submit_all(ctx, only=c)
        w.approve_pending(ctx, c)
        w.finish_edits(ctx, c)
        first = w.works(ctx.cid, c, status="submitted")[0]
        assert w.approve_work(first["id"]).status_code == 200
        assert w.campaign(ctx.cid)["status"] != "completed"


# ---------------------------------------------------------------------------------------------
# Cross-cutting checks that are not tied to one scenario
# ---------------------------------------------------------------------------------------------
class TestListingFeeTiers:
    @pytest.mark.parametrize("creators, rows, fee", [
        (None, [1], 500), (1, [1], 500), (1, [1, 1], 1500), (1, [3], 1500), (1, [5, 5], 1500),
        (2, [1], 1500), (10, [1], 1500), (11, [1], 3000), (25, [3], 3000),
    ])
    def test_tier_is_chosen_by_creators_then_total_assets(self, creators, rows, fee):
        c = {"deliverable_items": [{"quantity": q} for q in rows]}
        if creators is not None:
            c["creators_wanted"] = creators
        assert server.campaign_listing_fee(c) == fee

    def test_legacy_brief_without_rows_pays_the_single_fee(self):
        assert server.campaign_listing_fee({}) == 500

    def test_fee_follows_the_admin_setting(self, monkeypatch):
        monkeypatch.setitem(server._PLATFORM_SETTINGS_CACHE, "listing_fee", 650)
        assert server.campaign_listing_fee({"deliverable_items": [{"quantity": 1}]}) == 650


class TestBudgetMathAndLegacyDefaults:
    @pytest.mark.parametrize("campaign, per_asset", [
        ({}, 0), ({"budget": 900, "per_video_budget": 100}, 900), ({"per_video_budget": 100, "budget_max": 400}, 100),
        ({"budget_min": 500, "budget_max": 800}, 800), ({"budget_min": 500}, 500), ({"budget_max": 700}, 700),
        ({"budget_min": "500", "budget_max": "bad"}, 500), ({"budget_min": None}, 0),
    ])
    def test_per_asset_budget(self, campaign, per_asset):
        assert server.campaign_per_asset_budget(campaign) == per_asset

    @pytest.mark.parametrize("items, expected", [
        (None, 1), ([], 1), ([{"quantity": 3}], 3), ([{"quantity": 0}], 1), ([{"quantity": "x"}], 1),
        ([{"quantity": 2}, {"quantity": 3}], 5), ([{}], 1), ([{"quantity": None}, {"quantity": 2}], 3),
    ])
    def test_total_deliverable_quantity(self, items, expected):
        assert server.total_deliverable_quantity({"deliverable_items": items}) == expected

    def test_legacy_campaign_holds_exactly_one_assets_budget(self):
        legacy = {"budget_min": 500, "budget_max": 800}
        assert server.campaign_slot_budget(legacy) == 800 and server.campaign_budget_total(legacy) == 800
        assert server.campaign_creators_wanted(legacy) == 1

    @pytest.mark.parametrize("wanted", [None, 0, "x", -3])
    def test_creators_wanted_never_drops_below_one(self, wanted):
        assert server.campaign_creators_wanted({"creators_wanted": wanted}) == 1

    def test_only_creator_edited_rows_are_charged_the_editing_fee(self):
        c = {"per_video_budget": 1000, "editing_fee_per_video": 300, "creators_wanted": 2, "deliverable_items": [
            {"quantity": 2, **CREATOR_EDIT}, {"quantity": 1, **UGC_EDIT}, {"quantity": 1, **RAW_ONLY}]}
        assert server.creator_editing_quantity(c) == 2
        assert server.campaign_slot_budget(c) == 1000 * 4 + 300 * 2
        assert server.campaign_budget_total(c) == 2 * (1000 * 4 + 300 * 2)

    @pytest.mark.parametrize("per_video", [333.33, 1234.56, 0.01, 17.5, 250.25])
    @pytest.mark.parametrize("n", [5, 9])
    def test_fractional_budgets_lose_no_paise(self, monkeypatch, per_video, n):
        monkeypatch.setitem(globals(), "PER_VIDEO", per_video)
        world = World(monkeypatch)
        try:
            ctx = world.start(n)
            world.submit_all(ctx)
            world.approve_pending(ctx)
            view = world.money_view(ctx)
            assert view["in_escrow"] == 0
            assert view["sum"] == pytest.approx(ctx.initial, abs=0.005), view
            assert all(world.balance(c) >= 0 for _, c in ctx.creators)
        finally:
            world.close()


class TestStateMachinePure:
    def work(self, status, stage=None):
        return {"status": status, "stage": stage, "submitted_at": "2026-10-26T00:00:00+00:00"}

    def state(self, campaign, work=None, escrow=None):
        return server.compute_deal_state(campaign, None, {}, work, escrow, [])["current_state"]

    def test_raw_only_has_no_editing_state(self):
        c = {"id": "c", "selected_creator": "a", "status": "in_progress", "deliverable_items": [row(**RAW_ONLY)]}
        assert self.state(c) == "Received - Content in Progress"
        assert self.state(c, self.work(server.WorkStatus.SUBMITTED)) == "Content Submitted - Awaiting Review"
        assert self.state(c, self.work(server.WorkStatus.APPROVED)) == "Approved - Payment Processing"
        assert self.state(c, self.work(server.WorkStatus.APPROVED), {"status": "released"}) == "Paid - Complete"

    def test_ugc_edit_states(self):
        c = {"id": "c", "selected_creator": "a", "status": "in_progress", "deliverable_items": [row(**UGC_EDIT)]}
        assert self.state(c, self.work(server.WorkStatus.AWAITING_EDIT, "edited")) == "Raw Approved - UGC.ad Editing"
        assert self.state(c, self.work(server.WorkStatus.SUBMITTED, "edited")) == "Content Submitted - Awaiting Review"
        assert self.state(c, self.work(server.WorkStatus.REVISION_REQUESTED, "edited")) == "Revision Requested"

    def test_creator_edit_states(self):
        c = {"id": "c", "selected_creator": "a", "status": "in_progress", "deliverable_items": [row(**CREATOR_EDIT)]}
        assert self.state(c, self.work(server.WorkStatus.APPROVED, "raw")) == "Raw Approved - Edited Video Due"

    def test_private_invitation_not_yet_answered(self):
        c = {"id": "c", "selected_creator": "a", "status": "active", "visibility": "private"}
        state = server.compute_deal_state(c, None, {}, None, None, [], invitation_pending=True)
        assert state["current_state"] == "Awaiting Creator Response"


class TestEditedByValidation:
    @pytest.mark.xfail(strict=False, reason=(
        "BUG: DeliverableItem.edited_by is a free string; anything except 'creator'/'ugc' (e.g. 'UGC') makes "
        "edit_mode() return None, so a row that asks for an edited cut is delivered as plain raw, uncharged and "
        "unedited (campaign_models.py l.50, server.py l.10632-10636)"))
    def test_unknown_edited_by_is_rejected_or_normalised(self, w):
        sc = scenario([row(**dict(raw_required=True, edited_required=True, edited_by="UGC"))])
        r = w.publish(sc)
        if r.status_code == 200:
            stored = w.campaign(r.json()["campaign_id"])
            assert server.edit_mode(stored) in ("ugc", "creator")
        else:
            assert r.status_code in (400, 422)


class TestDirectBookingQuantity:
    @pytest.mark.xfail(strict=False, reason=(
        "BUG: POST /checkout/brief charges price x video_count into escrow but stores no deliverable_items, so "
        "total_deliverable_quantity()==1 and ONE approval releases the whole escrow (server.py l.5035-5130)"))
    def test_three_paid_videos_need_three_approvals(self, w):
        ct, c = w.add_creator()
        r = w.call("POST", "/checkout/brief", w.brand_t, json={"creator_id": c, "video_count": 3,
                                                               "brief": {"title": "Three videos"}})
        assert r.status_code == 201, r.text
        cid = r.json()["campaign_id"]
        stored = w.campaign(cid)
        assert server.total_deliverable_quantity(stored) == 3

    @pytest.mark.xfail(strict=False, reason=(
        "BUG (low, API only - the wizard sends whole rupees): submit_bid() compares round(amount x qty, 2) with an "
        "unrounded ceiling (budget_max x qty), so a bid exactly AT the maximum is refused for many fractional "
        "budgets, e.g. 1.91 x 3 (server.py l.8086-8097)"))
    @pytest.mark.parametrize("per_video", [1.91, 99.99, 2.4])
    def test_bid_exactly_at_a_fractional_maximum_is_accepted(self, monkeypatch, per_video):
        monkeypatch.setitem(globals(), "PER_VIDEO", per_video)
        world = World(monkeypatch)
        try:
            world.start(9)
        finally:
            world.close()
