"""A brief with several hired creators holds one escrow and one deal PER creator. A dispute,
a ruling, an issue card or an activity row on one creator's deal must never touch another
creator's money or deal. Real routes, in-memory database."""
import asyncio

import pytest

pytest.importorskip("mongomock_motor")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402
from mongomock_motor import AsyncMongoMockClient  # noqa: E402

import server  # noqa: E402

DESCRIPTION = "The delivered video does not match the brief: wrong product shown and the script was not followed. " * 2


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("RESEND_API_KEY", "")
    monkeypatch.setattr(server, "db", AsyncMongoMockClient()["multi_deals"])
    loop = asyncio.new_event_loop()
    client = TestClient(server.app, follow_redirects=False)
    run = loop.run_until_complete
    n = {"i": 0}

    def call(method, path, token=None, **kw):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return client.request(method, "/api" + path, headers=headers, **kw)

    def signup(role):
        n["i"] += 1
        b = call("POST", "/auth/signup", json={"email": f"md-{role}-{n['i']}@example.com", "password": "Passw0rd!x",
                                               "role": role, "phone": f"98765{50000 + n['i']}", "dial_code": "+91",
                                               "name": f"M{n['i']}"}).json()
        run(server.db.users.update_one({"id": b["user_id"]}, {"$set": {"approval_status": "approved", "balance": 0.0}}))
        return b["token"], b["user_id"]

    run(server.db.users.insert_one({"id": "adm", "email": "adm@example.com", "role": "admin", "admin_role": "founder",
                                    "approval_status": "approved", "profile_completed": True}))
    admin_t = server.create_token("adm", "adm@example.com", "admin")

    brand_t, brand = signup("business")
    (a_t, a), (b_t, b) = signup("creator"), signup("creator")
    camp = {"id": "mc1", "business_id": brand, "title": "Two creators", "status": "in_progress",
            "creators_wanted": 2, "selected_creators": [a, b], "selected_creator": a,
            "bids": [{"creator_id": a, "amount": 2000}, {"creator_id": b, "amount": 3000}],
            "deliverable_items": [{"type": "Reel", "quantity": 1}], "budget_min": 2000, "budget_max": 3000}
    run(server.db.campaigns.insert_one(dict(camp)))
    run(server.db.escrow.insert_many([
        {"id": "e-a", "campaign_id": "mc1", "creator_id": a, "business_id": brand, "status": "held", "amount": 2000.0},
        {"id": "e-b", "campaign_id": "mc1", "creator_id": b, "business_id": brand, "status": "held", "amount": 3000.0},
    ]))
    for cid in (a, b):
        run(server.db.work_submissions.insert_one({
            "id": f"w-{cid[:4]}", "campaign_id": "mc1", "creator_id": cid, "status": "submitted",
            "work_files": ["v.mp4"], "submitted_at": "2026-10-12T10:00:00+00:00", "revisions": []}))

    def deal_id(creator_id):
        return server.person_deal_id(camp, creator_id)

    def escrow(eid):
        return run(server.db.escrow.find_one({"id": eid}))

    def balance(uid):
        return round(run(server.db.users.find_one({"id": uid})).get("balance") or 0, 2)

    def raise_dispute(creator_id):
        return call("POST", f"/deals/{deal_id(creator_id)}/raise-dispute", brand_t, json={
            "dispute_type": "quality_below_brief", "desired_outcome": "partial_refund",
            "description": DESCRIPTION, "evidence_urls": ["https://cdn.example.com/e.png"]})

    def rule(dispute_id, **body):
        return call("POST", f"/admin/disputes/{dispute_id}/rule", admin_t, json=body)

    yield type("Env", (), dict(call=staticmethod(call), run=run, db=server.db, brand_t=brand_t, brand=brand,
                               a_t=a_t, a=a, b_t=b_t, b=b, admin_t=admin_t, deal_id=staticmethod(deal_id),
                               escrow=staticmethod(escrow), balance=staticmethod(balance),
                               raise_dispute=staticmethod(raise_dispute), rule=staticmethod(rule), camp=camp))
    loop.close()


# ------------------------------------------------------------------ a dispute belongs to ONE creator
def test_paid_revision_credits_only_the_submitting_creator_once(env):
    work_id = f"w-{env.a[:4]}"
    env.run(env.db.users.update_one({"id": env.brand}, {"$set": {"balance": 1000}}))
    env.run(env.db.work_submissions.insert_one({
        "id": "previous-rounds", "campaign_id": "mc1", "creator_id": env.a,
        "status": "revision_requested", "revisions": [{"index": 1}, {"index": 2}],
    }))
    response = env.call("POST", f"/work/{work_id}/request-revision", env.brand_t,
                        json={"feedback": "Replace the opening shot"})
    assert response.status_code == 200, response.text
    assert response.json()["fee_charged"] == 500
    assert env.balance(env.brand) == 500
    assert env.escrow("e-a")["revision_credit_owed"] == 300
    assert env.escrow("e-b").get("revision_credit_owed", 0) == 0
    env.run(env.db.work_submissions.update_one({"id": work_id}, {"$set": {"status": "submitted"}}))
    response = env.call("POST", f"/work/{work_id}/approve", env.brand_t)
    assert response.status_code == 200, response.text
    credited = env.balance(env.a)
    assert credited > 0
    assert env.escrow("e-a")["revision_credit_paid"] == 300
    assert env.balance(env.b) == 0
    assert env.escrow("e-b")["status"] == "held"
    response = env.call("POST", f"/work/{work_id}/approve", env.brand_t)
    assert response.status_code == 200
    assert env.balance(env.a) == credited


def test_raw_approval_requires_the_edited_submission_before_payment(env):
    env.run(env.db.campaigns.update_one({"id": "mc1"}, {"$set": {
        "deliverable_items": [{"type": "Reel", "quantity": 1, "raw_required": True,
                               "edited_required": True, "edited_by": "creator"}]
    }}))
    work_id = f"w-{env.a[:4]}"
    env.run(env.db.work_submissions.update_one({"id": work_id}, {"$set": {"stage": "raw"}}))
    response = env.call("POST", f"/work/{work_id}/approve", env.brand_t)
    assert response.status_code == 200, response.text
    assert env.balance(env.a) == 0
    assert env.balance(env.b) == 0
    assert env.escrow("e-a")["status"] == "held"
    campaign = env.run(env.db.campaigns.find_one({"id": "mc1"}))
    assert env.run(server.edit_stage(campaign, env.a, 0)) == "edited"
    assert env.run(server.edit_stage(campaign, env.b, 0)) == "raw"


def test_a_dispute_is_filed_against_the_creator_of_that_deal(env):
    r = env.raise_dispute(env.b)
    assert r.status_code == 200, r.text
    dispute = env.run(env.db.disputes.find_one({"id": r.json()["dispute_id"]}))
    assert dispute["creator_id"] == env.b                       # was: the first hired creator (A)
    assert env.escrow("e-b")["status"] == "on_hold"             # B's money is held...
    assert env.escrow("e-a")["status"] == "held"                # ...and A's is not touched
    assert env.run(env.db.escrow.count_documents({})) == 2      # no phantom escrow from an upsert


def test_a_dispute_on_one_deal_does_not_pause_the_other_creator(env):
    env.raise_dispute(env.b)
    # A's deal keeps working: the brand can still approve A's submission.
    r = env.call("POST", f"/work/w-{env.a[:4]}/approve", env.brand_t)
    assert r.status_code == 200, r.text
    # B's deal IS paused.
    r = env.call("POST", f"/work/w-{env.b[:4]}/approve", env.brand_t)
    assert r.status_code == 409


# ------------------------------------------------------------------ a ruling pays / refunds the right deal
def test_ruling_for_the_creator_pays_only_that_creator_and_that_escrow(env):
    dispute_id = env.raise_dispute(env.b).json()["dispute_id"]
    r = env.rule(dispute_id, ruling="favor_creator", reasoning="Work matched the brief.")
    assert r.status_code == 200, r.text
    assert env.balance(env.b) == 3000.0 and env.balance(env.a) == 0.0
    assert env.escrow("e-b")["status"] == "released" and env.escrow("e-a")["status"] == "held"
    # The brief as a whole is NOT finished: creator A still has work waiting for review.
    assert env.run(env.db.campaigns.find_one({"id": "mc1"}))["status"] in ("in_progress", "work_submitted")


def test_ruling_for_the_brand_refunds_only_that_creators_amount(env):
    dispute_id = env.raise_dispute(env.b).json()["dispute_id"]
    r = env.rule(dispute_id, ruling="favor_brand", reasoning="Work did not match the brief.")
    assert r.status_code == 200, r.text
    assert env.balance(env.brand) == 3000.0                     # B's 3000, not A's 2000
    assert env.balance(env.a) == 0.0 and env.balance(env.b) == 0.0
    assert env.escrow("e-b")["status"] == "refunded" and env.escrow("e-a")["status"] == "held"
    campaign = env.run(env.db.campaigns.find_one({"id": "mc1"}))
    assert campaign["status"] in ("in_progress", "work_submitted")   # was: cancelled for everyone


def test_ruling_one_dispute_leaves_the_other_creators_open_dispute_alone(env):
    da = env.raise_dispute(env.a).json()["dispute_id"]
    db_ = env.raise_dispute(env.b).json()["dispute_id"]
    assert da != db_                                            # one per creator, not one per brief
    env.rule(db_, ruling="favor_creator")
    still_open = env.run(env.db.disputes.find_one({"id": da}))
    assert still_open["status"] == "open"
    assert env.escrow("e-a")["status"] == "on_hold"


# ------------------------------------------------------------------ issue cards hold only their own escrow
def test_an_issue_card_holds_only_that_creators_escrow_and_stays_in_their_deal(env):
    r = env.call("POST", f"/deals/{env.deal_id(env.b)}/dispute", env.brand_t, json={"message": "Product shown is wrong."})
    assert r.status_code == 200, r.text
    assert env.escrow("e-b")["status"] == "on_hold" and env.escrow("e-a")["status"] == "held"
    assert env.run(env.db.escrow.count_documents({})) == 2
    card = env.run(env.db.deal_action_cards.find_one({"type": "raise_dispute"}))
    assert card["creator_id"] == env.b                          # visible in B's deal room, not A's


# ------------------------------------------------------------------ admin money actions name the creator
def test_admin_release_and_refund_refuse_to_guess_a_creator_on_a_multi_creator_brief(env):
    for path in ("release-payment", "refund"):
        r = env.call("POST", f"/admin/deals/mc1/{path}", env.admin_t, json={"reason": "support"})
        assert r.status_code == 400, (path, r.status_code, r.text)
        assert "creator" in str(r.json().get("detail")).lower()
    assert env.escrow("e-a")["status"] == "held" and env.escrow("e-b")["status"] == "held"
    assert env.balance(env.a) == 0.0 and env.balance(env.brand) == 0.0


# ------------------------------------------------------------------ timeline rows reach the right people
def _activity(env, tok, creator_id=None):
    """The timeline a viewer sees for this brief: a creator reads their own deal row from
    /deals/my; the brand reads the row of the creator it asks about from /deals/business."""
    if creator_id is None:
        rows = env.call("GET", "/deals/my", tok).json()
    else:
        rows = [r for r in env.call("GET", "/deals/business", tok).json()
                if (r.get("creator") or {}).get("id") == creator_id]
    row = next(r for r in rows if (r.get("campaign") or {}).get("id") == "mc1")
    return [e.get("message") for e in (row.get("activity_feed") or [])]


def test_per_creator_events_are_tagged_and_do_not_cross_over(env):
    env.call("POST", f"/deals/{env.deal_id(env.b)}/dispute", env.brand_t, json={"message": "Wrong product."})
    rows = env.run(env.db.deal_activity.find({"campaign_id": "mc1"}).to_list(20))
    assert rows and all(r.get("creator_id") == env.b for r in rows)
    assert not any("Wrong product" in m for m in _activity(env, env.a_t))
    assert any("Wrong product" in m for m in _activity(env, env.b_t))
    assert any("Wrong product" in m for m in _activity(env, env.brand_t, env.b))
    assert not any("Wrong product" in m for m in _activity(env, env.brand_t, env.a))


def test_campaign_wide_notes_are_visible_to_every_hired_creator(env):
    camp = env.run(env.db.campaigns.find_one({"id": "mc1"}, {"_id": 0}))
    env.run(server.insert_deal_activity(camp, "system", "UGCAD.IO", "campaign_update", "Brief deadline moved to Friday."))
    for tok in (env.a_t, env.b_t):
        assert "Brief deadline moved to Friday." in _activity(env, tok)


# ------------------------------------------------------------------ the rest of the money paths
def test_waiving_a_late_penalty_only_touches_that_creators_payout(env):
    env.run(env.db.escrow.update_many({"campaign_id": "mc1"}, {"$set": {
        "payout_status": "scheduled", "penalty_amount": 100.0, "gross_amount": 2000.0, "tds_amount": 0.0}}))
    env.run(env.db.late_offenses.insert_one({"id": "off-b", "creator_id": env.b, "campaign_id": "mc1", "waived": False}))
    r = env.call("POST", "/admin/late-offenses/off-b/waive", env.admin_t)
    assert r.status_code == 200, r.text
    assert env.escrow("e-b")["penalty_amount"] == 0
    assert env.escrow("e-a")["penalty_amount"] == 100.0          # the other creator's penalty stands


def _stale_with_a_dispute_on_a(env):
    env.run(env.db.work_submissions.update_many({"campaign_id": "mc1"}, {"$set": {"submitted_at": "2026-09-01T10:00:00+00:00"}}))
    env.run(env.db.deal_action_cards.insert_one({
        "id": "card-a", "campaign_id": "mc1", "creator_id": env.a, "type": "raise_dispute", "status": "open"}))


def _work_status(env):
    return {w["creator_id"]: w["status"] for w in env.run(env.db.work_submissions.find({}).to_list(10))}


def test_viewing_a_deal_auto_approves_only_the_undisputed_creators_stale_work(env):
    _stale_with_a_dispute_on_a(env)
    assert env.call("GET", "/deals/my", env.b_t).status_code == 200      # a view settles lazily
    status = _work_status(env)
    assert status[env.b] == "approved" and status[env.a] == "submitted"


def test_nightly_auto_approval_is_per_creator_too(env):
    _stale_with_a_dispute_on_a(env)
    assert env.run(server.auto_approve_stale_submissions()) == 1
    status = _work_status(env)
    assert status[env.b] == "approved" and status[env.a] == "submitted"


def test_banning_a_brief_flags_every_held_escrow_for_manual_handling(env):
    r = env.call("POST", "/admin/campaigns/mc1/ban", env.admin_t, json={"reason": "Policy violation in the brief"})
    assert r.status_code == 200, r.text
    assert env.escrow("e-a").get("needs_manual_review") and env.escrow("e-b").get("needs_manual_review")


def test_a_brief_with_one_paid_and_one_refunded_creator_is_finished(env):
    env.run(env.db.escrow.update_one({"id": "e-a"}, {"$set": {"status": "released", "payout_status": "released"}}))
    env.run(env.db.escrow.update_one({"id": "e-b"}, {"$set": {"status": "refunded"}}))
    camp = env.run(env.db.campaigns.find_one({"id": "mc1"}))
    assert env.run(server.campaign_rollup_status(camp)) == "completed"


def test_a_creator_can_submit_work_while_only_the_other_creators_deal_is_disputed(env):
    env.run(env.db.work_submissions.delete_many({"campaign_id": "mc1"}))
    env.run(env.db.users.update_many({"id": {"$in": [env.a, env.b]}}, {"$set": {"kyc": {"status": "verified"}}}))
    env.raise_dispute(env.b)
    ok = env.call("POST", "/work/submit", env.a_t, json={"campaign_id": "mc1", "work_files": ["https://cdn.example.com/a.mp4"], "description": "cut"})
    assert ok.status_code == 200, ok.text                       # A is not paused (and the route does not crash)
    blocked = env.call("POST", "/work/submit", env.b_t, json={"campaign_id": "mc1", "work_files": ["https://cdn.example.com/b.mp4"], "description": "cut"})
    assert blocked.status_code == 409                           # B's own deal is under dispute
