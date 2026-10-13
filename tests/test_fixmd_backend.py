"""fix.md round: staff roles cannot be self-registered, welcome message on every signup
route, a creator only sees their OWN status on a multi-creator brief, archiving is per
creator, and the revision dialog gets real counters. Real routes, in-memory database."""
import asyncio

import pytest

pytest.importorskip("mongomock_motor")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402
from mongomock_motor import AsyncMongoMockClient  # noqa: E402

import server  # noqa: E402


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("RESEND_API_KEY", "")
    monkeypatch.setattr(server, "db", AsyncMongoMockClient()["fixmd"])
    monkeypatch.setattr(server, "GOOGLE_CLIENT_ID", "test-client-id")
    loop = asyncio.new_event_loop()
    client = TestClient(server.app, follow_redirects=False)
    run = loop.run_until_complete
    n = {"i": 0}

    def call(method, path, token=None, **kw):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return client.request(method, "/api" + path, headers=headers, **kw)

    def signup(role):
        n["i"] += 1
        b = call("POST", "/auth/signup", json={"email": f"fm-{role}-{n['i']}@example.com", "password": "Passw0rd!x",
                                               "role": role, "phone": f"98765{49000 + n['i']}", "dial_code": "+91",
                                               "name": f"F{n['i']}"}).json()
        run(server.db.users.update_one({"id": b["user_id"]}, {"$set": {"approval_status": "approved"}}))
        return b["token"], b["user_id"]

    def google(email, role=None):
        monkeypatch.setattr(server, "_verify_google_id_token", lambda cred: {
            "aud": "test-client-id", "email": email, "email_verified": True, "sub": f"g-{email}", "name": "G User"})
        body = {"credential": "x"}
        if role:
            body["role"] = role
        return call("POST", "/auth/google", json=body)

    yield type("Env", (), dict(call=staticmethod(call), signup=staticmethod(signup), google=staticmethod(google),
                               run=run, db=server.db))
    loop.close()


# ---------------------------------------------------------------- staff roles are not self-service
@pytest.mark.parametrize("price,quantity,editing,expected", [
    (5000, 3, 0, 19500),
    (2000, 2, 0, 6300),
    (1000, 1, 1000, 2900),
])
def test_brief_price_includes_quantity_editing_commission_and_listing(price, quantity, editing, expected):
    campaign = {"per_video_budget": price, "creators_wanted": 1,
                "editing_fee_per_video": editing,
                "deliverable_items": [{"quantity": quantity, "edited_required": bool(editing), "edited_by": "creator"}]}
    gross = server.campaign_budget_total(campaign)
    assert gross + server.brand_commission(gross) + server.campaign_listing_fee(campaign) == expected
    campaign["total_budget"] = gross
    mapped = server.map_legacy_to_new_fields(campaign)
    assert mapped["budget_max"] == price
    assert server.campaign_budget_total(mapped) == gross


def test_legacy_welcome_is_repaired_without_rewriting_admin_announcements(env):
    token, user_id = env.signup("creator")
    env.run(env.db.in_app_notifications.insert_many([
        {"id": "legacy-welcome", "user_id": user_id, "title": "cdsnig", "message": "placeholder", "source": "admin"},
        {"id": "real-announcement", "user_id": user_id, "title": "Campaign update", "message": "Review your brief", "source": "admin"},
        {"id": "other-user", "user_id": "another-user", "title": "cdsnig", "message": "placeholder"},
    ]))
    response = env.call("GET", "/notifications/my-notifications", token)
    assert response.status_code == 200
    rows = {row["id"]: row for row in response.json()}
    assert rows["legacy-welcome"]["title"] == "Welcome to UGCad.io!"
    assert "Browse open briefs" in rows["legacy-welcome"]["message"]
    assert rows["real-announcement"]["title"] == "Campaign update"
    assert env.run(env.db.in_app_notifications.find_one({"id": "other-user"}))["title"] == "cdsnig"


@pytest.mark.parametrize("role", ["admin", "campaign_manager", "support_staff"])
def test_email_signup_cannot_create_staff(env, role):
    r = env.call("POST", "/auth/signup", json={"email": f"evil-{role}@example.com", "password": "Passw0rd!x",
                                               "role": role, "phone": "9876543210", "dial_code": "+91", "name": "E"})
    assert r.status_code == 403
    assert env.run(env.db.users.count_documents({"email": f"evil-{role}@example.com"})) == 0


@pytest.mark.parametrize("role", ["admin", "campaign_manager", "support_staff"])
def test_google_signup_cannot_create_staff(env, role):
    r = env.google(f"g-{role}@example.com", role=role)
    assert r.status_code == 200
    assert r.json()["role"] == "creator"                       # falls back to the default role
    assert r.json()["approval_status"] == "pending"
    assert env.call("GET", "/admin/pending-profiles", r.json()["token"]).status_code == 403


def test_an_existing_admin_can_still_sign_in_with_google(env):
    env.run(env.db.users.insert_one({"id": "adm", "email": "boss@example.com", "role": "admin", "admin_role": "founder",
                                     "approval_status": "approved", "profile_completed": True}))
    r = env.google("boss@example.com")
    assert r.status_code == 200 and r.json()["role"] == "admin"


def test_creator_and_brand_signup_still_work_and_get_a_welcome(env):
    for role in ("creator", "business"):
        _, uid = env.signup(role)
        assert env.run(env.db.in_app_notifications.count_documents({"user_id": uid, "title": {"$regex": "Welcome"}})) == 1


def test_google_signup_gets_the_welcome_message_too(env):
    r = env.google("newbie@example.com", role="business")
    assert r.json()["role"] == "business"
    assert env.run(env.db.in_app_notifications.count_documents(
        {"user_id": r.json()["user_id"], "title": {"$regex": "Welcome"}})) == 1
    again = env.google("newbie@example.com")                   # signing in again must not repeat it
    assert env.run(env.db.in_app_notifications.count_documents(
        {"user_id": again.json()["user_id"], "title": {"$regex": "Welcome"}})) == 1


# ---------------------------------------------------------------- multi-creator status is per creator
def _multi_brief(env, brand):
    (a_t, a), (b_t, b) = env.signup("creator"), env.signup("creator")
    env.run(env.db.campaigns.insert_one({
        "id": "mc1", "business_id": brand, "title": "Two creators", "status": "work_submitted",
        "creators_wanted": 2, "selected_creators": [a, b], "selected_creator": a,
        "bids": [{"creator_id": a, "amount": 2000, "status": "accepted"}, {"creator_id": b, "amount": 2000, "status": "accepted"}],
        "work_submission": {"id": "w-a", "creator_id": a, "work_files": ["a.mp4"], "video_url": "a.mp4"},
        "deliverable_items": [{"type": "Reel", "quantity": 1}],
    }))
    env.run(env.db.work_submissions.insert_one({
        "id": "w-a", "campaign_id": "mc1", "creator_id": a, "status": "submitted", "work_files": ["a.mp4"],
        "submitted_at": "2026-10-12T10:00:00+00:00", "revisions": []}))
    for cid in (a, b):
        env.run(env.db.escrow.insert_one({"id": f"e-{cid}", "campaign_id": "mc1", "creator_id": cid, "status": "held", "amount": 2000}))
    return (a_t, a), (b_t, b)


def test_only_the_creator_who_submitted_sees_under_review(env):
    brand_t, brand = env.signup("business")
    (a_t, a), (b_t, b) = _multi_brief(env, brand)

    for_a = env.call("GET", "/campaigns/mc1", a_t).json()
    for_b = env.call("GET", "/campaigns/mc1", b_t).json()
    assert for_a["status"] == "work_submitted" and for_a["work_submission"]["creator_id"] == a
    assert for_b["status"] == "in_progress" and for_b["work_submission"] is None     # B submitted nothing

    brand_view = env.call("GET", "/campaigns/mc1", brand_t).json()                   # brand keeps the rollup
    assert brand_view["status"] == "work_submitted"


def test_list_and_status_tabs_are_per_creator(env):
    brand_t, brand = env.signup("business")
    (a_t, a), (b_t, b) = _multi_brief(env, brand)

    def mine(tok, status=None):
        r = env.call("GET", "/campaigns" + (f"?status={status}" if status else ""), tok).json()
        return {c["id"]: c["status"] for c in r}.get("mc1")

    assert mine(a_t) == "work_submitted" and mine(b_t) == "in_progress"
    assert mine(a_t, "work_submitted") == "work_submitted" and mine(b_t, "work_submitted") is None
    assert mine(b_t, "in_progress") == "in_progress" and mine(a_t, "in_progress") is None
    bids = {r["campaign"]["id"]: r["campaign_status"] for r in env.call("GET", "/bids/my", b_t).json()}
    assert bids["mc1"] == "in_progress"


def test_deal_rows_embed_the_viewers_own_status(env):
    brand_t, brand = env.signup("business")
    (a_t, a), (b_t, b) = _multi_brief(env, brand)
    mine = lambda tok: env.call("GET", "/deals/my", tok).json()[0]["campaign"]
    assert mine(a_t)["status"] == "work_submitted" and mine(a_t)["work_submission"]["creator_id"] == a
    assert mine(b_t)["status"] == "in_progress" and mine(b_t)["work_submission"] is None


def test_a_paid_creator_is_completed_while_the_other_is_not(env):
    brand_t, brand = env.signup("business")
    (a_t, a), (b_t, b) = _multi_brief(env, brand)
    env.run(env.db.escrow.update_one({"id": f"e-{a}"}, {"$set": {"status": "released", "payout_status": "released"}}))
    assert env.call("GET", "/campaigns/mc1", a_t).json()["status"] == "completed"
    assert env.call("GET", "/campaigns/mc1", b_t).json()["status"] == "in_progress"


# ---------------------------------------------------------------- archive is per creator
def test_archiving_one_creators_deal_does_not_hide_the_other(env):
    brand_t, brand = env.signup("business")
    (a_t, a), (b_t, b) = _multi_brief(env, brand)

    def deal_ids(tok):
        rows = env.call("GET", "/deals/my", tok).json()
        return [(r.get("campaign") or {}).get("id") for r in rows]

    assert "mc1" in deal_ids(a_t) and "mc1" in deal_ids(b_t)
    assert env.call("POST", "/deals/mc1/archive", a_t).status_code == 200
    assert "mc1" not in deal_ids(a_t)
    assert "mc1" in deal_ids(b_t)


# ---------------------------------------------------------------- revision counters for the dialog
@pytest.mark.parametrize("revisions, remaining, next_fee", [(0, 2, 0), (1, 1, 0), (2, 0, 500)])
def test_work_review_rows_carry_revision_counters(env, revisions, remaining, next_fee):
    brand_t, brand = env.signup("business")
    _, creator = env.signup("creator")
    env.run(env.db.campaigns.insert_one({"id": "c1", "business_id": brand, "title": "T", "status": "work_submitted",
                                         "selected_creator": creator, "selected_creators": [creator],
                                         "deliverable_items": [{"type": "Reel", "quantity": 1}]}))
    # every resubmission is a NEW doc; the older ones hold the revisions that were requested
    for i in range(revisions):
        env.run(env.db.work_submissions.insert_one({
            "id": f"old{i}", "campaign_id": "c1", "creator_id": creator, "status": "revision_requested",
            "submitted_at": f"2026-10-1{i}T10:00:00+00:00", "revisions": [{"requested_at": f"2026-10-1{i}T11:00:00+00:00"}]}))
    env.run(env.db.work_submissions.insert_one({
        "id": "latest", "campaign_id": "c1", "creator_id": creator, "status": "submitted", "work_files": ["v.mp4"],
        "submitted_at": "2026-10-12T10:00:00+00:00", "revisions": []}))

    row = env.call("GET", "/business/work-review", brand_t).json()[0]
    assert row["revisionsUsed"] == revisions
    assert row["freeRevisionsRemaining"] == remaining
    assert row["nextRevisionFee"] == next_fee
    assert row["paidRevisionFee"] == 500


def test_work_campaign_route_carries_revision_counters_for_the_brand(env):
    brand_t, brand = env.signup("business")
    _, creator = env.signup("creator")
    env.run(env.db.campaigns.insert_one({"id": "c2", "business_id": brand, "title": "T", "status": "work_submitted",
                                         "selected_creator": creator, "selected_creators": [creator]}))
    env.run(env.db.work_submissions.insert_one({
        "id": "o1", "campaign_id": "c2", "creator_id": creator, "status": "revision_requested",
        "submitted_at": "2026-10-10T10:00:00+00:00", "revisions": [{"requested_at": "2026-10-10T11:00:00+00:00"}]}))
    env.run(env.db.work_submissions.insert_one({
        "id": "o2", "campaign_id": "c2", "creator_id": creator, "status": "submitted", "work_files": ["v.mp4"],
        "submitted_at": "2026-10-12T10:00:00+00:00", "revisions": []}))
    body = env.call("GET", "/work/campaign/c2", brand_t).json()
    assert body["revision_count_used"] == 1            # counted across the resubmission
    assert body["free_revisions_remaining"] == 1
    assert body["next_revision_fee"] == 0 and body["paid_revision_fee"] == 500
