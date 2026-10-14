"""A creator with an incomplete profile cannot bid; the bid form asks the server what the
platform fee is. Runs the real routes against an in-memory database."""
import asyncio
import copy

import pytest

pytest.importorskip("mongomock_motor")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402
from mongomock_motor import AsyncMongoMockClient  # noqa: E402

import server  # noqa: E402

FULL_PROFILE = {
    "age": 24, "gender": "female", "bodyType": "slim", "skinTone": "medium",
    "city": "Indore", "state": "MP", "pincode": "452010",
    "languages": ["Hindi", "English"],
}


def creator_doc(uid="cr-1", **overrides):
    doc = {
        "id": uid, "email": f"{uid}@example.com", "role": "creator", "nickname": "Deshna",
        "approval_status": "approved", "profile_completed": True,
        "kyc": {"status": "verified"},
        "profile_photo": "/uploads/me.jpg",
        "portfolio": ["/uploads/intro.mp4"],
        "profile": copy.deepcopy(FULL_PROFILE),
    }
    doc.update(overrides)
    return doc


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("RESEND_API_KEY", "")
    monkeypatch.setattr(server, "db", AsyncMongoMockClient()["bid_gate"])
    loop = asyncio.new_event_loop()
    run = loop.run_until_complete
    client = TestClient(server.app, follow_redirects=False)

    def add_creator(**kw):
        doc = creator_doc(**kw)
        run(server.db.users.insert_one(doc))
        return doc, server.create_token(doc["id"], doc["email"], "creator")

    run(server.db.users.insert_one({"id": "brand-1", "email": "b@example.com", "role": "business",
                                    "approval_status": "approved", "nickname": "Brand"}))
    run(server.db.campaigns.insert_one({
        "id": "camp-1", "title": "Sleeksoul", "business_id": "brand-1", "status": "active",
        "budget_min": 500, "budget_max": 5000, "bids": [],
        "deliverable_items": [{"type": "Reel", "quantity": 1, "raw_required": True, "edited_required": False}],
    }))

    def bid(token, amount=1000):
        return client.post("/api/campaigns/camp-1/bid", headers={"Authorization": f"Bearer {token}"},
                           json={"campaign_id": "camp-1", "amount": amount, "proposal": "I can do this",
                                 "estimated_delivery_days": 3})

    def readiness(token):
        return client.get("/api/creator/bid-readiness", headers={"Authorization": f"Bearer {token}"})

    class E:
        pass
    e = E()
    e.run, e.add_creator, e.bid, e.readiness, e.db = run, add_creator, bid, readiness, server.db
    return e


def test_complete_profile_can_bid(env):
    _, token = env.add_creator()
    r = env.bid(token)
    assert r.status_code == 200, r.text
    camp = env.run(env.db.campaigns.find_one({"id": "camp-1"}))
    assert len(camp["bids"]) == 1


def test_incomplete_profile_cannot_bid_and_is_told_what_is_missing(env):
    _, token = env.add_creator(
        profile_photo="", portfolio=[], profile={"age": 24, "gender": "female"})
    r = env.bid(token)
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert detail.startswith("Complete your profile before bidding")
    for item in ("a profile picture", "city, state and pincode", "languages", "an intro video"):
        assert item in detail
    # nothing was recorded
    assert env.run(env.db.campaigns.find_one({"id": "camp-1"}))["bids"] == []


@pytest.mark.parametrize("remove, label", [
    ({"profile_photo": ""}, "a profile picture"),
    ({"portfolio": []}, "an intro video"),
    ({"profile": {**FULL_PROFILE, "age": None}}, "age, gender, body type and skin tone"),
    ({"profile": {**FULL_PROFILE, "skinTone": ""}}, "age, gender, body type and skin tone"),
    ({"profile": {**FULL_PROFILE, "pincode": ""}}, "city, state and pincode"),
    ({"profile": {**FULL_PROFILE, "languages": []}}, "the languages you create in"),
])
def test_each_missing_item_blocks_a_bid(env, remove, label):
    _, token = env.add_creator(**remove)
    r = env.bid(token)
    assert r.status_code == 403
    assert label in r.json()["detail"]


def test_profile_gate_comes_before_kyc_gate(env):
    # An unverified creator with an empty profile is told to fix the profile first.
    _, token = env.add_creator(kyc={"status": "not_submitted"}, profile_photo="")
    assert "Complete your profile" in env.bid(token).json()["detail"]
    # Once the profile is whole, the KYC gate speaks.
    _, token2 = env.add_creator(uid="cr-2", kyc={"status": "not_submitted"})
    assert "KYC" in env.bid(token2).json()["detail"]


def test_readiness_endpoint_reports_missing_items_and_the_fee(env):
    _, token = env.add_creator(profile_photo="")
    body = env.readiness(token).json()
    assert body["can_bid"] is False
    assert body["missing"] == ["a profile picture"]
    assert body["commission_percent"] == 20.0
    assert "Complete your profile" in body["message"]

    _, ok_token = env.add_creator(uid="cr-2")
    ok = env.readiness(ok_token).json()
    assert ok["can_bid"] is True and ok["missing"] == [] and ok["message"] == ""


def test_readiness_is_creator_only(env):
    token = server.create_token("brand-1", "b@example.com", "business")
    assert env.readiness(token).status_code == 403


def test_signup_only_profile_has_everything_missing():
    missing = server.creator_profile_missing({"profile_completed": True, "profile": {}})
    assert len(missing) == 5
