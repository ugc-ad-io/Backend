"""Editing an approved profile applies at once: no "in review", no admin ping.
First submissions and reapplications after a rejection still go to review.
Runs the real routes against an in-memory database."""
import asyncio

import pytest

pytest.importorskip("mongomock_motor")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402
from mongomock_motor import AsyncMongoMockClient  # noqa: E402

import server  # noqa: E402

BRAND_PROFILE = {"business_description": "x", "product_type": "Skincare", "industry_category": "Beauty & Cosmetics"}
CREATOR_PROFILE = {"bio": "b", "tags": ["beauty"], "fullName": "Cre One"}


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("RESEND_API_KEY", "")  # never send real email from a test
    monkeypatch.setattr(server, "db", AsyncMongoMockClient()["profile_edit"])
    loop = asyncio.new_event_loop()
    client = TestClient(server.app, follow_redirects=False)
    run = loop.run_until_complete

    def call(method, path, token=None, **kw):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return client.request(method, "/api" + path, headers=headers, **kw)

    n = {"i": 0}

    def signup(role):
        n["i"] += 1
        b = call("POST", "/auth/signup", json={"email": f"pe-{role}-{n['i']}@example.com", "password": "Passw0rd!x", "role": role,
                                               "phone": f"98765{47000 + n['i']}", "dial_code": "+91", "name": f"P{n['i']}"}).json()
        return b["token"], b["user_id"]

    run(server.db.users.insert_one({"id": "adm", "email": "adm@example.com", "role": "admin", "admin_role": "super_admin",
                                    "approval_status": "approved", "profile_completed": True}))
    admin_t = server.create_token("adm", "adm@example.com", "admin")

    def decide(uid, action):
        body = {"item_id": uid, "action": action}
        if action == "reject":
            body.update(reason_code="other", reason_details="no")
        assert call("POST", "/admin/approve-profile", admin_t, json=body).status_code == 200

    def user(uid):
        return run(server.db.users.find_one({"id": uid}))

    yield type("Env", (), dict(call=staticmethod(call), signup=staticmethod(signup), decide=staticmethod(decide),
                               user=staticmethod(user), run=run, db=server.db))
    loop.close()


def put(env, role, token):
    path, body = ("/profile/creator", CREATOR_PROFILE) if role == "creator" else ("/profile/business", BRAND_PROFILE)
    return env.call("PUT", path, token, json=body)


def test_approved_creator_edit_applies_without_review(env):
    token, uid = env.signup("creator")
    put(env, "creator", token)
    env.decide(uid, "approve")
    env.run(env.db.users.update_one({"id": uid}, {"$set": {"profile_review_status": "pending_review"}}))  # stale flag
    env.run(env.db.admin_notifications.delete_many({}))

    r = put(env, "creator", token)

    assert r.status_code == 200 and r.json()["message"] == "Profile updated"
    u = env.user(uid)
    assert u["approval_status"] == "approved"
    assert "profile_review_status" not in u
    assert env.run(env.db.admin_notifications.count_documents({})) == 0      # nothing for an admin to approve


def test_first_creator_submission_still_goes_to_review(env):
    token, uid = env.signup("creator")
    r = put(env, "creator", token)
    assert r.json()["message"] == "Profile submitted for review"
    assert env.user(uid)["approval_status"] == "pending"


def test_approved_brand_edit_stays_approved(env):
    token, uid = env.signup("business")
    put(env, "business", token)
    env.decide(uid, "approve")

    r = put(env, "business", token)

    assert r.status_code == 200 and r.json()["message"] == "Profile updated"
    assert env.user(uid)["approval_status"] == "approved"


def test_brand_knocked_back_by_an_old_edit_is_restored(env):
    token, uid = env.signup("business")
    put(env, "business", token)
    env.decide(uid, "approve")
    # what the old /profile/business did on every edit: back to pending, approval record kept
    env.run(env.db.users.update_one({"id": uid}, {"$set": {"approval_status": "pending"}}))

    r = put(env, "business", token)

    assert r.json()["approval_status"] == "approved"
    assert env.user(uid)["approval_status"] == "approved"


def test_new_and_rejected_brands_still_go_to_review(env):
    token, uid = env.signup("business")
    assert put(env, "business", token).json()["message"] == "Profile submitted for review"
    assert env.user(uid)["approval_status"] == "pending"

    env.decide(uid, "reject")
    assert put(env, "business", token).json()["approval_status"] == "pending"    # reapplication
    assert env.user(uid)["approval_status"] == "pending"
