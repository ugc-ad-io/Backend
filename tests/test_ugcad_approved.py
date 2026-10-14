"""The team's own shortlist: an admin can mark a creator "UGCad approved" and brands see the
flag on the creator directory (it drives the "Meet Creators Approved by Our UGCAD Team"
collection). Runs the real routes against an in-memory database."""
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
    monkeypatch.setattr(server, "db", AsyncMongoMockClient()["ugcad_approved"])
    loop = asyncio.new_event_loop()
    run = loop.run_until_complete
    client = TestClient(server.app, follow_redirects=False)

    def call(method, path, token, **kw):
        return client.request(method, "/api" + path, headers={"Authorization": f"Bearer {token}"}, **kw)

    def creator(uid, **extra):
        doc = {"id": uid, "email": f"{uid}@example.com", "nickname": uid, "role": "creator", "approval_status": "approved",
               "profile_completed": True, "primary_category": "Beauty", "created_at": "2026-01-01T00:00:00+00:00"}
        doc.update(extra)
        run(server.db.users.insert_one(doc))

    creator("c_picked")
    creator("c_plain")
    run(server.db.users.insert_many([
        {"id": "adm", "email": "adm@example.com", "role": "admin", "admin_role": "founder", "approval_status": "approved"},
        {"id": "brd", "email": "brd@example.com", "role": "business", "approval_status": "approved", "nickname": "Brand",
         "profile": {"industry_category": "Beauty"}},
    ]))
    tokens = {
        "admin": server.create_token("adm", "adm@example.com", "admin"),
        "brand": server.create_token("brd", "brd@example.com", "business"),
        "creator": server.create_token("c_plain", "c_plain@example.com", "creator"),
    }
    yield type("Env", (), dict(call=staticmethod(call), t=tokens, run=run, db=server.db))
    loop.close()


def directory(env):
    r = env.call("GET", "/business/creator-directory", env.t["brand"])
    assert r.status_code == 200, r.text
    return {c["id"]: c for c in r.json()["creators"]}


def test_nobody_is_ugcad_approved_until_the_team_picks(env):
    rows = directory(env)
    assert set(rows) == {"c_picked", "c_plain"}
    assert all(c["ugcad_approved"] is False for c in rows.values())


def test_admin_picks_and_unpicks_a_creator(env):
    r = env.call("POST", "/admin/user/ugcad-approved", env.t["admin"], json={"user_id": "c_picked", "approved": True})
    assert r.status_code == 200 and r.json()["ugcad_approved"] is True

    rows = directory(env)
    assert rows["c_picked"]["ugcad_approved"] is True
    assert rows["c_plain"]["ugcad_approved"] is False            # only the picked one
    doc = env.run(env.db.users.find_one({"id": "c_picked"}))
    assert doc["ugcad_approved_by"] == "adm" and doc["ugcad_approved_at"]
    log = env.run(env.db.admin_logs.find_one({"action": "user.ugcad_approved", "target_id": "c_picked"}))
    assert log and log["after"] == {"ugcad_approved": True}      # the audit trail records who picked whom

    r = env.call("POST", "/admin/user/ugcad-approved", env.t["admin"], json={"user_id": "c_picked", "approved": False})
    assert r.status_code == 200 and r.json()["ugcad_approved"] is False
    assert directory(env)["c_picked"]["ugcad_approved"] is False
    doc = env.run(env.db.users.find_one({"id": "c_picked"}))
    assert "ugcad_approved_at" not in doc and "ugcad_approved_by" not in doc


def test_only_admins_and_only_creators(env):
    body = {"user_id": "c_picked", "approved": True}
    assert env.call("POST", "/admin/user/ugcad-approved", env.t["brand"], json=body).status_code in (401, 403)
    assert env.call("POST", "/admin/user/ugcad-approved", env.t["creator"], json=body).status_code in (401, 403)

    r = env.call("POST", "/admin/user/ugcad-approved", env.t["admin"], json={"user_id": "brd", "approved": True})
    assert r.status_code == 400                                   # a brand can't be picked
    assert env.call("POST", "/admin/user/ugcad-approved", env.t["admin"], json={"user_id": "nobody", "approved": True}).status_code == 404
