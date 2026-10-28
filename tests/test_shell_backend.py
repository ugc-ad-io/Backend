"""Backend for the mobile shell: device tokens, blocks, reports, account deletion, social-login audiences."""
import time
import types

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from mongomock_motor import AsyncMongoMockClient

import server


@pytest.fixture
def isolated(monkeypatch):
    database = AsyncMongoMockClient()["shell_backend"]
    monkeypatch.setattr(server, "db", database)
    return database


async def _users(db):
    await db.users.insert_many([
        {"id": "c1", "role": "creator", "nickname": "Cee", "email": "c1@x.io"},
        {"id": "b1", "role": "business", "nickname": "Bee", "email": "b1@x.io"},
        {"id": "a1", "role": "admin", "nickname": "Root", "email": "a1@x.io"},
    ])
    return {"id": "c1", "role": "creator", "nickname": "Cee"}, {"id": "b1", "role": "business", "nickname": "Bee"}


TOKEN = "t" * 40


# ---------------------------------------------------------------- device tokens
@pytest.mark.asyncio
async def test_device_token_upsert_validate_and_delete(isolated):
    creator, brand = await _users(isolated)
    body = server.DeviceTokenIn(token=TOKEN, platform="IOS", app_version="1.3.0")
    await server.register_device_token(body, creator)
    await server.register_device_token(body, creator)  # same user+token stays one row
    rows = await isolated.device_tokens.find({}).to_list(10)
    assert len(rows) == 1 and rows[0]["platform"] == "ios" and rows[0]["created_at"] and rows[0]["updated_at"]

    # the same phone signing in as someone else moves the token
    await server.register_device_token(body, brand)
    rows = await isolated.device_tokens.find({}).to_list(10)
    assert [r["user_id"] for r in rows] == ["b1"]

    for bad in (server.DeviceTokenIn(token="short", platform="ios"),
                server.DeviceTokenIn(token=TOKEN, platform="windows"),
                server.DeviceTokenIn(token=TOKEN)):
        with pytest.raises(HTTPException) as e:
            await server.register_device_token(bad, brand)
        assert e.value.status_code == 400

    await server.remove_device_token(server.DeviceTokenRemove(token=TOKEN), creator)  # not hers: no-op
    assert await isolated.device_tokens.count_documents({}) == 1
    await server.remove_device_token(server.DeviceTokenRemove(token=TOKEN), brand)
    assert await isolated.device_tokens.count_documents({}) == 0


@pytest.mark.asyncio
async def test_push_is_a_safe_noop_without_firebase(isolated, monkeypatch):
    monkeypatch.setattr(server, "FIREBASE_CREDENTIALS_JSON", "")
    monkeypatch.setattr(server, "FIREBASE_CREDENTIALS_PATH", "")
    assert await server.send_push_to_user("c1", "t", "b", {"path": "/x"}) == 0
    server.queue_push("c1", "t", "b", "/x", "n1")  # must not raise or spawn anything
    assert not server._push_tasks
    # a configured-but-broken credential also degrades to a no-op
    monkeypatch.setattr(server, "FIREBASE_CREDENTIALS_JSON", "not json")
    monkeypatch.setitem(server._firebase_state, "failed", False)
    assert await server.send_push_to_user("c1", "t", "b") == 0
    assert server._firebase_state["failed"] is True


# ---------------------------------------------------------------- blocks
@pytest.mark.asyncio
async def test_block_stops_messages_and_hides_conversation(isolated):
    creator, brand = await _users(isolated)
    await isolated.messages.insert_one({
        "id": "m1", "sender_id": "c1", "recipient_id": "b1", "message": "hi",
        "timestamp": "2026-10-01T00:00:00+00:00", "created_at": "2026-10-01T00:00:00+00:00",
        "read": False, "read_by": ["c1"]})
    assert len(await server.get_conversations(brand)) == 1

    await server.block_user(server.BlockIn(user_id="c1"), brand)
    await server.block_user(server.BlockIn(user_id="c1"), brand)  # idempotent
    assert await isolated.blocks.count_documents({}) == 1
    assert [b["user_id"] for b in (await server.list_blocks(brand))["blocks"]] == ["c1"]
    assert await server.get_conversations(brand) == []
    chat_unread = [r.endpoint for r in server.api_router.routes if r.path.endswith("/chat/unread-count")][0]
    assert (await chat_unread(brand))["unread_count"] == 0
    assert len(await server.get_conversations(creator)) == 1  # the blocked side keeps their view

    with pytest.raises(HTTPException) as e:  # blocked creator cannot write to the blocker
        await server.validate_chat_access(creator, "b1")
    assert e.value.status_code == 403 and "can't message" in e.value.detail
    with pytest.raises(HTTPException) as e:  # and the blocker is told to unblock first
        await server.validate_chat_access(brand, "c1")
    assert e.value.status_code == 403 and "Unblock" in e.value.detail

    await server.unblock_user("c1", brand)
    assert (await server.list_blocks(brand))["blocks"] == []
    assert len(await server.get_conversations(brand)) == 1


@pytest.mark.asyncio
async def test_block_rules(isolated):
    creator, _ = await _users(isolated)
    for target, code in (("c1", 400), ("nobody", 404), ("a1", 400)):
        with pytest.raises(HTTPException) as e:
            await server.block_user(server.BlockIn(user_id=target), creator)
        assert e.value.status_code == code


# ---------------------------------------------------------------- reports
@pytest.mark.asyncio
async def test_report_dedupe_validation_and_rate_limit(isolated, monkeypatch):
    creator, _ = await _users(isolated)
    await isolated.messages.insert_one({"id": "m1", "sender_id": "b1", "recipient_id": "c1", "message": "bad text"})
    notified = []

    async def fake_notify(*a, **k):
        notified.append(a)
    monkeypatch.setattr(server, "notify_admins", fake_notify)

    r = await server.create_content_report(
        server.ContentReportIn(target_type="message", target_id="m1", reason="Harassment", note="n"), creator)
    assert r["ok"] and not r["already_reported"] and len(notified) == 1
    doc = await isolated.reports.find_one({"id": r["report_id"]})
    assert doc["reported_user_id"] == "b1" and doc["content_excerpt"] == "bad text" and doc["status"] == "open"
    again = await server.create_content_report(
        server.ContentReportIn(target_type="message", target_id="m1", reason="Spam"), creator)
    assert again["already_reported"] and again["report_id"] == r["report_id"]
    assert await isolated.reports.count_documents({}) == 1

    for bad in (server.ContentReportIn(target_type="vehicle", target_id="x", reason="r"),
                server.ContentReportIn(target_type="user", target_id="", reason="r"),
                server.ContentReportIn(target_type="user", target_id="b1", reason=""),
                server.ContentReportIn(target_type="user", target_id="c1", reason="r")):
        with pytest.raises(HTTPException) as e:
            await server.create_content_report(bad, creator)
        assert e.value.status_code == 400

    for i in range(9):
        await server.create_content_report(
            server.ContentReportIn(target_type="campaign", target_id=f"camp{i}", reason="Scam"), creator)
    with pytest.raises(HTTPException) as e:
        await server.create_content_report(
            server.ContentReportIn(target_type="review", target_id="rev", reason="Fake"), creator)
    assert e.value.status_code == 429


# ---------------------------------------------------------------- account deletion
@pytest.mark.asyncio
async def test_delete_profile_removes_personal_data_and_tokens(isolated, monkeypatch):
    creator, brand = await _users(isolated)

    async def fake_email(*a, **k):
        return {}
    monkeypatch.setattr(server, "send_email", fake_email)
    await server.register_device_token(server.DeviceTokenIn(token=TOKEN, platform="android"), creator)
    await server.block_user(server.BlockIn(user_id="b1"), creator)
    await isolated.messages.insert_one({"id": "m1", "sender_id": "c1", "recipient_id": "b1", "sender_nickname": "Cee"})
    await isolated.in_app_notifications.insert_one({"id": "n1", "user_id": "c1"})

    await server.delete_profile({**creator, "email": "c1@x.io"})
    assert await isolated.users.find_one({"id": "c1"}) is None
    assert await isolated.users.find_one({"id": "b1"}) is not None  # someone else's account is untouched
    assert await isolated.device_tokens.count_documents({}) == 0
    assert await isolated.blocks.count_documents({}) == 0
    assert await isolated.in_app_notifications.count_documents({"user_id": "c1"}) == 0
    assert (await isolated.messages.find_one({"id": "m1"}))["sender_nickname"] == "Deleted user"

    with pytest.raises(HTTPException) as e:  # staff cannot self-delete from the app
        await server.delete_profile({"id": "a1", "role": "admin"})
    assert e.value.status_code == 403
    assert await isolated.users.find_one({"id": "a1"}) is not None


@pytest.mark.asyncio
async def test_deactivate_drops_device_tokens(isolated, monkeypatch):
    creator, _ = await _users(isolated)

    async def fake_event(*a, **k):
        return None
    monkeypatch.setattr(server, "notify_event", fake_event)
    await server.register_device_token(server.DeviceTokenIn(token=TOKEN, platform="ios"), creator)
    await server.deactivate_profile(creator)
    assert await isolated.device_tokens.count_documents({}) == 0


# ---------------------------------------------------------------- Apple / Google
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PRIV = _KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _apple_token(aud="io.ugcad.app", sub="apple-sub-1", email=None):
    claims = {"iss": "https://appleid.apple.com", "aud": aud, "sub": sub, "exp": int(time.time()) + 600}
    if email:
        claims["email"] = email
    return pyjwt.encode(claims, _PRIV, algorithm="RS256")


@pytest.fixture
def apple(monkeypatch, isolated):
    monkeypatch.setattr(server, "_APPLE_JWKS", types.SimpleNamespace(
        get_signing_key_from_jwt=lambda t: types.SimpleNamespace(key=_KEY.public_key())))
    monkeypatch.setattr(server, "APPLE_AUDIENCES", ["io.ugcad.app", "io.ugcad.web"])

    async def noop(*a, **k):
        return None
    monkeypatch.setattr(server, "send_welcome_notification", noop)
    return isolated


@pytest.mark.asyncio
async def test_apple_first_and_later_logins(apple):
    # first login: relay email + name object from the shell bridge, brand chosen
    req = server.AppleAuthRequest(identity_token=_apple_token(email="x@privaterelay.appleid.com"),
                                  role="business", full_name={"givenName": "Asha", "familyName": "Rao"})
    first = await server.apple_auth(req)
    assert first["role"] == "business" and first["token"] and first["user_id"]
    for key in ("admin_caps", "profile", "review", "is_team_member"):  # same shape as /auth/login
        assert key in first
    user = await apple.users.find_one({"apple_id": "apple-sub-1"})
    assert user["email"] == "x@privaterelay.appleid.com" and user["full_name"] == "Asha Rao"

    # later login: only `sub`, no email, no name, no role
    later = await server.apple_auth(server.AppleAuthRequest(identity_token=_apple_token(email=None)))
    assert later["user_id"] == first["user_id"] and later["role"] == "business"
    assert await apple.users.count_documents({}) == 1


@pytest.mark.asyncio
async def test_apple_links_existing_email_and_checks_audience(apple):
    await apple.users.insert_one({"id": "u9", "email": "me@x.io", "role": "creator", "password": "h"})
    out = await server.apple_auth(server.AppleAuthRequest(identity_token=_apple_token(sub="s2", email="me@x.io", aud="io.ugcad.web")))
    assert out["user_id"] == "u9"
    assert (await apple.users.find_one({"id": "u9"}))["apple_id"] == "s2"

    with pytest.raises(HTTPException) as e:
        await server.apple_auth(server.AppleAuthRequest(identity_token=_apple_token(aud="com.evil.app")))
    assert e.value.status_code == 401
    with pytest.raises(HTTPException) as e:  # unknown sub and no email: nothing to create an account with
        await server.apple_auth(server.AppleAuthRequest(identity_token=_apple_token(sub="new")))
    assert e.value.status_code == 401


@pytest.mark.asyncio
async def test_google_accepts_every_configured_client_id(isolated, monkeypatch):
    monkeypatch.setattr(server, "GOOGLE_CLIENT_ID", "web.apps.googleusercontent.com")
    monkeypatch.setattr(server, "GOOGLE_EXTRA_CLIENT_IDS", ["ios.apps.googleusercontent.com"])

    async def noop(*a, **k):
        return None
    monkeypatch.setattr(server, "send_welcome_notification", noop)
    claims = {"aud": "ios.apps.googleusercontent.com", "email": "g@x.io", "email_verified": "true", "sub": "g1", "name": "Gee"}
    monkeypatch.setattr(server, "_verify_google_id_token", lambda c: dict(claims))
    out = await server.google_auth(server.GoogleAuthRequest(credential="c"))
    assert out["token"] and out["role"] == "creator"
    claims["aud"] = "other"
    with pytest.raises(HTTPException) as e:
        await server.google_auth(server.GoogleAuthRequest(credential="c"))
    assert e.value.status_code == 401
