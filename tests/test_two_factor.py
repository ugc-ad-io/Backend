import uuid
from datetime import datetime, timedelta, timezone

import pyotp
import pytest
from fastapi import HTTPException

import server


async def _user_with_2fa():
    secret = pyotp.random_base32()
    user = {
        "id": f"test-2fa-{uuid.uuid4()}",
        "email": f"test-2fa-{uuid.uuid4().hex[:8]}@example.com",
        "password": server.hash_password("old-pass-1"),
        "role": "creator",
        "google_id": "google-sub",
        "two_factor_enabled": True,
        "two_factor_secret": secret,
        "reset_code": server._reset_code_hash("111111"),
        "reset_code_expires": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
    }
    await server.db.users.insert_one(dict(user))
    return user, secret


@pytest.mark.asyncio
async def test_every_sign_in_route_requires_the_second_factor():
    user, secret = await _user_with_2fa()
    login = server.LoginRequest(email=user["email"], password="old-pass-1")
    google = server.GoogleAuthRequest(credential="google-id-token")
    real_verify, real_client = server._verify_google_id_token, server.GOOGLE_CLIENT_ID
    server.GOOGLE_CLIENT_ID = "client"
    server._verify_google_id_token = lambda _: {"aud": "client", "email": user["email"], "email_verified": "true", "sub": "google-sub"}
    try:
        # Password alone: asked for a code, and handed no token of any kind.
        reply = await server.login(login)
        assert reply.get("requires_2fa") is True
        assert not any("token" in key for key in reply)

        with pytest.raises(HTTPException) as wrong:
            await server.login(login, totp_token="000000")
        assert wrong.value.status_code == 401
        assert (await server.login(login, totp_token=pyotp.TOTP(secret).now()))["token"]

        # Google used to skip 2FA entirely.
        reply = await server.google_auth(google)
        assert reply.get("requires_2fa") is True and "token" not in reply
        assert (await server.google_auth(google, totp_token=pyotp.TOTP(secret).now()))["token"]

        # A reset code (inbox access) changes the password but does not sign in.
        reply = await server.reset_password(server.ResetPasswordRequest(email=user["email"], code="111111", password="new-pass-1"))
        assert reply.get("requires_2fa") is True and "token" not in reply
    finally:
        server._verify_google_id_token, server.GOOGLE_CLIENT_ID = real_verify, real_client
        await server.db.users.delete_one({"id": user["id"]})
