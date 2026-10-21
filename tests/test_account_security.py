import bcrypt
import pytest
from fastapi import HTTPException
from mongomock_motor import AsyncMongoMockClient

import server


@pytest.fixture
def isolated(monkeypatch):
    database = AsyncMongoMockClient()["account_security"]
    monkeypatch.setattr(server, "db", database)
    return database


async def _user(db, password="old-password-1"):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    await db.users.insert_one({"id": "u1", "role": "creator", "password": hashed})
    return {"id": "u1", "role": "creator"}


@pytest.mark.asyncio
async def test_change_password_accepts_a_json_body(isolated):
    user = await _user(isolated)
    body = server.ChangePasswordBody(old_password="old-password-1", new_password="new-password-2")
    assert (await server.change_password(body=body, current_user=user))["message"] == "Password changed successfully"
    stored = (await isolated.users.find_one({"id": "u1"}))["password"]
    assert bcrypt.checkpw(b"new-password-2", stored.encode())


@pytest.mark.asyncio
async def test_change_password_query_params_still_work_for_old_clients(isolated):
    user = await _user(isolated)
    await server.change_password(old_password="old-password-1", new_password="another-pass-3", current_user=user)
    stored = (await isolated.users.find_one({"id": "u1"}))["password"]
    assert bcrypt.checkpw(b"another-pass-3", stored.encode())


@pytest.mark.asyncio
async def test_change_password_rules_are_unchanged(isolated):
    user = await _user(isolated)
    with pytest.raises(HTTPException) as short:
        await server.change_password(body=server.ChangePasswordBody(old_password="old-password-1", new_password="short"), current_user=user)
    assert short.value.status_code == 400 and "8 characters" in short.value.detail
    with pytest.raises(HTTPException) as wrong:
        await server.change_password(body=server.ChangePasswordBody(old_password="not-it", new_password="long-enough-1"), current_user=user)
    assert wrong.value.status_code == 400
    with pytest.raises(HTTPException) as missing:
        await server.change_password(current_user=user)
    assert missing.value.status_code == 422


@pytest.mark.asyncio
async def test_a_brand_cannot_mark_its_own_company_verified(isolated):
    brand = {"id": "b1", "role": "business", "approval_status": "pending", "profile": {}}
    await isolated.users.insert_one(dict(brand))
    data = server.BusinessSettingsCompanyUpdate(
        business_type="Retail", business_category="Beauty", country="India", billing_address="1 MG Road",
        city="Indore", state="MP", pincode="452001", kyb_status="verified")
    saved = await server.update_business_settings_company(data, brand)
    company = (await isolated.business_settings.find_one({"business_id": "b1"}))["company"]
    assert company["kyb_status"] == "pending"
    assert company["pincode"] == "452001"
    # once an admin approves the brand, the status follows that approval
    approved = {**brand, "approval_status": server.ApprovalStatus.APPROVED}
    await server.update_business_settings_company(data, approved)
    assert (await isolated.business_settings.find_one({"business_id": "b1"}))["company"]["kyb_status"] == "verified"


@pytest.mark.asyncio
async def test_payout_overview_publishes_the_minimum_withdrawal(isolated):
    creator = {"id": "c1", "role": "creator"}
    await isolated.users.insert_one(dict(creator))
    overview = await server.payout_overview(current_user=creator)
    assert overview["min_withdrawal"] == server.MIN_WITHDRAWAL_AMOUNT


@pytest.mark.asyncio
async def test_answering_a_more_info_request_resubmits_the_profile(isolated, monkeypatch):
    monkeypatch.setattr(server.cf, "validate_portfolio", lambda items: (True, ""))
    monkeypatch.setattr(server.cf, "build_watermark_record", lambda *a, **k: {})
    creator = {"id": "c9", "role": "creator", "approval_status": "more_info",
               "review": {"more_info_message": "Add samples", "more_info_items": ["3 clips"]}}
    await isolated.users.insert_one(dict(creator))
    result = await server.update_portfolio([{"video_url": "/uploads/1.mp4"}], creator)
    stored = await isolated.users.find_one({"id": "c9"})
    assert result["approval_status"] == "pending" and stored["approval_status"] == "pending"
    assert stored["review"]["more_info_message"] == "Add samples" and stored["review"]["resubmitted_at"]

    await isolated.users.update_one({"id": "c9"}, {"$set": {"approval_status": "more_info"}})
    info = await server.update_profile_info(bio="Hello", language=None, current_user=creator)
    assert info["approval_status"] == "pending"


def test_resubmission_only_touches_more_info_profiles():
    for status in ("approved", "pending", "rejected"):
        assert server._resubmission_fields({"approval_status": status}, "now") == {}
    assert server._resubmission_fields({"approval_status": "more_info"}, "now")["approval_status"] == "pending"
