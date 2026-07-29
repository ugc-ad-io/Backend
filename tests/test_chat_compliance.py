import uuid

import pytest
from fastapi import HTTPException

import server


TEST_PREFIX = "test-chat-compliance"


def ids():
    suffix = str(uuid.uuid4())
    return {
        "brand_id": f"{TEST_PREFIX}-brand-{suffix}",
        "creator_id": f"{TEST_PREFIX}-creator-{suffix}",
        "campaign_id": f"{TEST_PREFIX}-campaign-{suffix}",
        "upload_url": f"/uploads/{TEST_PREFIX}-{suffix}.png",
    }


def business(user_id, balance=6000, approval_status="approved"):
    return {
        "id": user_id,
        "email": f"{user_id}@example.com",
        "nickname": "Test Brand",
        "role": "business",
        "approval_status": approval_status,
        "balance": balance,
        "profile": {"website": "https://brand.example.com"},
    }


def creator(user_id):
    return {
        "id": user_id,
        "email": f"{user_id}@example.com",
        "nickname": "Test Creator",
        "role": "creator",
        "approval_status": "approved",
        "balance": 0,
    }


async def cleanup(test_ids):
    user_ids = [test_ids["brand_id"], test_ids["creator_id"]]
    campaign_ids = [test_ids["campaign_id"]]
    collections = [
        server.db.users,
        server.db.campaigns,
        server.db.messages,
        server.db.chat_action_cards,
        server.db.uploaded_files,
        server.db.violations,
        server.db.chat_strikes,
        server.db.chat_pauses,
        server.db.in_app_notifications,
        server.db.admin_notifications,
        server.db.chat_false_positive_reviews,
        server.db.chat_typing,
        server.db.escrow,
        server.db.campaign_invites,
        server.db.creator_invitations,
        server.db.private_invitations,
    ]
    for collection in collections:
        await collection.delete_many({
            "$or": [
                {"id": {"$regex": f"^{TEST_PREFIX}"}},
                {"user_id": {"$in": user_ids}},
                {"sender_id": {"$in": user_ids}},
                {"recipient_id": {"$in": user_ids}},
                {"participants": {"$all": user_ids}},
                {"business_id": test_ids["brand_id"]},
                {"creator_id": test_ids["creator_id"]},
                {"campaign_id": {"$in": campaign_ids}},
                {"file_url": test_ids["upload_url"]},
            ]
        })


async def seed_pair(with_deal=False, brand_balance=6000, approval_status="approved"):
    test_ids = ids()
    await cleanup(test_ids)
    brand = business(test_ids["brand_id"], balance=brand_balance, approval_status=approval_status)
    crt = creator(test_ids["creator_id"])
    await server.db.users.insert_many([brand, crt])
    if with_deal:
        await server.db.campaigns.insert_one({
            "id": test_ids["campaign_id"],
            "business_id": test_ids["brand_id"],
            "selected_creator": test_ids["creator_id"],
            "status": "in_progress",
            "title": "Test Campaign",
        })
    return test_ids, brand, crt


@pytest.mark.asyncio
async def test_text_message_send_real_db():
    test_ids, brand, _crt = await seed_pair()
    try:
        payload = server.ChatMessage(recipient_id=test_ids["creator_id"], message="Hello", attachment_urls=[])
        await server.send_message(payload, brand)
        saved = await server.db.messages.find_one({"sender_id": test_ids["brand_id"], "recipient_id": test_ids["creator_id"]})
        assert saved["message"] == "Hello"
        assert saved["status"] == "delivered"
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_attachment_only_message_send_real_db():
    test_ids, brand, _crt = await seed_pair()
    try:
        await server.db.uploaded_files.insert_one({
            "id": f"{TEST_PREFIX}-upload-{uuid.uuid4()}",
            "file_url": test_ids["upload_url"],
            "filename": "test.png",
            "content_type": "image/png",
            "size": 100,
            "kind": "image",
            "uploaded_by": test_ids["brand_id"],
        })
        payload = server.ChatMessage(recipient_id=test_ids["creator_id"], message="", attachment_urls=[test_ids["upload_url"]])
        await server.send_message(payload, brand)
        saved = await server.db.messages.find_one({"sender_id": test_ids["brand_id"], "recipient_id": test_ids["creator_id"]})
        assert saved["message"] == ""
        assert saved["attachment_urls"] == [test_ids["upload_url"]]
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_blocked_contact_info_message_real_db():
    test_ids, brand, _crt = await seed_pair()
    try:
        payload = server.ChatMessage(recipient_id=test_ids["creator_id"], message="Call 98765 43210", attachment_urls=[])
        with pytest.raises(HTTPException) as exc:
            await server.send_message(payload, brand)
        assert exc.value.status_code == 400
        assert await server.db.messages.count_documents({"sender_id": test_ids["brand_id"]}) == 0
        assert await server.db.violations.count_documents({"user_id": test_ids["brand_id"]}) == 1
        assert await server.db.chat_strikes.count_documents({"user_id": test_ids["brand_id"]}) == 1
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_strike_progression_real_db():
    test_ids, brand, _crt = await seed_pair()
    try:
        for _ in range(3):
            await server.log_chat_violation(
                brand,
                test_ids["creator_id"],
                "wa.me/test",
                [{"type": "contact_link", "severity": "high"}],
            )
        updated = await server.db.users.find_one({"id": test_ids["brand_id"]})
        assert updated.get("action_cards_only_until")
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_brand_wallet_gate_real_db():
    test_ids, brand, _crt = await seed_pair(brand_balance=100)
    try:
        with pytest.raises(HTTPException) as exc:
            await server.validate_chat_access(brand, test_ids["creator_id"])
        assert exc.value.status_code == 403
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_creator_can_start_chat_without_invite_or_deal_real_db():
    test_ids, _brand, crt = await seed_pair()
    try:
        recipient = await server.validate_chat_access(crt, test_ids["brand_id"])
        assert recipient["id"] == test_ids["brand_id"]
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_action_card_creation_and_immutability_real_db():
    test_ids, brand, crt = await seed_pair()
    try:
        data = server.ChatActionCardCreate(
            recipient_id=test_ids["creator_id"],
            type="custom_offer",
            fields={
                "deliverable_type": "video",
                "quantity": 1,
                "duration": "30s",
                "price": 12000,
                "timeline": "7 days",
                "usage_rights": "organic",
            },
        )
        await server.create_chat_action_card(data, brand)
        card = await server.db.chat_action_cards.find_one({"sender_id": test_ids["brand_id"]})
        original_fields = card["fields"].copy()
        await server.respond_chat_action_card(card["id"], server.ChatActionCardRespond(action="accept"), crt)
        updated = await server.db.chat_action_cards.find_one({"id": card["id"]})
        assert updated["fields"] == original_fields
        assert updated["status"] == "accept"
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_chat_history_returns_messages_and_action_cards_real_db():
    test_ids, brand, crt = await seed_pair(with_deal=True)
    try:
        await server.db.messages.insert_one({
            "id": f"{TEST_PREFIX}-message-{uuid.uuid4()}",
            "sender_id": test_ids["brand_id"],
            "recipient_id": test_ids["creator_id"],
            "message": "Hi",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "read": False,
        })
        await server.db.chat_action_cards.insert_one({
            "id": f"{TEST_PREFIX}-card-{uuid.uuid4()}",
            "participants": [test_ids["brand_id"], test_ids["creator_id"]],
            "sender_id": test_ids["brand_id"],
            "recipient_id": test_ids["creator_id"],
            "type": "milestone_update",
            "fields": {"status": "sent"},
            "status": "open",
            "created_at": "2026-01-01T00:01:00+00:00",
            "read_by": [],
        })
        items = await server.get_chat_history(test_ids["brand_id"], crt)
        assert [item["item_type"] for item in items] == ["message", "action_card"]
    finally:
        await cleanup(test_ids)


def test_attachment_validation_rejects_unsupported_file():
    with pytest.raises(HTTPException):
        server.validate_upload_payload("application/x-msdownload", "run.exe", 100)
