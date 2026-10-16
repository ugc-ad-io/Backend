"""Regression coverage for repeated mobile taps and stage-specific downloads."""
import asyncio
from unittest.mock import AsyncMock

import pytest
from mongomock_motor import AsyncMongoMockClient
import server


@pytest.fixture
def env(monkeypatch):
    database = AsyncMongoMockClient()["submission_feedback"]
    monkeypatch.setattr(server, "db", database)
    monkeypatch.setattr(server, "notify_event", AsyncMock())
    monkeypatch.setattr(server, "insert_deal_activity", AsyncMock())
    monkeypatch.setattr(server, "insert_deal_system_message", AsyncMock())
    monkeypatch.setattr(server, "ensure_ready_for_content", AsyncMock())
    monkeypatch.setattr(server, "ensure_not_delivered", AsyncMock())
    monkeypatch.setattr(server, "edit_stage", AsyncMock(return_value=None))
    monkeypatch.setattr(server, "get_deal_context", AsyncMock(return_value={"campaign": {
        "id": "c", "business_id": "brand", "selected_creator": "creator",
        "deliverable_items": [{"type": "Reel", "quantity": 1}],
    }}))
    return database


def test_repeated_content_taps_create_one_round_and_one_chat_message(env):
    async def scenario():
        for _ in range(4):
            await server.submit_deal_content("c", server.DealContentSubmit(video_url="https://cdn.example.com/edit.mp4"),
                                             {"id": "creator", "role": "creator"})
        assert await env.deal_content_submissions.count_documents({}) == 1
        assert await env.work_submissions.count_documents({}) == 1
        assert server.insert_deal_system_message.await_count == 1
        assert server.notify_event.await_count == 1
        # A requested revision must still allow a new round.
        await env.deal_content_submissions.update_one({}, {"$set": {"status": "revision_requested"}})
        await server.submit_deal_content("c", server.DealContentSubmit(video_url="https://cdn.example.com/v2.mp4"),
                                         {"id": "creator", "role": "creator"})
        assert await env.deal_content_submissions.count_documents({}) == 2
    asyncio.run(scenario())


def test_repeated_receipt_taps_notify_brand_once(env):
    async def scenario():
        for _ in range(3):
            await server.submit_deal_receipt("c", server.DealReceiptSubmit(unboxing_video_url="https://cdn.example.com/unboxing.mp4"), {"id": "creator", "role": "creator"})
        assert await env.deal_receipts.count_documents({}) == 1
        assert server.notify_event.await_count == 1
    asyncio.run(scenario())


def test_raw_and_edited_downloads_resolve_different_files(env):
    async def scenario():
        await env.campaigns.insert_one({"id": "c", "business_id": "brand", "selected_creator": "creator"})
        await env.work_submissions.insert_one({"id": "w", "campaign_id": "c", "creator_id": "creator",
            "status": "approved", "raw_files": ["/uploads/raw.mp4"], "edited_files": ["/uploads/edit.mp4"],
            "work_files": ["/uploads/edit.mp4", "/uploads/raw.mp4"]})
        user = {"id": "brand", "role": "business"}
        raw = await server.download_work("w", asset="raw", current_user=user)
        edited = await server.download_work("w", asset="edited", current_user=user)
        assert raw.headers["location"] == "/uploads/raw.mp4"
        assert edited.headers["location"] == "/uploads/edit.mp4"
    asyncio.run(scenario())


def test_address_reminder_targets_only_the_missing_party(env, monkeypatch):
    notify = AsyncMock()
    monkeypatch.setattr(server, "notify_user", notify)
    monkeypatch.setattr(server, "log_admin_action", AsyncMock())
    async def scenario():
        await env.campaigns.insert_one({"id": "c", "business_id": "brand", "selected_creator": "creator"})
        await env.shipments.insert_one({"campaign_id": "c", "creator_id": "creator", "pickup_address": {"line1": "Saved"}})
        await server.admin_remind_shipping_address("c", "creator", {"id": "admin", "role": "admin"})
        assert notify.await_count == 1
        assert notify.await_args.args[0] == "creator"
        assert notify.await_args.kwargs['link'] == "/my-deals"
    asyncio.run(scenario())


def test_completed_deal_accepts_a_star_only_review(env):
    async def scenario():
        await env.campaigns.insert_one({"id": "c", "business_id": "brand", "selected_creator": "creator", "status": "completed"})
        await env.users.insert_one({"id": "creator"})
        await server.submit_review(server.ReviewSubmit(campaign_id="c", creator_id="creator", rating=5, review=""),
                                   {"id": "brand", "role": "business"})
        assert await env.reviews.count_documents({"rating": 5}) == 1
    asyncio.run(scenario())
