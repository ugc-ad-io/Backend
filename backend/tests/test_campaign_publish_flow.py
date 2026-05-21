import uuid

import pytest
from fastapi import HTTPException

import server
from campaign_models import CampaignCreateExtended


TEST_PREFIX = "test-campaign-publish-flow"


def business_user(user_id):
    return {
        "id": user_id,
        "email": f"{user_id}@example.com",
        "nickname": "Publish Flow Brand",
        "role": "business",
        "approval_status": "approved",
        "profile": {
            "business_name": "Publish Flow Brand",
            "logo": "/uploads/logo.png",
            "banner": "/uploads/banner.png",
        },
    }


def admin_user():
    return {
        "id": f"{TEST_PREFIX}-admin",
        "email": f"{TEST_PREFIX}-admin@example.com",
        "nickname": "Admin",
        "role": "admin",
        "approval_status": "approved",
    }


async def cleanup(business_id):
    await server.db.campaigns.delete_many({
        "$or": [
            {"business_id": business_id},
            {"title": {"$regex": f"^{TEST_PREFIX}"}},
        ]
    })


def publish_payload(**overrides):
    payload = {
        "status": "pending_approval",
        "title": f"{TEST_PREFIX} launch brief",
        "product_name": "Glow Serum",
        "product_category": "skincare",
        "product_description": "A lightweight vitamin C serum for daily use.",
        "campaign_hook": "Show a realistic morning routine transformation.",
        "key_message": "Brighter-looking skin without a heavy finish.",
        "brief_type": "ugc_video",
        "video_format": "reel",
        "aspect_ratio": "9:16",
        "duration_seconds": 30,
        "creator_level": "mid",
        "content_quality_tier": "premium",
        "gender_preference": "any",
        "city_filter": "Bengaluru",
        "creator_niche_tags": ["beauty", "skincare"],
        "tone_tags": ["warm", "credible"],
        "additional_deliverables": ["raw footage"],
        "per_video_budget": 2500,
        "total_budget": 10000,
        "budget_min": 2000,
        "budget_max": 3000,
        "brief_text": "Create an authentic product routine video with a clear hook.",
        "deadline": "2026-06-15",
        "due_date": "2026-06-12",
        "requires_shipment": True,
        "shipment_required": True,
        "free_revisions": 2,
        "revision_limit": 2,
    }
    payload.update(overrides)
    return payload


@pytest.mark.asyncio
async def test_create_pending_approval_campaign_success():
    business_id = f"{TEST_PREFIX}-brand-{uuid.uuid4()}"
    current_user = business_user(business_id)
    await cleanup(business_id)
    try:
        response = await server.create_campaign(
            CampaignCreateExtended(**publish_payload()),
            current_user,
        )

        assert response == {
            "campaign_id": response["campaign_id"],
            "status": "pending_approval",
            "message": "Campaign submitted for approval",
        }

        saved = await server.db.campaigns.find_one({"id": response["campaign_id"]}, {"_id": 0})
        assert saved["status"] == "pending_approval"
        assert saved["product_name"] == "Glow Serum"
        assert saved["brief_text"] == "Create an authentic product routine video with a clear hook."
        assert saved["creator_niche_tags"] == ["beauty", "skincare"]
        assert saved["shipment_required"] is True
        assert saved["requires_shipment"] is True
        assert saved["submitted_at"]
    finally:
        await cleanup(business_id)


@pytest.mark.asyncio
async def test_create_draft_campaign_allows_partial_fields():
    business_id = f"{TEST_PREFIX}-brand-{uuid.uuid4()}"
    current_user = business_user(business_id)
    await cleanup(business_id)
    try:
        response = await server.create_campaign(
            CampaignCreateExtended(status="draft", product_name="Partial product"),
            current_user,
        )

        assert response["status"] == "draft"
        assert response["message"] == "Draft campaign created"

        saved = await server.db.campaigns.find_one({"id": response["campaign_id"]}, {"_id": 0})
        assert saved["status"] == "draft"
        assert saved["product_name"] == "Partial product"
        assert "submitted_at" not in saved
    finally:
        await cleanup(business_id)


@pytest.mark.asyncio
async def test_pending_approval_missing_required_fields_returns_field_errors():
    business_id = f"{TEST_PREFIX}-brand-{uuid.uuid4()}"
    current_user = business_user(business_id)
    await cleanup(business_id)
    payload = publish_payload(product_name=None, creator_level=None)

    try:
        with pytest.raises(HTTPException) as exc_info:
            await server.create_campaign(CampaignCreateExtended(**payload), current_user)

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail == {
            "message": "Campaign validation failed",
            "fields": {
                "product_name": "Product name is required",
                "creator_level": "Creator level is required",
            },
        }
        assert await server.db.campaigns.count_documents({"business_id": business_id}) == 0
    finally:
        await cleanup(business_id)


@pytest.mark.asyncio
async def test_pending_campaigns_include_pending_approval_and_exclude_drafts():
    business_id = f"{TEST_PREFIX}-brand-{uuid.uuid4()}"
    current_user = business_user(business_id)
    await cleanup(business_id)
    try:
        pending_response = await server.create_campaign(
            CampaignCreateExtended(**publish_payload(title=f"{TEST_PREFIX} pending")),
            current_user,
        )
        draft_response = await server.create_campaign(
            CampaignCreateExtended(status="draft", product_name="Draft only"),
            current_user,
        )

        pending_campaigns = await server.get_pending_campaigns(admin_user())
        pending_ids = {campaign["id"] for campaign in pending_campaigns}

        assert pending_response["campaign_id"] in pending_ids
        assert draft_response["campaign_id"] not in pending_ids

        await server.approve_campaign(
            server.ApprovalAction(item_id=pending_response["campaign_id"], action="approve"),
            admin_user(),
        )
        approved = await server.db.campaigns.find_one(
            {"id": pending_response["campaign_id"]},
            {"_id": 0},
        )
        assert approved["status"] == "active"
    finally:
        await cleanup(business_id)
