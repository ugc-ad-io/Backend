import uuid

import pytest
from fastapi import HTTPException

import server


TEST_PREFIX = "test-creator-directory"


def make_ids():
    suffix = str(uuid.uuid4())
    return {
        "brand_id": f"{TEST_PREFIX}-brand-{suffix}",
        "creator_a": f"{TEST_PREFIX}-creator-a-{suffix}",
        "creator_b": f"{TEST_PREFIX}-creator-b-{suffix}",
        "creator_hidden": f"{TEST_PREFIX}-creator-hidden-{suffix}",
        "campaign_id": f"{TEST_PREFIX}-campaign-{suffix}",
    }


def brand(user_id, approval_status="approved"):
    return {
        "id": user_id,
        "email": f"{user_id}@example.com",
        "nickname": "Glow Brand",
        "role": "business",
        "approval_status": approval_status,
        "profile": {"industry_category": "Beauty"},
    }


def creator(user_id, **overrides):
    data = {
        "id": user_id,
        "email": f"{user_id}@example.com",
        "phone": "9999999999",
        "password": "secret",
        "payment_methods": {"upi": "hidden"},
        "social_links": {"instagram": "@hidden"},
        "nickname": "beachglow",
        "role": "creator",
        "approval_status": "approved",
        "profile_completed": True,
        "curated_brand_visible": True,
        "primary_category": "Beauty",
        "tags": ["skincare", "demo"],
        "languages": ["English", "Hindi"],
        "city_tier": "Metro",
        "content_style": "Product demo",
        "budget_range": "Rs. 5,000 - Rs. 10,000",
        "portfolio": ["/uploads/portfolio-a.png"],
        "profile_photo": "/uploads/profile-a.png",
        "created_at": "2026-01-01T00:00:00+00:00",
    }
    data.update(overrides)
    return data


async def cleanup(test_ids):
    user_ids = [test_ids["brand_id"], test_ids["creator_a"], test_ids["creator_b"], test_ids["creator_hidden"]]
    await server.db.users.delete_many({"id": {"$in": user_ids}})
    await server.db.campaigns.delete_many({
        "$or": [
            {"id": test_ids["campaign_id"]},
            {"business_id": test_ids["brand_id"]},
            {"selected_creator": {"$in": user_ids}},
        ]
    })
    await server.db.private_invitations.delete_many({
        "$or": [
            {"business_id": test_ids["brand_id"]},
            {"creator_id": {"$in": user_ids}},
            {"campaign_id": test_ids["campaign_id"]},
        ]
    })
    await server.db.chat_action_cards.delete_many({
        "$or": [
            {"sender_id": test_ids["brand_id"]},
            {"recipient_id": {"$in": user_ids}},
            {"participants": {"$in": user_ids}},
        ]
    })


async def seed_directory():
    test_ids = make_ids()
    await cleanup(test_ids)
    brand_user = brand(test_ids["brand_id"])
    creator_a = creator(
        test_ids["creator_a"],
        deliverables_completed=2,
        recent_activity_score=5,
        created_at="2026-01-01T00:00:00+00:00",
    )
    creator_b = creator(
        test_ids["creator_b"],
        nickname="@foodmaker",
        primary_category="Food",
        tags=["recipe"],
        languages=["Tamil"],
        city_tier="Tier-2",
        content_style="Recipe",
        budget_range="Rs. 10,000 - Rs. 20,000",
        portfolio=["/uploads/portfolio-b.png"],
        profile_photo="/uploads/profile-b.png",
        deliverables_completed=7,
        recent_activity_score=10,
        created_at="2026-02-01T00:00:00+00:00",
    )
    hidden = creator(test_ids["creator_hidden"], curated_brand_visible=False, creator_directory_visible=False)
    await server.db.users.insert_many([brand_user, creator_a, creator_b, hidden])
    return test_ids, brand_user, creator_a, creator_b, hidden


@pytest.mark.asyncio
async def test_business_can_list_only_curated_approved_creators():
    test_ids, brand_user, creator_a, creator_b, _hidden = await seed_directory()
    try:
        response = await server.get_creator_directory(sort="best_match", current_user=brand_user)
        ids = [item["id"] for item in response["creators"]]
        assert ids == [creator_a["id"], creator_b["id"]]
        assert test_ids["creator_hidden"] not in ids
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_non_business_is_rejected_but_pending_business_can_access_directory():
    test_ids, brand_user, creator_a, _creator_b, _hidden = await seed_directory()
    try:
        with pytest.raises(HTTPException) as non_business:
            await server.get_creator_directory(current_user=creator_a)
        assert non_business.value.status_code == 403

        brand_user["approval_status"] = "pending"
        response = await server.get_creator_directory(current_user=brand_user)
        assert {item["id"] for item in response["creators"]} == {
            test_ids["creator_a"],
            test_ids["creator_b"],
        }
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_directory_filters_work():
    test_ids, brand_user, creator_a, _creator_b, _hidden = await seed_directory()
    try:
        response = await server.get_creator_directory(
            category="Beauty",
            language="Hindi",
            region="Metro",
            style="Product demo",
            budget="5,000",
            current_user=brand_user,
        )
        assert [item["id"] for item in response["creators"]] == [creator_a["id"]]
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_directory_sorting_recent_and_active():
    test_ids, brand_user, creator_a, creator_b, _hidden = await seed_directory()
    try:
        recent = await server.get_creator_directory(sort="recent", current_user=brand_user)
        assert [item["id"] for item in recent["creators"]] == [creator_b["id"], creator_a["id"]]

        active = await server.get_creator_directory(sort="active", current_user=brand_user)
        assert [item["id"] for item in active["creators"]] == [creator_b["id"], creator_a["id"]]
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_directory_does_not_return_sensitive_fields():
    test_ids, brand_user, _creator_a, _creator_b, _hidden = await seed_directory()
    try:
        response = await server.get_creator_directory(current_user=brand_user)
        sensitive = {"email", "phone", "password", "payment_methods", "social_links"}
        for row in response["creators"]:
            assert sensitive.isdisjoint(row.keys())
    finally:
        await cleanup(test_ids)


def invite_payload(campaign_id=None):
    return server.CreatorDirectoryInviteCreate(
        campaign_id=campaign_id,
        campaign_name="Summer Skincare Reel",
        deliverable_summary="1 Instagram reel + 3 raw clips",
        budget="Rs. 10,000",
        timeline="7 days",
        usage_rights="30 days paid social usage",
        message="We think your style fits this campaign.",
    )


@pytest.mark.asyncio
async def test_business_can_invite_directory_creator():
    test_ids, brand_user, creator_a, _creator_b, _hidden = await seed_directory()
    try:
        response = await server.invite_creator_from_directory(creator_a["id"], invite_payload(), brand_user)
        assert response["message"] == "Invitation sent"
        assert response["invitation"]["creator_id"] == creator_a["id"]
        assert await server.creator_has_chat_relationship(creator_a["id"], brand_user["id"]) is True
        assert await server.db.chat_action_cards.count_documents({
            "sender_id": brand_user["id"],
            "recipient_id": creator_a["id"],
            "type": "private_invitation",
        }) == 1
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_duplicate_open_directory_invite_is_rejected():
    test_ids, brand_user, creator_a, _creator_b, _hidden = await seed_directory()
    try:
        payload = invite_payload()
        await server.invite_creator_from_directory(creator_a["id"], payload, brand_user)
        with pytest.raises(HTTPException) as duplicate:
            await server.invite_creator_from_directory(creator_a["id"], payload, brand_user)
        assert duplicate.value.status_code == 409
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_creator_not_in_curated_directory_cannot_be_invited():
    test_ids, brand_user, _creator_a, _creator_b, hidden = await seed_directory()
    try:
        with pytest.raises(HTTPException) as exc:
            await server.invite_creator_from_directory(hidden["id"], invite_payload(), brand_user)
        assert exc.value.status_code == 404
    finally:
        await cleanup(test_ids)
