import pytest
from unittest.mock import AsyncMock
from mongomock_motor import AsyncMongoMockClient

import server
from portfolio_helpers import creator_portfolio


@pytest.fixture
def isolated(monkeypatch):
    database = AsyncMongoMockClient()["oct13_feedback"]
    monkeypatch.setattr(server, "db", database)
    monkeypatch.setattr(server, "notify_user", AsyncMock())
    return database


@pytest.mark.asyncio
async def test_profile_and_directory_expose_all_nested_portfolio_videos(isolated):
    first = {"videoUrl": "https://cdn.example.com/first.mp4", "price": 1000, "category": "Beauty"}
    second = {"videoUrl": "https://cdn.example.com/second.mp4", "delivery": 3}
    user = {"id": "creator", "role": "creator", "portfolio": [first["videoUrl"]],
            "profile": {"portfolio_items": [first, second]}}
    await isolated.users.insert_one(user)
    profile = await server.get_profile("creator", {"id": "brand", "role": "business"})
    directory = server.creator_directory_public_view(user, 0)
    assert profile["portfolio"] == [first, second]
    assert directory["portfolio"] == [first, second]
    assert profile["portfolio"][0]["price"] == 1000


def test_portfolio_deduplicates_and_uses_intro_only_when_no_saved_work_exists():
    assert creator_portfolio({"profile": {"intro_video": "intro.mp4"}}) == ["intro.mp4"]
    assert creator_portfolio({"portfolio": ["one.mp4", "one.mp4", "blob:unsaved"],
                              "profile": {"portfolio": ["two.mp4"], "intro_video": "intro.mp4"}}) == ["one.mp4", "two.mp4"]
    work = creator_portfolio({"profile": {"portfolio_items": [
        {"url": "cover.jpg", "urls": ["cover.jpg", "sample.mp4"], "price": 1000}
    ]}})
    assert work[0]["videoUrl"] == "sample.mp4"


@pytest.mark.asyncio
async def test_address_notifications_reach_both_parties_and_open_the_exact_deal(isolated):
    calls = []
    async def notify(user_id, title, message, **kwargs):
        calls.append((user_id, kwargs))
        await isolated.in_app_notifications.insert_one({"user_id": user_id, "link": kwargs["link"], "category": kwargs["category"]})
    server.notify_user.side_effect = notify
    campaign = {"id": "campaign", "business_id": "brand", "requires_shipment": True,
                "selected_creators": ["creator-a", "creator-b"], "title": "Product"}
    await server.notify_confirm_delivery_address(campaign, "creator-a")
    await server.notify_confirm_delivery_address(campaign, "creator-a")
    assert len(calls) == 2
    assert {uid for uid, _ in calls} == {"brand", "creator-a"}
    brand = next(kwargs for uid, kwargs in calls if uid == "brand")
    assert brand["link"] == "/dashboard/business/campaign/campaign?creator=creator-a"
    assert all(kwargs["email"] for _, kwargs in calls)
    await server.notify_confirm_delivery_address({**campaign, "requires_shipment": False}, "creator-b")
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_dashboard_counts_pending_kyc_gst_and_only_unshipped_requests(isolated, monkeypatch):
    await isolated.users.insert_many([
        {"role": "creator", "kyc": {"status": "pending"}},
        {"role": "creator", "kyc": {"status": "verified"}},
        {"role": "business", "gst": {"status": "pending"}},
    ])
    monkeypatch.setattr(server, "admin_shipping_requests", AsyncMock(return_value=[
        {"status": "pending"}, {"status": "label_generated"}, {"status": "shipped"}, {"status": "delivered"},
    ]))
    stats = await server.get_admin_stats({"id": "admin", "role": "admin", "admin_role": "founder"})
    assert stats["pending_kyc"] == stats["pending_gst"] == 1
    assert stats["pending_shipments"] == 2


@pytest.mark.asyncio
async def test_one_combined_bid_covers_raw_and_edited_for_each_video(isolated):
    await isolated.campaigns.insert_one({"id": "combined", "status": "active", "title": "Two videos",
        "business_id": "brand", "budget_max": 1000, "editing_fee_per_video": 500,
        "deliverable_items": [{"quantity": 2, "raw_required": True, "edited_required": True, "edited_by": "creator"}]})
    await server.submit_bid("combined", server.BidCreate(campaign_id="combined", amount=1500, proposal="I will deliver both files", estimated_delivery_days=3),
        {"id": "creator", "nickname": "Creator", "role": "creator", "approval_status": "approved", "kyc": {"status": "verified"}})
    campaign = await isolated.campaigns.find_one({"id": "combined"})
    bid = campaign["bids"][0]
    assert bid["amount"] == 3000
    assert bid.get("raw_amount") is None and bid.get("edited_amount") is None
