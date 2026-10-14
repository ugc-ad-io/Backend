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
async def test_creator_counteroffer_notifies_brand_with_campaign_room_link(isolated, monkeypatch):
    monkeypatch.setattr(server, 'validate_chat_access', AsyncMock())
    monkeypatch.setattr(server, 'validate_action_card_payload', AsyncMock(return_value={'modified_price': 1500}))
    monkeypatch.setattr(server, 'record_match_event', AsyncMock())
    monkeypatch.setattr(server, 'find_countered_private_campaign', AsyncMock(return_value={'id': 'private-campaign'}))
    data = server.ChatActionCardCreate(recipient_id='brand', type='counter_offer', fields={'modified_price': 1500})
    await server.create_chat_action_card(data, {'id': 'creator', 'role': 'creator', 'nickname': 'Arushi'})
    args, kwargs = server.notify_user.call_args
    assert args[0] == 'brand'
    assert args[1] == 'Creator sent a counteroffer'
    assert '1,500' in args[2]
    assert kwargs['link'] == '/dashboard/business/campaign/private-campaign?creator=creator'
    assert server.notify_user.call_count == 1


@pytest.mark.asyncio
async def test_counteroffer_without_campaign_opens_messages(isolated, monkeypatch):
    monkeypatch.setattr(server, 'validate_chat_access', AsyncMock())
    monkeypatch.setattr(server, 'validate_action_card_payload', AsyncMock(return_value={'modified_price': 1500}))
    monkeypatch.setattr(server, 'record_match_event', AsyncMock())
    monkeypatch.setattr(server, 'find_countered_private_campaign', AsyncMock(return_value=None))
    data = server.ChatActionCardCreate(recipient_id='brand', type='counter_offer', fields={'modified_price': 1500})
    await server.create_chat_action_card(data, {'id': 'creator', 'role': 'creator'})
    assert server.notify_user.call_args.kwargs['link'] == '/messages'


@pytest.mark.asyncio
async def test_private_brief_rejection_notifies_brand_once_with_reason(isolated, monkeypatch):
    monkeypatch.setattr(server, 'record_match_event', AsyncMock())
    monkeypatch.setattr(server, 'get_campaign_by_deal_id', AsyncMock(return_value={'id': 'private', 'title': 'Product brief'}))
    await isolated.chat_action_cards.insert_one({
        'id': 'invitation', 'type': 'private_invitation', 'status': 'open',
        'sender_id': 'brand', 'recipient_id': 'creator', 'participants': ['brand', 'creator'],
        'deal_id': 'deal', 'available_actions': ['reject'], 'created_at': server.now_iso(),
    })
    await isolated.campaigns.insert_one({'id': 'private', 'status': 'active', 'business_id': 'brand'})
    response = server.ChatActionCardRespond(action='reject', decline_reason=server.DECLINE_REASONS[0])
    creator = {'id': 'creator', 'role': 'creator', 'nickname': 'Arushi'}
    await server.respond_chat_action_card('invitation', response, creator)
    args, kwargs = server.notify_user.call_args
    assert args[0] == 'brand'
    assert args[1] == 'Creator rejected your private brief'
    assert 'Product brief' in args[2]
    assert kwargs['link'] == '/dashboard/business/campaign/private?creator=creator'
    assert kwargs['email'] is True
    campaign = await isolated.campaigns.find_one({'id': 'private'})
    assert campaign['status'] == 'rejected'
    assert campaign['booking_status'] == 'declined'
    with pytest.raises(server.HTTPException):
        await server.respond_chat_action_card('invitation', response, creator)
    assert server.notify_user.call_count == 1


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
