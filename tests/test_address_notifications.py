"""Address prompts must be persisted for both parties when a shipping deal is confirmed."""
from unittest.mock import AsyncMock

import pytest
from mongomock_motor import AsyncMongoMockClient

import server


@pytest.fixture
def database(monkeypatch):
    db = AsyncMongoMockClient()["address_prompts"]
    monkeypatch.setattr(server, "db", db)
    monkeypatch.setattr(server, "_address_recovery_ran_at", {})
    monkeypatch.setattr(server, "send_email", AsyncMock(return_value={"skipped": True}))
    monkeypatch.setattr(server, "insert_deal_system_message", AsyncMock())
    return db


async def seed_booking(db, **overrides):
    campaign = {"id": "shipping-deal", "title": "Serum", "business_id": "brand",
                "selected_creator": "creator", "requires_shipment": True,
                "status": "in_progress", "booking_status": "price_revision",
                "amount_paid": 1200, "proposed_amount": 1000}
    campaign.update(overrides)
    await db.campaigns.insert_one(campaign)
    await db.users.insert_many([{"id": "brand", "role": "business", "balance": 10000},
                                {"id": "creator", "role": "creator"}])
    await db.escrow.insert_one({"id": "escrow", "campaign_id": campaign["id"],
                               "creator_id": "creator", "amount": 1000, "status": "held"})
    return campaign


async def assert_both_prompts(db):
    prompts = await db.in_app_notifications.find({"category": "delivery_address"}).to_list(10)
    assert len(prompts) == 2
    assert {n["user_id"] for n in prompts} == {"brand", "creator"}
    for user_id, role, link in [
        ("creator", "creator", "/my-deals?campaign=shipping-deal"),
        ("brand", "business", "/dashboard/business/campaign/shipping-deal?creator=creator"),
    ]:
        feed = await server.get_my_notifications({"id": user_id, "role": role})
        assert any(n["category"] == "delivery_address" and n["link"] == link and not n["read"] for n in feed)


@pytest.mark.asyncio
async def test_counter_price_acceptance_persists_prompts_in_both_feeds(database):
    await seed_booking(database)
    await server.decide_booking_price("shipping-deal", server.BookingPriceDecision(action="accept"),
                                      {"id": "brand", "role": "business"})
    await assert_both_prompts(database)


@pytest.mark.asyncio
async def test_normal_booking_acceptance_persists_prompts_in_both_feeds(database):
    await seed_booking(database, booking_status="pending_creator")
    await server.respond_to_booking("shipping-deal", server.BookingRespond(action="accept"),
                                     {"id": "creator", "role": "creator"})
    await assert_both_prompts(database)


@pytest.mark.asyncio
async def test_prompts_are_not_duplicated_on_retry(database):
    campaign = await seed_booking(database)
    await server.notify_confirm_delivery_address(campaign, "creator")
    await server.notify_confirm_delivery_address(campaign, "creator")
    await assert_both_prompts(database)


@pytest.mark.asyncio
async def test_non_shipping_booking_does_not_ask_for_addresses(database):
    await seed_booking(database, requires_shipment=False)
    await server.decide_booking_price("shipping-deal", server.BookingPriceDecision(action="accept"),
                                      {"id": "brand", "role": "business"})
    assert await database.in_app_notifications.count_documents({"category": "delivery_address"}) == 0


@pytest.mark.asyncio
async def test_private_invitation_acceptance_persists_both_prompts(database):
    await seed_booking(database)
    card = {"id": "invitation", "type": "private_invitation", "deal_id": "shipping-deal",
            "participants": ["brand", "creator"], "fields": {"budget": 1000}}
    await server.activate_deal_from_card(card)
    await assert_both_prompts(database)


@pytest.mark.asyncio
async def test_private_counter_acceptance_persists_both_prompts(database, monkeypatch):
    campaign = await seed_booking(database)
    await database.escrow.delete_many({})
    monkeypatch.setattr(server, "insert_deal_activity", AsyncMock())
    card = {"id": "counter", "type": "counter_offer", "participants": ["brand", "creator"],
            "fields": {"modified_price": 1000, "timeline": "2027-02-10", "revisions": "1"}}
    await database.chat_action_cards.insert_one(dict(card))
    await server.activate_countered_private_deal(card, campaign)
    await assert_both_prompts(database)


@pytest.mark.asyncio
@pytest.mark.parametrize("viewer", ["creator", "brand"])
async def test_opening_feed_recovers_missing_private_brief_prompts(database, viewer):
    await seed_booking(database, booking_status=None, status="active")
    await database.escrow.update_many({}, {"$set": {"status": "reserved"}})
    await database.chat_action_cards.insert_one({"id": "accepted-invitation", "type": "private_invitation",
        "status": "accept", "deal_id": "shipping-deal", "participants": ["brand", "creator"]})
    user = {"id": viewer, "role": "creator" if viewer == "creator" else "business"}
    await server.get_my_notifications(user)
    await server.get_my_notifications(user)
    await assert_both_prompts(database)
    server.send_email.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("overrides,shipment", [
    ({"booking_status": "pending_creator"}, None),
    ({"status": "rejected", "booking_status": "declined"}, None),
    ({"status": "completed", "booking_status": "accepted"}, None),
    ({"requires_shipment": False, "booking_status": "accepted"}, None),
    ({"booking_status": "accepted"}, {"status": "shipped"}),
    ({"booking_status": "accepted"}, {"delivery_address": {"line1": "Home"}, "pickup_address": {"line1": "Office"}}),
])
async def test_recovery_does_not_prompt_ineligible_deals(database, overrides, shipment):
    await seed_booking(database, **overrides)
    if shipment:
        await database.shipments.insert_one({"campaign_id": "shipping-deal", "creator_id": "creator", **shipment})
    await server.get_my_notifications({"id": "creator", "role": "creator"})
    assert await database.in_app_notifications.count_documents({"category": "delivery_address"}) == 0


@pytest.mark.asyncio
async def test_unaccepted_private_brief_with_reservation_does_not_trigger_recovery(database):
    await seed_booking(database, status="active", booking_status=None)
    await database.escrow.update_many({}, {"$set": {"status": "reserved"}})
    await server.get_my_notifications({"id": "creator", "role": "creator"})
    assert await database.in_app_notifications.count_documents({"category": "delivery_address"}) == 0


@pytest.mark.asyncio
async def test_recovery_only_notifies_party_with_unconfirmed_address(database):
    await seed_booking(database, booking_status="accepted")
    await database.shipments.insert_one({"campaign_id": "shipping-deal", "creator_id": "creator",
                                         "delivery_address": {"line1": "Home"}})
    await server.get_my_notifications({"id": "creator", "role": "creator"})
    prompts = await database.in_app_notifications.find({"category": "delivery_address"}).to_list(10)
    assert [n["user_id"] for n in prompts] == ["brand"]


@pytest.mark.asyncio
async def test_concurrent_recovery_cannot_duplicate_prompts(database, monkeypatch):
    import asyncio
    await seed_booking(database, booking_status="accepted")
    # Force simultaneous callers to both observe a missing prompt before insertion.
    lookup = database.in_app_notifications.find_one
    async def delayed_lookup(*args, **kwargs):
        result = await lookup(*args, **kwargs)
        await asyncio.sleep(0)
        return result
    monkeypatch.setattr(database.in_app_notifications, "find_one", delayed_lookup)
    await asyncio.gather(
        server.get_my_notifications({"id": "creator", "role": "creator"}),
        server.get_my_notifications({"id": "brand", "role": "business"}),
    )
    await assert_both_prompts(database)


@pytest.mark.asyncio
async def test_feed_polls_do_not_rescan_deals_every_time(database, monkeypatch):
    # The bell polls the feed every 15s; the deal scan must not run on each poll.
    scans = []
    real = server.find_shipment
    async def counted(*args, **kwargs):
        scans.append(1)
        return await real(*args, **kwargs)
    monkeypatch.setattr(server, "find_shipment", counted)
    await seed_booking(database, booking_status="accepted")
    user = {"id": "creator", "role": "creator"}
    await server.get_my_notifications(user)
    first = len(scans)
    await server.get_my_notifications(user)
    await server.get_my_notifications(user)
    assert first > 0 and len(scans) == first
