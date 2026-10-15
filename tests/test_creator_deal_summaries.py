from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from mongomock_motor import AsyncMongoMockClient
import server


@pytest.fixture
def db(monkeypatch):
    database = AsyncMongoMockClient()["creator_summary"]
    monkeypatch.setattr(server, "db", database)
    return database


async def seed(db, count=1):
    await db.users.insert_one({"id": "brand", "nickname": "Brand", "profile": {"business_name": "Sleek", "logo": "logo.png"}})
    await db.campaigns.insert_many([{"id": f"c{i}", "title": f"Deal {i}", "business_id": "brand",
        "selected_creators": ["other", "creator"], "status": "in_progress", "requires_shipment": True,
        "budget_max": 1000, "brief_draft": {"brief_text": "PRIVATE DRAFT"}} for i in range(count)])
    await db.escrow.insert_many([{"id": f"e{i}", "campaign_id": f"c{i}", "creator_id": "creator", "amount": 1800, "status": "held"} for i in range(count)])


@pytest.mark.asyncio
async def test_summary_is_creator_scoped_and_does_not_build_chat_rooms(db, monkeypatch):
    await seed(db)
    monkeypatch.setattr(server, "build_deal_rows", AsyncMock(side_effect=AssertionError("Full room built")))
    await db.work_submissions.insert_one({"campaign_id": "c0", "creator_id": "other", "status": "approved"})
    await db.shipments.insert_one({"campaign_id": "c0", "creator_id": "creator", "status": "in_transit"})
    rows = await server.get_my_deals({"id": "creator", "role": "creator"}, summary=True)
    assert len(rows) == 1
    row = rows[0]
    assert row["current_state"] == "Shipped - In Transit"
    assert row["creator"]["id"] == "creator"
    assert row["escrow"]["held_amount"] == 1800
    assert row["brand"]["name"] == "Sleek"
    assert "brief_draft" not in row["campaign"]
    assert "chat_summary" not in row and "activity" not in row


@pytest.mark.asyncio
async def test_fifty_deals_use_seven_batch_reads_and_no_per_deal_queries(db, monkeypatch):
    await seed(db, 50)
    counts = []
    collections = {}
    for name in ["campaigns", "users", "work_submissions", "escrow", "shipments", "deal_receipts", "deal_action_cards"]:
        collection = db[name]
        collections[name] = collection
        find = collection.find
        def counted(*args, _find=find, _name=name, **kwargs):
            counts.append(_name)
            return _find(*args, **kwargs)
        monkeypatch.setattr(collection, "find", counted)
        monkeypatch.setattr(collection, "find_one", AsyncMock(side_effect=AssertionError("Per-deal read")))
    monkeypatch.setattr(server, "db", SimpleNamespace(**collections))
    rows = await server.get_my_deals({"id": "creator", "role": "creator"}, summary=True)
    assert len(rows) == 50 and len(counts) == 7


@pytest.mark.asyncio
async def test_pending_and_archived_briefs_stay_hidden(db):
    await seed(db)
    for status in ["draft", "pending_approval", "rejected"]:
        await db.campaigns.update_one({"id": "c0"}, {"$set": {"status": status}})
        assert await server.get_my_deals({"id": "creator", "role": "creator"}, summary=True) == []


@pytest.mark.asyncio
async def test_summary_preserves_due_payout_settlement(db, monkeypatch):
    await seed(db)
    await db.escrow.update_one({"id": "e0"}, {"$set": {"payout_status": "scheduled",
        "payout_scheduled_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()}})
    await db.work_submissions.insert_one({"campaign_id": "c0", "creator_id": "creator", "status": "approved"})
    async def settle(campaign):
        await db.escrow.update_one({"id": "e0"}, {"$set": {"status": "released", "payout_status": "paid"}})
    settle_mock = AsyncMock(side_effect=settle)
    monkeypatch.setattr(server, "settle_deal_lazily", settle_mock)
    rows = await server.get_my_deals({"id": "creator", "role": "creator"}, summary=True)
    settle_mock.assert_awaited_once()
    assert rows[0]["current_state"] == "Paid - Complete"


@pytest.mark.asyncio
async def test_detail_loads_only_the_requested_deal(db, monkeypatch):
    context = {"campaign": {"id": "c0"}}
    get_context = AsyncMock(return_value=context)
    build = AsyncMock(return_value={"deal_id": "DEAL-1"})
    monkeypatch.setattr(server, "get_deal_context", get_context)
    monkeypatch.setattr(server, "build_deal_response", build)
    viewer = {"id": "creator", "role": "creator"}
    assert await server.get_single_deal("c0", viewer) == {"deal_id": "DEAL-1"}
    get_context.assert_awaited_once_with("c0", viewer)
    build.assert_awaited_once_with(context, viewer)


@pytest.mark.asyncio
async def test_direct_detail_cannot_expose_an_unapproved_private_brief(db, monkeypatch):
    monkeypatch.setattr(server, "get_deal_context", AsyncMock(return_value={"campaign": {"id": "draft", "status": "pending_approval"}}))
    build = AsyncMock()
    monkeypatch.setattr(server, "build_deal_response", build)
    with pytest.raises(server.HTTPException) as exc:
        await server.get_single_deal("draft", {"id": "creator", "role": "creator"})
    assert exc.value.status_code == 404
    build.assert_not_awaited()
