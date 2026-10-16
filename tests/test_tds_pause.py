import creator_features as cf


def test_new_payouts_do_not_withhold_tds_by_default(monkeypatch):
    monkeypatch.delenv("TDS_WITHHOLDING_ENABLED", raising=False)
    assert cf.compute_tds(1000) == 0


def test_tds_can_be_explicitly_reenabled(monkeypatch):
    monkeypatch.setenv("TDS_WITHHOLDING_ENABLED", "true")
    assert cf.compute_tds(1000) == 100
    assert cf.compute_tds(1000, exempt=True) == 0


def test_explicit_pause_disables_withholding(monkeypatch):
    monkeypatch.setenv("TDS_WITHHOLDING_ENABLED", "false")
    assert cf.compute_tds(1000) == 0


def test_paused_tds_flows_through_payout_wallet_invoice_and_receipt(monkeypatch):
    import asyncio
    from unittest.mock import AsyncMock
    from mongomock_motor import AsyncMongoMockClient
    import server

    database = AsyncMongoMockClient()["tds_payout_flow"]
    monkeypatch.setattr(server, "db", database)
    monkeypatch.delenv("TDS_WITHHOLDING_ENABLED", raising=False)
    monkeypatch.setattr(server, "assess_late_delivery", AsyncMock(return_value={
        "is_late": False, "penalty_pct": 0, "severity": None,
    }))
    monkeypatch.setattr(server, "notify_event", AsyncMock())
    monkeypatch.setattr(server, "insert_deal_activity", AsyncMock())

    async def scenario():
        campaign = {"id": "c", "title": "Reel", "business_id": "brand", "selected_creator": "creator"}
        work = {"id": "w", "creator_id": "creator", "campaign_id": "c"}
        await database.campaigns.insert_one(dict(campaign))
        await database.users.insert_many([{"id": "brand"}, {"id": "creator", "balance": 0}])
        await database.escrow.insert_one({"id": "e", "campaign_id": "c", "creator_id": "creator",
                                          "amount": 1000, "status": "held"})
        calculated = await server.schedule_payout_for_deal(campaign, work)
        assert calculated['tds_amount'] == 0
        assert calculated['net_payable'] == 800
        escrow = await database.escrow.find_one({"id": "e"})
        assert await server.release_scheduled_payout(escrow)
        assert not await server.release_scheduled_payout(escrow)
        assert (await database.users.find_one({"id": "creator"}))['balance'] == 800
        invoice = await database.invoices.find_one({"campaign_id": "c"})
        assert invoice['tds_amount'] == 0 and invoice['net_to_creator'] == 800
        receipt = await database.payout_receipts.find_one({"campaign_id": "c"})
        assert receipt['commission_amount'] == 200 and receipt['tds_amount'] == 0
        assert receipt['net_amount'] == 800
        assert await database.payout_receipts.count_documents({}) == 1
        assert (await database.wallet_ledger.find_one({"user_id": "creator"}))['amount'] == 800
    asyncio.run(scenario())
