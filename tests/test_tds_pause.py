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


def test_brand_checkout_has_only_deal_value_and_platform_fee(monkeypatch):
    import server
    monkeypatch.delenv("TDS_WITHHOLDING_ENABLED", raising=False)
    quote = server.quote_brief({"profile": {"rate_card": {"raw_payout": "1000"}}}, 1)
    assert quote['subtotal'] == 1000
    assert quote['fee'] == 200
    assert quote['total'] == 1200
    assert quote.get('tds_amount', 0) == 0


def test_previously_scheduled_payout_drops_saved_tds_when_released(monkeypatch):
    import asyncio
    from unittest.mock import AsyncMock
    from mongomock_motor import AsyncMongoMockClient
    import server
    db = AsyncMongoMockClient()["previously_scheduled"]
    monkeypatch.setattr(server, "db", db)
    monkeypatch.setenv("TDS_WITHHOLDING_ENABLED", "false")
    monkeypatch.setattr(server, "notify_event", AsyncMock())
    monkeypatch.setattr(server, "insert_deal_activity", AsyncMock())
    async def scenario():
        await db.campaigns.insert_one({"id": "c", "business_id": "brand", "selected_creator": "creator"})
        await db.users.insert_one({"id": "creator", "balance": 0})
        escrow = {"id": "e", "campaign_id": "c", "creator_id": "creator", "amount": 1000,
                  "status": "held", "payout_status": "scheduled", "tds_amount": 100,
                  "commission_amount": 200, "net_payable": 700, "deductions": [{"label": "TDS", "amount": 100}]}
        await db.escrow.insert_one(dict(escrow))
        await db.invoices.insert_one({"id": "i", "campaign_id": "c", "creator_id": "creator", "tds_amount": 100, "net_to_creator": 700})
        assert await server.release_scheduled_payout(escrow)
        assert (await db.users.find_one({"id": "creator"}))['balance'] == 800
        updated = await db.escrow.find_one({"id": "e"})
        assert updated['tds_amount'] == 0 and updated['net_payable'] == 800
        assert updated['deductions'][0]['amount'] == 0
        assert (await db.invoices.find_one({"id": "i"}))['net_to_creator'] == 800
        receipt = await db.payout_receipts.find_one({"campaign_id": "c"})
        assert receipt['tds_amount'] == 0 and receipt['net_amount'] == 800
        assert not await server.release_scheduled_payout(escrow)
        assert (await db.users.find_one({"id": "creator"}))['balance'] == 800
    asyncio.run(scenario())
