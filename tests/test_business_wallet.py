import uuid

import pytest
from fastapi import HTTPException

import server


TEST_PREFIX = "test-business-wallet"


def ids():
    suffix = str(uuid.uuid4())
    return {
        "brand_id": f"{TEST_PREFIX}-brand-{suffix}",
        "creator_id": f"{TEST_PREFIX}-creator-{suffix}",
        "campaign_id": f"{TEST_PREFIX}-campaign-{suffix}",
        "order_id": f"cf_wallet_{suffix[:8]}",
    }


def brand(user_id, approval_status="approved", balance=0):
    return {
        "id": user_id,
        "email": f"{user_id}@example.com",
        "nickname": "Wallet Brand",
        "role": "business",
        "approval_status": approval_status,
        "balance": balance,
    }


def creator(user_id):
    return {
        "id": user_id,
        "email": f"{user_id}@example.com",
        "nickname": "Wallet Creator",
        "role": "creator",
        "approval_status": "approved",
    }


async def cleanup(test_ids):
    await server.db.users.delete_many({"id": {"$in": [test_ids["brand_id"], test_ids["creator_id"]]}})
    await server.db.business_settings.delete_many({"business_id": test_ids["brand_id"]})
    await server.db.campaigns.delete_many({
        "$or": [
            {"id": test_ids["campaign_id"]},
            {"business_id": test_ids["brand_id"]},
        ]
    })
    await server.db.escrow.delete_many({"campaign_id": test_ids["campaign_id"]})
    await server.db.payment_transactions.delete_many({
        "$or": [
            {"user_id": test_ids["brand_id"]},
            {"gateway_order_id": test_ids["order_id"]},
            {"id": {"$regex": f"^{TEST_PREFIX}"}},
        ]
    })
    await server.db.wallet_ledger.delete_many({
        "$or": [
            {"user_id": test_ids["brand_id"]},
            {"id": {"$regex": f"^{TEST_PREFIX}"}},
        ]
    })
    await server.db.payment_gateways.delete_many({"id": {"$regex": f"^{TEST_PREFIX}"}})


async def seed_gateway(name="cashfree"):
    await server.db.payment_gateways.delete_many({"gateway_name": name, "id": {"$regex": f"^{TEST_PREFIX}"}})
    doc = {
        "id": f"{TEST_PREFIX}-gateway-{name}-{uuid.uuid4()}",
        "gateway_name": name,
        "key_id": f"test_{name}_key",
        "key_secret": "test_secret",
        "enabled": True,
        "is_default": True,
        "created_at": server.now_iso(),
    }
    await server.db.payment_gateways.insert_one(doc)
    return doc


async def seed_brand(balance=0, approval_status="approved"):
    test_ids = ids()
    await cleanup(test_ids)
    brand_user = brand(test_ids["brand_id"], approval_status=approval_status, balance=balance)
    await server.db.users.insert_one(brand_user)
    return test_ids, brand_user


def recharge_payload(amount=25000, gateway="cashfree"):
    return server.BusinessWalletRechargeCreate(amount=amount, gateway=gateway)


@pytest.mark.asyncio
async def test_wallet_rejects_non_business_and_unapproved_business():
    test_ids, brand_user = await seed_brand(approval_status="pending")
    crt = creator(test_ids["creator_id"])
    await server.db.users.insert_one(crt)
    try:
        with pytest.raises(HTTPException) as non_business:
            await server.get_business_wallet(crt)
        assert non_business.value.status_code == 403

        with pytest.raises(HTTPException) as unapproved:
            await server.get_business_wallet(brand_user)
        assert unapproved.value.status_code == 403
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_wallet_returns_balance_tiers_progress_and_transactions():
    test_ids, brand_user = await seed_brand(balance=25000)
    try:
        await server.db.business_settings.insert_one({
            "id": f"{TEST_PREFIX}-settings-{uuid.uuid4()}",
            "business_id": test_ids["brand_id"],
            "billing": {"plan_name": "Brand Pro"},
        })
        await server.db.wallet_ledger.insert_one({
            "id": f"{TEST_PREFIX}-ledger-{uuid.uuid4()}",
            "user_id": test_ids["brand_id"],
            "type": "Wallet Recharge",
            "amount": 25000,
            "direction": "credit",
            "status": "success",
            "reference": "pay_123",
            "created_at": "2026-05-15T10:00:00+00:00",
        })
        await server.db.campaigns.insert_one({
            "id": test_ids["campaign_id"],
            "business_id": test_ids["brand_id"],
            "selected_creator": test_ids["creator_id"],
            "status": "in_progress",
        })
        await server.db.escrow.insert_one({
            "id": f"{TEST_PREFIX}-escrow-{uuid.uuid4()}",
            "campaign_id": test_ids["campaign_id"],
            "amount": 5000,
            "status": "held",
            "created_at": "2026-05-15T11:00:00+00:00",
        })

        response = await server.get_business_wallet(brand_user)
        assert response["available_balance"] == 25000
        assert response["minimum_chat_balance"] == 5000
        assert response["chat_unlocked"] is True
        assert response["plan_name"] == "Brand Pro"
        assert response["recharge_bonus"]["current_tier_percent"] == 7
        assert response["recharge_bonus"]["next_tier_percent"] == 10
        assert response["bonus_tiers"] == server.WALLET_BONUS_TIERS
        assert {txn["type"] for txn in response["transactions"]} >= {"Wallet Recharge", "Escrow Lock"}
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_wallet_recharge_validates_minimum_amount():
    test_ids, brand_user = await seed_brand()
    await seed_gateway("cashfree")
    try:
        with pytest.raises(HTTPException) as exc:
            await server.recharge_business_wallet(recharge_payload(amount=4999), brand_user)
        assert exc.value.status_code == 400
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_wallet_recharge_creates_transaction_with_bonus():
    test_ids, brand_user = await seed_brand()
    await seed_gateway("cashfree")
    try:
        response = await server.recharge_business_wallet(recharge_payload(amount=25000), brand_user)
        assert response["success"] is True
        assert response["bonus_amount"] == 1750
        assert response["credited_amount"] == 26750

        transaction = await server.db.payment_transactions.find_one({"gateway_order_id": response["order_id"]}, {"_id": 0})
        assert transaction["purpose"] == "wallet_recharge"
        assert transaction["bonus_amount"] == 1750
        assert transaction["credited_amount"] == 26750
        assert transaction["status"] == "created"
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_payment_verify_credits_wallet_once_and_writes_ledger():
    test_ids, brand_user = await seed_brand()
    await seed_gateway("cashfree")
    try:
        order = await server.recharge_business_wallet(recharge_payload(amount=10000), brand_user)
        verify_payload = server.PaymentVerifyRequest(
            cashfree_order_id=order["order_id"],
            cashfree_payment_id="cf_pay_123",
        )

        first = await server.verify_payment(verify_payload, brand_user)
        second = await server.verify_payment(verify_payload, brand_user)

        assert first["wallet_balance"] == 10300
        assert second["wallet_balance"] == 10300
        updated_user = await server.db.users.find_one({"id": test_ids["brand_id"]}, {"_id": 0})
        assert updated_user["balance"] == 10300

        ledger = await server.db.wallet_ledger.find({"user_id": test_ids["brand_id"]}, {"_id": 0}).to_list(10)
        assert sorted(row["type"] for row in ledger) == ["Bonus Credit", "Wallet Recharge"]
        assert sorted(row["amount"] for row in ledger) == [300, 10000]
    finally:
        await cleanup(test_ids)


@pytest.mark.asyncio
async def test_cashfree_webhook_success_credits_wallet_once():
    test_ids, brand_user = await seed_brand()
    await seed_gateway("cashfree")
    try:
        order = await server.recharge_business_wallet(recharge_payload(amount=50000), brand_user)
        webhook = {
            "type": "PAYMENT_SUCCESS_WEBHOOK",
            "data": {
                "order": {"order_id": order["order_id"]},
                "payment": {"cf_payment_id": "cf_pay_webhook_123"},
            },
        }

        await server.cashfree_webhook(webhook)
        await server.cashfree_webhook(webhook)

        updated_user = await server.db.users.find_one({"id": test_ids["brand_id"]}, {"_id": 0})
        assert updated_user["balance"] == 55000
        ledger = await server.db.wallet_ledger.find({"user_id": test_ids["brand_id"]}, {"_id": 0}).to_list(10)
        assert sorted(row["type"] for row in ledger) == ["Bonus Credit", "Wallet Recharge"]
        assert sorted(row["amount"] for row in ledger) == [5000, 50000]
    finally:
        await cleanup(test_ids)
