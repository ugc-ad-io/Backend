"""Oct-12 feedback fixes: raw-only briefs, both files visible to the brand, and shipping
addresses taken from the account. Pure functions + one in-memory notification check."""
import asyncio

import pytest

pytest.importorskip("mongomock_motor")

from mongomock_motor import AsyncMongoMockClient  # noqa: E402

import creator_features as cf  # noqa: E402
import server  # noqa: E402


def item(**kw):
    return {"type": "Reel", "quantity": 1, "raw_required": True, "edited_required": False, **kw}


def test_raw_only_brief_asks_for_one_file():
    required = server.get_required_assets({"deliverable_items": [item()]})
    assert required["raw_only"] is True
    assert required["raw_footage"] is False      # no second "raw footage" slot
    assert required["final_video"] is True       # the one video slot (it IS the raw video)


def test_edited_brief_keeps_the_raw_then_edited_flow():
    required = server.get_required_assets({"deliverable_items": [item(edited_required=True)]})
    assert required["raw_only"] is False
    assert required["raw_footage"] is True


def test_brief_without_deliverable_rows_is_unchanged():
    required = server.get_required_assets({"raw_footage_required": True})
    assert required["raw_only"] is False
    assert required["raw_footage"] is True


def _labels(asset, approved=False):
    out = cf.to_brand_facing_asset(asset, approved=approved)
    return [(f["kind"], f["label"]) for f in out["files"]]


def test_brand_sees_final_and_raw_for_a_plain_two_file_submission():
    work = {"work_files": ["/u/final.mp4", "/u/raw.mp4"], "raw_files": ["/u/raw.mp4"], "edited_files": []}
    assert _labels(work) == [("edited", "Edited video"), ("raw", "Raw video")]
    assert _labels(work, approved=True) == [("edited", "Edited video"), ("raw", "Raw video")]


def test_raw_only_submission_is_one_raw_file():
    work = {"work_files": ["/u/raw.mp4"], "raw_files": ["/u/raw.mp4"], "edited_files": []}
    assert _labels(work) == [("raw", "Raw video")]


def test_staged_edited_submission_still_lists_both():
    work = {"work_files": ["/u/edit.mp4", "/u/raw.mp4"], "raw_files": ["/u/raw.mp4"], "edited_files": ["/u/edit.mp4"]}
    assert _labels(work) == [("edited", "Edited video"), ("raw", "Raw video")]


def test_creator_account_address_comes_from_kyc():
    user = {"role": "creator", "phone": "9244984867",
            "kyc": {"full_legal_name": "Deshna Shrimal",
                    "address": {"line": "303 Sanrachna Avenue", "city": "Indore", "state": "MP", "pincode": "452010"}}}
    addr = server.account_address_for(user)
    assert addr["line1"] == "303 Sanrachna Avenue" and addr["pincode"] == "452010"
    assert addr["full_name"] == "Deshna Shrimal" and addr["phone"] == "9244984867"
    assert server.address_missing_fields(addr) == []


def test_brand_account_address_comes_from_company_settings_and_flags_missing_pincode():
    brand = {"role": "business", "phone": "9000000000", "profile": {"contact_person": "Asha"}}
    company = {"billing_address": "12 MG Road", "city": "Pune", "state": "MH", "country": "India"}
    addr = server.account_address_for(brand, company)
    assert addr["line1"] == "12 MG Road" and addr["full_name"] == "Asha"
    assert server.address_missing_fields(addr) == ["pincode"]


def test_no_saved_address_means_none_not_an_empty_form_of_zeros():
    assert server.account_address_for({"role": "creator"}) is None
    assert server.account_address_for({"role": "business"}, {}) is None
    assert server.address_missing_fields(None) == list(server._ADDR_REQUIRED)


@pytest.fixture
def captured(monkeypatch):
    monkeypatch.setattr(server, "db", AsyncMongoMockClient()["oct12_notify"])
    calls = []

    async def fake_notify(user_id, title, message, **kw):
        calls.append((user_id, title, kw))
        await server.db.in_app_notifications.insert_one(
            {"user_id": user_id, "title": title, "link": kw.get("link"), "category": kw.get("category")})

    monkeypatch.setattr(server, "notify_user", fake_notify)
    return calls


def test_creator_is_asked_to_confirm_address_once_by_notification_and_email(captured):
    campaign = {"id": "c1", "title": "Sleeksoul", "requires_shipment": True}
    run = asyncio.new_event_loop().run_until_complete
    run(server.notify_confirm_delivery_address(campaign, "creator-1"))
    run(server.notify_confirm_delivery_address(campaign, "creator-1"))   # second call: no duplicate
    assert len(captured) == 1
    user_id, title, kw = captured[0]
    assert user_id == "creator-1" and "delivery address" in title.lower()
    assert kw["email"] is True and kw["link"] == "/my-deals?campaign=c1"


def test_no_address_request_when_nothing_ships(captured):
    run = asyncio.new_event_loop().run_until_complete
    run(server.notify_confirm_delivery_address({"id": "c2", "title": "Digital", "requires_shipment": False}, "creator-1"))
    assert captured == []
