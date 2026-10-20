import pytest
from fastapi import HTTPException
from mongomock_motor import AsyncMongoMockClient

import server


@pytest.fixture
def isolated(monkeypatch):
    database = AsyncMongoMockClient()["saved_creators"]
    monkeypatch.setattr(server, "db", database)
    return database


async def _seed(db):
    await db.users.insert_one({"id": "b1", "role": "business"})
    await db.users.insert_one({"id": "c1", "role": "creator"})
    return {"id": "b1", "role": "business"}


@pytest.mark.asyncio
async def test_brand_can_save_list_and_remove_a_creator(isolated):
    brand = await _seed(isolated)
    await server.add_saved_creator("c1", brand)
    await server.add_saved_creator("c1", brand)  # saving twice keeps one entry
    assert (await server.list_saved_creators(brand))["creator_ids"] == ["c1"]
    await server.remove_saved_creator("c1", brand)
    assert (await server.list_saved_creators(brand))["creator_ids"] == []


@pytest.mark.asyncio
async def test_only_brands_save_creators_and_only_real_creators_can_be_saved(isolated):
    brand = await _seed(isolated)
    with pytest.raises(HTTPException) as creator_caller:
        await server.add_saved_creator("c1", {"id": "c1", "role": "creator"})
    assert creator_caller.value.status_code == 403
    with pytest.raises(HTTPException) as missing:
        await server.add_saved_creator("nobody", brand)
    assert missing.value.status_code == 404
