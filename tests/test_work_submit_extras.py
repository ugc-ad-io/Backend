import pytest
from fastapi import HTTPException
from mongomock_motor import AsyncMongoMockClient

import server

CREATOR = {"id": "c1", "role": "creator"}


@pytest.fixture
def isolated(monkeypatch):
    database = AsyncMongoMockClient()["work_submit_extras"]
    monkeypatch.setattr(server, "db", database)

    async def no_announce(*args, **kwargs):
        return None

    monkeypatch.setattr(server, "announce_submission", no_announce)
    return database


async def _campaign(db, **extra):
    await db.campaigns.insert_one({"id": "camp1", "title": "Serum", "selected_creator": "c1", **extra})


def _body(**over):
    return server.WorkSubmission(campaign_id="camp1", work_files=["https://cdn.example.com/v.mp4"], description="cut", **over)


@pytest.mark.asyncio
async def test_a_brief_that_asks_for_a_caption_and_thumbnail_rejects_a_bare_video(isolated):
    await _campaign(isolated, content_requirements={"caption_script": True, "thumbnail": True})
    with pytest.raises(HTTPException) as err:
        await server.submit_work(_body(), CREATOR)
    assert err.value.status_code == 400
    assert err.value.detail == "Missing required assets: caption_url, thumbnail_url"
    assert await isolated.work_submissions.count_documents({}) == 0


@pytest.mark.asyncio
async def test_only_the_missing_one_is_named(isolated):
    await _campaign(isolated, content_requirements={"caption_script": True, "thumbnail": True})
    with pytest.raises(HTTPException) as err:
        await server.submit_work(_body(caption_url="https://cdn.example.com/script.pdf"), CREATOR)
    assert err.value.detail == "Missing required assets: thumbnail_url"


@pytest.mark.asyncio
async def test_caption_and_thumbnail_are_stored_with_the_submission(isolated):
    await _campaign(isolated, content_requirements={"caption_script": True, "thumbnail": True})
    body = _body(caption_url="https://cdn.example.com/script.pdf", thumbnail_url="https://cdn.example.com/t.jpg")
    assert (await server.submit_work(body, CREATOR))["message"] == "Work submitted successfully"
    work = await isolated.work_submissions.find_one({"campaign_id": "camp1"})
    # the video stays first: the watermarker and the brand's review play work_files[0]
    assert work["work_files"] == ["https://cdn.example.com/v.mp4", "https://cdn.example.com/script.pdf", "https://cdn.example.com/t.jpg"]
    assert work["caption_url"].endswith("script.pdf") and work["thumbnail_url"].endswith("t.jpg")
    version = await isolated.deal_content_submissions.find_one({"campaign_id": "camp1"})
    assert version["caption_url"].endswith("script.pdf") and version["thumbnail_url"].endswith("t.jpg")
    assert version["video_url"] == "https://cdn.example.com/v.mp4"
    campaign = await isolated.campaigns.find_one({"id": "camp1"})
    assert campaign["work_submission"]["thumbnail_url"].endswith("t.jpg")


@pytest.mark.asyncio
async def test_a_brief_without_those_requirements_still_submits_a_bare_video(isolated):
    await _campaign(isolated)
    assert (await server.submit_work(_body(), CREATOR))["message"] == "Work submitted successfully"
    work = await isolated.work_submissions.find_one({"campaign_id": "camp1"})
    assert work["work_files"] == ["https://cdn.example.com/v.mp4"]
    assert work["caption_url"] is None
