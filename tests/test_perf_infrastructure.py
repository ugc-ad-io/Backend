"""Page-load speed guards: lookup indexes exist, and only JSON API responses are compressed."""
import pytest
from mongomock_motor import AsyncMongoMockClient

import server


@pytest.mark.asyncio
async def test_ensure_indexes_creates_the_hot_lookups_and_is_repeatable(monkeypatch):
    database = AsyncMongoMockClient()["indexes"]
    monkeypatch.setattr(server, "db", database)
    await server.ensure_indexes()
    await server.ensure_indexes()  # a second boot changes nothing and does not fail
    campaigns = await database.campaigns.index_information()
    assert any(spec["key"] == [("business_id", 1)] for spec in campaigns.values())
    notifications = await database.in_app_notifications.index_information()
    assert any(spec["key"] == [("user_id", 1), ("created_at", -1)] for spec in notifications.values())


async def _call(path, headers):
    """Drive the middleware directly (no HTTP client needed); returns the response headers."""
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", b"3000")]})
        await send({"type": "http.response.body", "body": b"x" * 3000})
    sent = []
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}
    async def send(message):
        sent.append(message)
    scope = {"type": "http", "method": "GET", "path": path, "headers": headers, "query_string": b""}
    await server.ApiGZipMiddleware(app, minimum_size=1024)(scope, receive, send)
    return {name.lower(): value for name, value in sent[0]["headers"]}


@pytest.mark.asyncio
async def test_api_json_is_compressed_but_uploads_and_range_requests_are_not():
    gzip_ok = [(b"accept-encoding", b"gzip")]
    assert (await _call("/api/campaigns", gzip_ok)).get(b"content-encoding") == b"gzip"
    assert b"content-encoding" not in await _call("/uploads/clip.mp4", gzip_ok)
    assert b"content-encoding" not in await _call("/api/campaigns", gzip_ok + [(b"range", b"bytes=0-9")])
