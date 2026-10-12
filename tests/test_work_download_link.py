"""Work Review download: the website cannot fetch the redirect to S3 (the browser sends
Origin: null on a cross-origin redirect and the bucket's CORS rejects it), so the route
has a JSON mode that hands back a presigned "save as" link. Real routes, in-memory DB."""
import asyncio
from urllib.parse import parse_qs, urlparse

import pytest

pytest.importorskip("mongomock_motor")
pytest.importorskip("httpx")
pytest.importorskip("boto3")

from fastapi.testclient import TestClient  # noqa: E402
from mongomock_motor import AsyncMongoMockClient  # noqa: E402

import server  # noqa: E402
import storage  # noqa: E402

BUCKET = "ugcad-media"
HOST = f"https://{BUCKET}.s3.ap-south-1.amazonaws.com"
MP4 = f"{HOST}/ugcad/uploads/u1_8c82c9be-0fe7-4d37-bb83-dc253db2c74b.mp4"
PNG = f"{HOST}/ugcad/uploads/u1_08547fb5-08ad-44cf-9885-f0b348cd30e2.png"


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("RESEND_API_KEY", "")
    monkeypatch.setenv("S3_BUCKET", BUCKET)
    monkeypatch.setenv("S3_ACCESS_KEY_ID", "AKIATESTTESTTESTTEST")
    monkeypatch.setenv("S3_SECRET_ACCESS_KEY", "test-secret-test-secret-test-secret-1234")
    monkeypatch.setenv("S3_REGION", "ap-south-1")
    monkeypatch.delenv("S3_PUBLIC_URL", raising=False)
    monkeypatch.delenv("S3_ENDPOINT", raising=False)
    monkeypatch.setattr(storage, "_s3_client", None)
    monkeypatch.setattr(storage, "_presign_client", None)
    monkeypatch.setattr(server, "db", AsyncMongoMockClient()["work_download"])
    loop = asyncio.new_event_loop()
    client = TestClient(server.app, follow_redirects=False)
    run = loop.run_until_complete

    def call(method, path, token=None, **kw):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return client.request(method, "/api" + path, headers=headers, **kw)

    def signup(role, n):
        b = call("POST", "/auth/signup", json={"email": f"wd-{role}-{n}@example.com", "password": "Passw0rd!x", "role": role,
                                               "phone": f"98765{48000 + n}", "dial_code": "+91", "name": f"W{n}"}).json()
        return b["token"], b["user_id"]

    brand_t, brand = signup("business", 1)
    _, creator = signup("creator", 1)

    def deliver(url, work_id, status=None):
        status = status or server.WorkStatus.APPROVED
        run(server.db.campaigns.insert_one({
            "id": f"c-{work_id}", "business_id": brand, "selected_creator": creator, "title": "Perfume reel",
            "status": server.CampaignStatus.IN_PROGRESS}))
        run(server.db.work_submissions.insert_one({
            "id": work_id, "campaign_id": f"c-{work_id}", "creator_id": creator, "status": status,
            "video_url": url, "submitted_at": "2026-10-10T10:00:00+00:00"}))
        return work_id

    yield type("Env", (), dict(call=staticmethod(call), brand_t=brand_t, deliver=staticmethod(deliver)))
    loop.close()


def test_default_still_redirects_for_old_clients(env):
    wid = env.deliver(MP4, "w1")
    r = env.call("GET", f"/work/{wid}/download", env.brand_t)
    assert r.status_code in (301, 302, 307) and r.headers["location"] == MP4


def test_link_mode_returns_a_presigned_attachment_url(env):
    wid = env.deliver(MP4, "w2")
    r = env.call("GET", f"/work/{wid}/download?as_link=1&name=Perfume%20reel", env.brand_t)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["forced"] is True and body["filename"] == "Perfume reel.mp4"
    u = urlparse(body["url"])
    assert u.netloc == f"{BUCKET}.s3.ap-south-1.amazonaws.com"
    assert u.path == "/ugcad/uploads/u1_8c82c9be-0fe7-4d37-bb83-dc253db2c74b.mp4"
    q = parse_qs(u.query)
    assert q["response-content-disposition"] == ['attachment; filename="Perfume reel.mp4"']
    assert "X-Amz-Signature" in q


def test_extension_comes_from_the_file_not_a_guess(env):
    wid = env.deliver(PNG, "w3")
    body = env.call("GET", f"/work/{wid}/download?as_link=1&name=Poster", env.brand_t).json()
    assert body["filename"] == "Poster.png"


def test_filename_hint_cannot_inject_header_characters(env):
    wid = env.deliver(MP4, "w4")
    body = env.call("GET", f"/work/{wid}/download?as_link=1&name=a%22%0D%0ASet-Cookie%3A%20x", env.brand_t).json()
    disp = parse_qs(urlparse(body["url"]).query)["response-content-disposition"][0]
    assert "\r" not in disp and "\n" not in disp and disp.count('"') == 2


def test_cloudinary_and_local_files_still_work(env):
    cl = "https://res.cloudinary.com/demo/video/upload/v1/ugcad/uploads/a.mp4"
    body = env.call("GET", f"/work/{env.deliver(cl, 'w5')}/download?as_link=1", env.brand_t).json()
    assert body == {"url": "https://res.cloudinary.com/demo/video/upload/fl_attachment/v1/ugcad/uploads/a.mp4",
                    "forced": True, "filename": "Perfume reel.mp4"}
    local = env.call("GET", f"/work/{env.deliver('/uploads/x.mp4', 'w6')}/download?as_link=1", env.brand_t).json()
    assert local["forced"] is False and local["url"] == "/uploads/x.mp4"


def test_unapproved_work_is_still_locked_in_link_mode(env):
    wid = env.deliver(MP4, "w7", status=server.WorkStatus.SUBMITTED)
    r = env.call("GET", f"/work/{wid}/download?as_link=1", env.brand_t)
    assert r.status_code == 403


def test_key_from_url_only_accepts_our_bucket(env):
    assert storage.s3_key_from_url(f"{HOST}/ugcad/uploads/a%20b.mp4?X=1") == "ugcad/uploads/a b.mp4"
    assert storage.s3_key_from_url("https://other-bucket.s3.ap-south-1.amazonaws.com/ugcad/a.mp4") is None
    assert storage.s3_key_from_url("/uploads/a.mp4") is None
