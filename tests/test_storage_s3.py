"""S3 upload behavior, with no Cloudinary fallback for creator videos."""

import pytest

import storage


S3_ENV = {
    "S3_BUCKET": "test-bucket",
    "S3_ACCESS_KEY_ID": "test-key",
    "S3_SECRET_ACCESS_KEY": "test-secret",
    "S3_REGION": "ap-south-1",
}


class FakeS3:
    def __init__(self):
        self.fail = False
        self.calls = []

    def upload_fileobj(self, fileobj, bucket, key, ExtraArgs=None):
        if self.fail:
            raise RuntimeError("denied")
        self.calls.append((bucket, key, ExtraArgs, fileobj.read()))


@pytest.fixture
def configured_s3(monkeypatch):
    for key in ("S3_ENDPOINT", "S3_PUBLIC_URL", "S3_FORCE_PATH_STYLE"):
        monkeypatch.delenv(key, raising=False)
    for key, value in S3_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("CLOUDINARY_URL", "cloudinary://configured")
    fake = FakeS3()
    monkeypatch.setattr(storage, "_s3_client", fake)
    return fake


def test_video_upload_uses_s3_even_when_cloudinary_is_configured(configured_s3, tmp_path):
    url = storage.persist_file(
        b"video",
        "creator clip.mp4",
        kind="video",
        local_dir=tmp_path,
        public_path="/uploads/creator clip.mp4",
    )

    assert url == "https://test-bucket.s3.ap-south-1.amazonaws.com/ugcad/creator%20clip.mp4"
    assert configured_s3.calls == [
        ("test-bucket", "ugcad/creator clip.mp4", {"ContentType": "video/mp4"}, b"video")
    ]
    assert not list(tmp_path.iterdir())


def test_video_without_s3_configuration_never_falls_back_to_cloudinary(monkeypatch, tmp_path):
    for key in S3_ENV:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("CLOUDINARY_URL", "cloudinary://configured")
    monkeypatch.setattr(storage, "upload_to_cloudinary", lambda *args, **kwargs: pytest.fail("Cloudinary fallback"))

    with pytest.raises(storage.CloudStorageError, match="not configured for S3"):
        storage.persist_file(
            b"video",
            "creator clip.mp4",
            kind="video",
            local_dir=tmp_path,
            public_path="/uploads/creator clip.mp4",
        )

    assert not list(tmp_path.iterdir())


def test_failed_s3_video_upload_does_not_fall_back(configured_s3, tmp_path):
    configured_s3.fail = True

    with pytest.raises(storage.CloudStorageError, match="in S3"):
        storage.persist_file(
            b"video",
            "creator clip.mp4",
            kind="video",
            local_dir=tmp_path,
            public_path="/uploads/creator clip.mp4",
        )

    assert not list(tmp_path.iterdir())


def test_s3_public_url_supports_custom_endpoint(configured_s3, monkeypatch):
    monkeypatch.setenv("S3_ENDPOINT", "https://objects.example.com/")
    assert storage.s3_public_url("videos/clip.mp4") == (
        "https://objects.example.com/test-bucket/videos/clip.mp4"
    )

    monkeypatch.setenv("S3_PUBLIC_URL", "https://cdn.example.com/")
    assert storage.s3_public_url("videos/clip.mp4") == "https://cdn.example.com/videos/clip.mp4"
