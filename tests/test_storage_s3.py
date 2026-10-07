"""S3 path of storage.persist_file: URL shapes, priority, no silent local fallback."""
import pytest

import storage

S3_ENV = {"S3_BUCKET": "b", "S3_ACCESS_KEY_ID": "k", "S3_SECRET_ACCESS_KEY": "s", "S3_REGION": "ap-south-1"}


class FakeS3:
    def __init__(self):
        self.fail, self.calls = False, []

    def upload_fileobj(self, fileobj, bucket, key, ExtraArgs=None):
        if self.fail:
            raise RuntimeError("denied")
        self.calls.append((bucket, key, ExtraArgs, fileobj.read()))


@pytest.fixture
def s3(monkeypatch):
    for k in ("S3_ENDPOINT", "S3_PUBLIC_URL", "S3_FORCE_PATH_STYLE"):
        monkeypatch.delenv(k, raising=False)
    for k, v in S3_ENV.items():
        monkeypatch.setenv(k, v)
    # Cloudinary configured too: S3 must still win.
    monkeypatch.setenv("CLOUDINARY_URL", "cloudinary://k:s@c")
    fake = FakeS3()
    monkeypatch.setattr(storage, "_s3_client", fake)
    return fake


def test_upload_goes_to_s3_with_content_type(s3, tmp_path):
    url = storage.persist_file(b"x", "a b.mp4", kind="video", local_dir=tmp_path, public_path="/uploads/a b.mp4")
    assert url == "https://b.s3.ap-south-1.amazonaws.com/ugcad/a%20b.mp4"
    assert s3.calls == [("b", "ugcad/a b.mp4", {"ContentType": "video/mp4"}, b"x")]
    assert not list(tmp_path.iterdir())


def test_url_shapes(s3, monkeypatch):
    monkeypatch.setenv("S3_ENDPOINT", "https://minio.example.com/")
    assert storage.s3_public_url("f/x.jpg") == "https://minio.example.com/b/f/x.jpg"
    monkeypatch.setenv("S3_PUBLIC_URL", "https://media.example.com")
    assert storage.s3_public_url("f/x.jpg") == "https://media.example.com/f/x.jpg"


def test_failed_upload_raises_instead_of_local_fallback(s3, tmp_path):
    s3.fail = True
    with pytest.raises(storage.CloudStorageError):
        storage.persist_file(b"x", "a.jpg", kind="image", local_dir=tmp_path, public_path="/uploads/a.jpg")
    assert not list(tmp_path.iterdir())


def test_video_without_s3_configuration_does_not_fall_back_to_cloudinary(monkeypatch, tmp_path):
    for key in S3_ENV:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("CLOUDINARY_URL", "******c")

    with pytest.raises(storage.CloudStorageError, match="Video storage is not configured for S3"):
        storage.persist_file(
            b"x",
            "a.mp4",
            kind="video",
            local_dir=tmp_path,
            public_path="/uploads/a.mp4",
        )

    assert not list(tmp_path.iterdir())
