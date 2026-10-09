"""Video processing behind the direct-to-S3 upload: real ffmpeg, a folder standing in for S3."""
import os
import shutil
import subprocess

import pytest

import storage

pytestmark = pytest.mark.skipif(not (shutil.which("ffmpeg") and shutil.which("ffprobe")), reason="ffmpeg not installed")


def _make(path, codec, seconds=2):
    args = ["-c:v", codec, "-pix_fmt", "yuv420p"] + (["-tag:v", "hvc1"] if codec == "libx265" else [])
    subprocess.run(
        ["ffmpeg", "-y", "-v", "error", "-f", "lavfi", "-i", "testsrc2=size=320x240:rate=15", "-f", "lavfi",
         "-i", "sine=frequency=440", "-t", str(seconds), *args, "-c:a", "aac", "-shortest", str(path)],
        check=True,
    )


class FolderS3:
    """Just the S3 calls process_incoming_video makes, backed by a folder."""
    def __init__(self, root):
        self.root = root

    def _p(self, key):
        path = os.path.join(self.root, *key.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path

    def download_file(self, bucket, key, filename):
        shutil.copyfile(self._p(key), filename)

    def upload_file(self, filename, bucket, key, ExtraArgs=None):
        shutil.copyfile(filename, self._p(key))
        self.last_args = ExtraArgs


@pytest.fixture
def s3(tmp_path, monkeypatch):
    monkeypatch.setenv("S3_BUCKET", "b")
    fake = FolderS3(str(tmp_path / "bucket"))
    monkeypatch.setattr(storage, "_s3_client", fake)
    return fake


def test_h264_is_remuxed_to_mp4_and_hevc_is_converted(tmp_path):
    h264, hevc = tmp_path / "a.mov", tmp_path / "b.mp4"
    _make(h264, "libx264")
    _make(hevc, "libx265")
    for src in (h264, hevc):
        out = tmp_path / f"out_{src.name}.mp4"
        assert storage.transcode_video_file(str(src), str(out)) is True
        assert storage._video_codec(str(out)) == "h264"


def test_unreadable_file_is_left_alone(tmp_path):
    junk = tmp_path / "junk.mp4"
    junk.write_bytes(b"not a video at all")
    assert storage.transcode_video_file(str(junk), str(tmp_path / "out.mp4")) is False
    assert not (tmp_path / "out.mp4").exists()


def test_process_incoming_video_stores_an_mp4_and_reports_length(s3):
    _make(s3._p("ugcad/incoming/u_1.mp4"), "libx265", seconds=3)
    duration, size = storage.process_incoming_video("ugcad/incoming/u_1.mp4", "ugcad/uploads/u_1.mp4", 400)
    assert 2.5 < duration < 3.5
    assert size == os.path.getsize(s3._p("ugcad/uploads/u_1.mp4"))
    assert s3.last_args == {"ContentType": "video/mp4"}
    assert storage._video_codec(s3._p("ugcad/uploads/u_1.mp4")) == "h264"


def test_a_video_over_the_length_limit_is_refused_before_anything_is_stored(s3):
    _make(s3._p("ugcad/incoming/u_2.mp4"), "libx264", seconds=5)
    with pytest.raises(storage.CloudStorageError, match="minutes or shorter"):
        storage.process_incoming_video("ugcad/incoming/u_2.mp4", "ugcad/uploads/u_2.mp4", 3)
    assert not os.path.exists(s3._p("ugcad/uploads/u_2.mp4"))
