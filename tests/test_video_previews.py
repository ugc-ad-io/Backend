import json
import os
import shutil
import subprocess

import pytest

import storage

pytestmark = pytest.mark.skipif(not shutil.which("ffmpeg"), reason="needs ffmpeg")


def test_previews_are_small_480p_clip_and_poster_at_the_shared_path(tmp_path, monkeypatch):
    src = tmp_path / "in.mp4"
    subprocess.run(["ffmpeg", "-y", "-f", "lavfi", "-i", "testsrc=size=720x1280:rate=30:duration=3",
                    "-pix_fmt", "yuv420p", str(src)], check=True, capture_output=True)
    uploaded = {}

    class FakeS3:
        def upload_file(self, path, bucket, key, ExtraArgs):
            probe = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "stream=codec_name,width",
                                    "-of", "json", path], capture_output=True, text=True).stdout
            uploaded[key] = (json.loads(probe)["streams"][0], ExtraArgs)

    monkeypatch.setenv("S3_BUCKET", "bucket")
    monkeypatch.setattr(storage, "get_s3", lambda: FakeS3())
    assert storage.make_video_previews(str(src), "ugcad/uploads/u_1.mp4")

    clip, clip_args = uploaded["previews/ugcad/uploads/u_1.mp4"]
    poster, poster_args = uploaded["previews/ugcad/uploads/u_1.jpg"]
    assert (clip["codec_name"], clip["width"]) == ("h264", 480)
    assert poster["width"] == 480 and poster_args["ContentType"] == "image/jpeg"
    assert "immutable" in clip_args["CacheControl"]


def test_a_broken_video_never_fails_the_upload(tmp_path, monkeypatch):
    bad = tmp_path / "bad.mp4"
    bad.write_bytes(b"not a video")
    monkeypatch.setenv("S3_BUCKET", "bucket")
    assert storage.make_video_previews(str(bad), "ugcad/uploads/x.mp4") is False
