"""
File storage helper for UGCAD.IO.

Render's filesystem is ephemeral — anything written to the local ``/uploads``
disk is wiped on every redeploy/restart, which silently destroys creator work
files, profile photos, logos and campaign images. This module routes uploads to
Cloudinary (persistent, CDN-backed, with native video support) when it is
configured, and transparently falls back to the local disk for local dev or if
Cloudinary credentials are absent.

Configure with either:
  * ``CLOUDINARY_URL=cloudinary://<api_key>:<api_secret>@<cloud_name>``  (one var)
  * or ``CLOUDINARY_CLOUD_NAME`` + ``CLOUDINARY_API_KEY`` + ``CLOUDINARY_API_SECRET``

S3 (AWS or any S3-compatible store such as MinIO) takes priority over Cloudinary
when ``S3_BUCKET`` + ``S3_ACCESS_KEY_ID`` + ``S3_SECRET_ACCESS_KEY`` are set, so
turning it on is an env change, not a code change. Optional: ``S3_REGION``,
``S3_ENDPOINT`` (non-AWS), ``S3_FORCE_PATH_STYLE``, ``S3_PUBLIC_URL`` (CDN base).
Video uploads require S3 to be configured and never fall back to Cloudinary.
"""

from __future__ import annotations

import io
import logging
import mimetypes
import os
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Optional
from urllib.parse import quote

logger = logging.getLogger("storage")

_cloudinary_ready: Optional[bool] = None
_s3_client = None


def s3_enabled() -> bool:
    return all(os.environ.get(k) for k in ("S3_BUCKET", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"))


def s3_public_url(key: str) -> str:
    """The URL a browser loads the object from. Objects must be publicly
    readable there (bucket policy or a CDN) — the URL is stored as-is."""
    path = quote(key)
    base = os.environ.get("S3_PUBLIC_URL")
    if base:
        return f"{base.rstrip('/')}/{path}"
    bucket = os.environ["S3_BUCKET"]
    endpoint = os.environ.get("S3_ENDPOINT")
    if endpoint:  # MinIO and friends address the bucket in the path
        return f"{endpoint.rstrip('/')}/{bucket}/{path}"
    region = os.environ.get("S3_REGION") or "us-east-1"
    return f"https://{bucket}.s3.{region}.amazonaws.com/{path}"


def get_s3():
    """The shared S3 client, built once from the S3_* settings."""
    global _s3_client
    if _s3_client is None:
        import boto3
        from botocore.config import Config

        path_style = str(os.environ.get("S3_FORCE_PATH_STYLE", "")).lower() in ("1", "true", "yes")
        _s3_client = boto3.client(
            "s3",
            aws_access_key_id=os.environ["S3_ACCESS_KEY_ID"],
            aws_secret_access_key=os.environ["S3_SECRET_ACCESS_KEY"],
            region_name=os.environ.get("S3_REGION") or "us-east-1",
            endpoint_url=os.environ.get("S3_ENDPOINT") or None,
            config=Config(s3={"addressing_style": "path" if path_style else "auto"}),
        )
    return _s3_client


def upload_to_s3(content: bytes, key: str) -> Optional[str]:
    """Upload bytes to the S3 bucket and return the public URL, or None on failure."""
    try:
        # Without a Content-Type S3 serves octet-stream and a browser downloads
        # the video instead of playing it. upload_fileobj goes multipart on its
        # own for large files.
        content_type = mimetypes.guess_type(key)[0] or "application/octet-stream"
        get_s3().upload_fileobj(
            io.BytesIO(content), os.environ["S3_BUCKET"], key,
            ExtraArgs={"ContentType": content_type},
        )
        return s3_public_url(key)
    except Exception as exc:
        logger.error("[s3] upload failed for %s (%.1f MB): %s", key, len(content) / (1024 * 1024), exc)
        return None


class CloudStorageError(Exception):
    """Persistent storage is unavailable or rejected the upload. Raised rather
    than silently falling back to another provider or ephemeral local disk."""


def _ensure_cloudinary() -> bool:
    """Configure the Cloudinary SDK once; return whether it is usable."""
    global _cloudinary_ready
    if _cloudinary_ready is not None:
        return _cloudinary_ready

    url = os.environ.get("CLOUDINARY_URL")
    cloud = os.environ.get("CLOUDINARY_CLOUD_NAME")
    key = os.environ.get("CLOUDINARY_API_KEY")
    secret = os.environ.get("CLOUDINARY_API_SECRET")

    if not (url or (cloud and key and secret)):
        _cloudinary_ready = False
        return False

    try:
        import cloudinary  # noqa: F401

        if url:
            # CLOUDINARY_URL is read from the environment automatically.
            cloudinary.config(secure=True)
        else:
            cloudinary.config(cloud_name=cloud, api_key=key, api_secret=secret, secure=True)
        _cloudinary_ready = True
    except Exception:
        _cloudinary_ready = False
    return _cloudinary_ready


def cloudinary_enabled() -> bool:
    return _ensure_cloudinary()


def _resource_type(kind: Optional[str]) -> str:
    if kind == "video":
        return "video"
    if kind == "image":
        return "image"
    # pdf / other / unknown -> raw so Cloudinary stores the file verbatim.
    return "raw"


def upload_to_cloudinary(content: bytes, public_id: str, kind: Optional[str] = None, folder: str = "ugcad") -> Optional[str]:
    """Upload bytes to Cloudinary and return the secure URL, or None if disabled/failed."""
    if not _ensure_cloudinary():
        return None
    try:
        import cloudinary.uploader

        resource_type = _resource_type(kind)
        stream = io.BytesIO(content)
        options = dict(
            public_id=public_id,
            folder=folder,
            resource_type=resource_type,
            overwrite=True,
        )
        # Videos can be large; use the chunked uploader so big files don't fail.
        if resource_type == "video":
            result = cloudinary.uploader.upload_large(stream, chunk_size=6 * 1024 * 1024, **options)
        else:
            result = cloudinary.uploader.upload(stream, **options)
        return result.get("secure_url")
    except Exception as exc:
        # Log the REAL reason (quota exhausted, file over the plan's size cap…)
        # so a failing upload is visible in Render logs instead of silent.
        logger.error("[cloudinary] upload failed for %s (kind=%s, %.1f MB): %s",
                     public_id, kind, len(content) / (1024 * 1024), exc)
        return None


def _video_codec(path: str) -> Optional[str]:
    """First video stream's codec name, or None if ffprobe can't tell.

    `csv=p=0` emits a trailing comma on some ffprobe builds even for a single
    field ("h264,\\r\\n") — strip it, or the codec=="h264" check below never
    matches and every already-compatible upload pays for a full re-encode it
    didn't need.
    """
    try:
        out = subprocess.run(
            ["ffprobe", "-v", "error", "-select_streams", "v:0",
             "-show_entries", "stream=codec_name", "-of", "csv=p=0", path],
            capture_output=True, text=True, timeout=30,
        )
        return out.stdout.strip().split(',')[0].strip() or None
    except Exception:
        return None


def video_duration_seconds(path: str) -> Optional[float]:
    """Length of the video in seconds, or None if ffprobe can't tell."""
    try:
        out = subprocess.run(
            ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", path],
            capture_output=True, text=True, timeout=30,
        )
        return float(out.stdout.strip().split(",")[0])
    except Exception:
        return None


def transcode_video_file(src: str, dst: str, timeout: int = 300) -> bool:
    """Write a browser-playable H.264/AAC MP4 of `src` to `dst`.

    Already-H.264 input is remuxed (stream copy: fast, lossless); anything else
    (iPhone HEVC) is re-encoded. Returns False, leaving `dst` unwritten, when
    ffprobe can't read the file at all. Raises CloudStorageError if ffmpeg fails.
    """
    codec = _video_codec(src)
    if codec is None:
        return False
    video_args = ["-c:v", "copy"] if codec == "h264" else [
        "-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-pix_fmt", "yuv420p",
    ]
    try:
        subprocess.run(
            ["ffmpeg", "-y", "-i", src, *video_args, "-c:a", "aac", "-movflags", "+faststart", dst],
            capture_output=True, timeout=timeout, check=True,
        )
    except Exception as exc:
        logger.error("[video] transcode failed (codec=%s): %s", codec, exc)
        raise CloudStorageError(
            "Could not process this video. Please try a different file or format; "
            "if this keeps happening, contact support."
        )
    return True


def ensure_browser_compatible_video(content: bytes) -> tuple[bytes, bool]:
    """Re-encode to H.264/AAC in a true MP4 container if needed for browser playback.

    Phones — iPhones especially, in their default "High Efficiency" camera mode
    — record HEVC/H.265 video. Browsers can read the file (duration, audio) but
    most can't decode HEVC frames, so the video plays as a black box with sound
    only. Cloudinary used to fix this invisibly via an on-the-fly transform; S3
    just serves the raw file, so without this the bug comes back for every
    phone-recorded upload.

    Returns (possibly-new bytes, whether the container was normalized to .mp4).
    When codec is already H.264 this still remuxes (stream copy — fast, no
    quality loss) rather than skipping entirely: it guarantees the output is a
    genuine .mp4 container, which matters because the caller renames the file
    to .mp4 whenever this returns True — serving a .mov file under a .mp4 name
    (wrong Content-Type) would just trade one playback bug for another.
    """
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "in")
        with open(src, "wb") as f:
            f.write(content)

        dst = os.path.join(tmp, "out.mp4")
        if not transcode_video_file(src, dst):
            # Unreadable/corrupt upload — let it through as-is; persist_file's
            # caller already validates the file before this point, and failing
            # the whole upload over a transcode we can't even diagnose is worse
            # than occasionally storing an unplayable file.
            logger.warning("[video] ffprobe couldn't read codec; storing untranscoded")
            return content, False
        with open(dst, "rb") as f:
            return f.read(), True


# ── Direct-to-S3 upload for large videos ─────────────────────────────────────
# A video over ~100 MB cannot travel through the app server: the hosting proxy
# cuts the request. Instead the browser POSTs it to S3 with a signed form, then
# the server converts it to browser-playable MP4 in the background.

def presign_video_post(key: str, content_type: str, max_bytes: int, expires: int = 3600) -> dict:
    """A signed form for one browser upload. S3 itself rejects any file whose
    size is outside 1..max_bytes or whose Content-Type differs from the signed one."""
    return get_s3().generate_presigned_post(
        Bucket=os.environ["S3_BUCKET"], Key=key,
        Fields={"Content-Type": content_type},
        Conditions=[{"Content-Type": content_type}, ["content-length-range", 1, max_bytes]],
        ExpiresIn=expires,
    )


def s3_object_size(key: str) -> Optional[int]:
    """Size in bytes of an object, or None when it does not exist."""
    try:
        return get_s3().head_object(Bucket=os.environ["S3_BUCKET"], Key=key)["ContentLength"]
    except Exception:
        return None


def s3_delete(key: str) -> None:
    try:
        get_s3().delete_object(Bucket=os.environ["S3_BUCKET"], Key=key)
    except Exception as exc:
        logger.warning("[s3] could not delete %s: %s", key, exc)


PREVIEW_CACHE = "public, max-age=31536000, immutable"


def preview_base_key(video_key: str) -> str:
    """previews/<video key without extension>. The app and website derive the same
    path from the video URL, so this naming is a contract: keep the three in step."""
    return f"previews/{video_key.rsplit('.', 1)[0]}"


def make_video_previews(src: str, video_key: str) -> bool:
    """Write the ~2 MB 480p clip and the still poster that tiles show instead of the
    original, next to each other at preview_base_key(video_key) + .mp4 / .jpg.

    Settings match the previews already in the bucket (480 wide, H.264 Main, 25 fps,
    ~360 kbps). Best effort: returns False and logs on any failure, never raises,
    because a missing preview only costs speed, never the upload itself.
    """
    base = preview_base_key(video_key)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            clip, poster = os.path.join(tmp, "p.mp4"), os.path.join(tmp, "p.jpg")
            subprocess.run(
                ["ffmpeg", "-y", "-i", src, "-vf", "scale=480:-2", "-r", "25", "-c:v", "libx264",
                 "-profile:v", "main", "-preset", "veryfast", "-crf", "30", "-maxrate", "450k",
                 "-bufsize", "900k", "-c:a", "aac", "-b:a", "64k", "-movflags", "+faststart", clip],
                check=True, capture_output=True, timeout=1800,
            )
            # Half a second in skips black first frames; a shorter clip falls back to frame 0.
            for seek in ("0.5", "0"):
                subprocess.run(["ffmpeg", "-y", "-ss", seek, "-i", src, "-frames:v", "1",
                                "-vf", "scale=480:-2", "-q:v", "4", poster],
                               capture_output=True, timeout=120)
                if os.path.exists(poster) and os.path.getsize(poster):
                    break
            else:
                raise RuntimeError("no frame for the poster")
            for path, content_type, ext in ((clip, "video/mp4", "mp4"), (poster, "image/jpeg", "jpg")):
                get_s3().upload_file(path, os.environ["S3_BUCKET"], f"{base}.{ext}",
                                     ExtraArgs={"ContentType": content_type, "CacheControl": PREVIEW_CACHE})
        return True
    except Exception as exc:
        logger.warning("[preview] could not make previews for %s: %s", video_key, exc)
        return False


def make_video_previews_in_background(content: bytes, video_key: str) -> None:
    """For a video already held in memory (the /upload/file path): previews take a
    few seconds of ffmpeg, so they must not hold up the upload response."""
    def run():
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "in")
            with open(src, "wb") as handle:
                handle.write(content)
            make_video_previews(src, video_key)
    threading.Thread(target=run, daemon=True).start()


def process_incoming_video(incoming_key: str, final_key: str, max_seconds: float) -> tuple[Optional[float], int]:
    """Turn a browser-uploaded video into a browser-playable MP4 at `final_key`.

    Downloads to disk (never into memory: this can be 400 MB), checks the length,
    converts, uploads. Returns (duration_seconds, final_size_bytes). Raises
    CloudStorageError with a message safe to show the user.
    """
    bucket = os.environ["S3_BUCKET"]
    with tempfile.TemporaryDirectory() as tmp:
        src, dst = os.path.join(tmp, "in"), os.path.join(tmp, "out.mp4")
        get_s3().download_file(bucket, incoming_key, src)
        duration = video_duration_seconds(src)
        if duration is not None and duration > max_seconds:
            raise CloudStorageError(f"Videos must be {int(max_seconds // 60)} minutes or shorter.")
        out = dst if transcode_video_file(src, dst, timeout=1800) else src
        get_s3().upload_file(out, bucket, final_key, ExtraArgs={"ContentType": "video/mp4"})
        make_video_previews(out, final_key)
        return duration, os.path.getsize(out)


def persist_file(
    content: bytes,
    unique_filename: str,
    *,
    kind: Optional[str],
    local_dir: Path,
    public_path: str,
    cloud_folder: str = "ugcad",
) -> str:
    """Store an uploaded file and return a retrievable URL.

    Prefers Cloudinary (persistent); falls back to writing to the local uploads
    disk and returning ``public_path`` (e.g. ``/uploads/profiles/x.jpg``) ONLY
    when Cloudinary isn't configured at all (local dev). When Cloudinary is
    configured but rejects the file, this raises CloudStorageError instead —
    a local-disk fallback on Render just stores a path that 404s after the
    next deploy (this silently destroyed creator work submissions before).

    Videos require S3; other files use S3 when configured, otherwise Cloudinary
    or local development storage."""
    if kind == "video":
        content, normalized = ensure_browser_compatible_video(content)
        if normalized and not unique_filename.lower().endswith(".mp4"):
            unique_filename = f"{Path(unique_filename).stem}.mp4"
            public_path = f"{public_path.rsplit('.', 1)[0]}.mp4" if "." in Path(public_path).name else public_path

    if s3_enabled():
        key = f"{cloud_folder}/{unique_filename}"
        url = upload_to_s3(content, key)
        if url:
            if kind == "video":
                make_video_previews_in_background(content, key)
            return url
        raise CloudStorageError(
            f"Could not store this file ({len(content) / (1024 * 1024):.0f} MB). "
            "Please try again; if this keeps happening, contact support."
        )

    if kind == "video":
        raise CloudStorageError(
            "Video storage is not configured for S3. Please contact support before retrying."
        )

    public_id = Path(unique_filename).stem
    url = upload_to_cloudinary(content, public_id=public_id, kind=kind, folder=cloud_folder)
    if url:
        return url

    if _ensure_cloudinary():
        size_mb = len(content) / (1024 * 1024)
        raise CloudStorageError(
            f"Could not store this file ({size_mb:.0f} MB). It may be larger than the "
            "media plan allows, or the monthly storage quota is exhausted. "
            "Please try a smaller file; if this keeps happening, contact support."
        )

    local_dir.mkdir(parents=True, exist_ok=True)
    with open(local_dir / unique_filename, "wb") as handle:
        handle.write(content)
    return public_path
