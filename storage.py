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

Video uploads require S3 configuration and never fall back to Cloudinary.
Configure ``S3_BUCKET``, ``S3_ACCESS_KEY_ID`` and ``S3_SECRET_ACCESS_KEY``.
Optional: ``S3_REGION``, ``S3_ENDPOINT``, ``S3_FORCE_PATH_STYLE`` and
``S3_PUBLIC_URL`` (CDN base).
"""

from __future__ import annotations

import io
import logging
import mimetypes
import os
from pathlib import Path
from typing import Optional
from urllib.parse import quote

logger = logging.getLogger("storage")

_cloudinary_ready: Optional[bool] = None
_s3_client = None


def s3_enabled() -> bool:
    return all(os.environ.get(key) for key in ("S3_BUCKET", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"))


def s3_public_url(key: str) -> str:
    """Build the public URL for an object stored in the configured S3 bucket."""
    path = quote(key)
    public_base = os.environ.get("S3_PUBLIC_URL")
    if public_base:
        return f"{public_base.rstrip('/')}/{path}"

    bucket = os.environ["S3_BUCKET"]
    endpoint = os.environ.get("S3_ENDPOINT")
    if endpoint:
        return f"{endpoint.rstrip('/')}/{bucket}/{path}"

    region = os.environ.get("S3_REGION") or "us-east-1"
    return f"https://{bucket}.s3.{region}.amazonaws.com/{path}"


def upload_to_s3(content: bytes, key: str) -> Optional[str]:
    """Upload an object to S3 and return its public URL."""
    global _s3_client
    try:
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

        content_type = mimetypes.guess_type(key)[0] or "application/octet-stream"
        _s3_client.upload_fileobj(
            io.BytesIO(content),
            os.environ["S3_BUCKET"],
            key,
            ExtraArgs={"ContentType": content_type},
        )
        return s3_public_url(key)
    except Exception as exc:
        logger.error("[s3] upload failed for %s (%.1f MB): %s", key, len(content) / (1024 * 1024), exc)
        return None


class CloudStorageError(Exception):
    """Persistent storage is unavailable or rejected an upload."""


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

    Videos require S3 and never fall back to Cloudinary or local storage.
    Other media uses Cloudinary when configured and local storage only for
    development environments without a cloud provider."""
    if kind == "video":
        if not s3_enabled():
            raise CloudStorageError(
                "Video storage is not configured for S3. Please contact support before retrying."
            )
        url = upload_to_s3(content, f"{cloud_folder}/{unique_filename}")
        if url:
            return url
        raise CloudStorageError(
            f"Could not store this file ({len(content) / (1024 * 1024):.0f} MB) in S3. "
            "Please try again; if this keeps happening, contact support."
        )

    if s3_enabled():
        url = upload_to_s3(content, f"{cloud_folder}/{unique_filename}")
        if url:
            return url
        raise CloudStorageError(
            f"Could not store this file ({len(content) / (1024 * 1024):.0f} MB) in S3. "
            "Please try again; if this keeps happening, contact support."
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
