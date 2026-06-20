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
"""

from __future__ import annotations

import io
import os
from pathlib import Path
from typing import Optional

_cloudinary_ready: Optional[bool] = None


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
    except Exception:
        # Surface as a fallback to local disk rather than failing the request.
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

    Prefers Cloudinary (persistent); falls back to writing to the local uploads
    disk and returning ``public_path`` (e.g. ``/uploads/profiles/x.jpg``)."""
    public_id = Path(unique_filename).stem
    url = upload_to_cloudinary(content, public_id=public_id, kind=kind, folder=cloud_folder)
    if url:
        return url

    local_dir.mkdir(parents=True, exist_ok=True)
    with open(local_dir / unique_filename, "wb") as handle:
        handle.write(content)
    return public_path
