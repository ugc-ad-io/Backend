"""
Creator-side feature helpers for UGCAD.IO V0.5.

Centralises the rules the PRD (Section 2 + Section 1.6 scope) requires on the
creator side that were previously missing or only partially enforced:

  * Anonymous handle hardening (blocklist, real-name rejection, format) and a
    permanent, unique creator code.
  * Portfolio sample count (3-5) and per-item metadata enforcement.
  * Watermark-protected previews so brands never receive raw creator assets.
  * Level-based price floors for custom / counter offers.
  * Paid-revision economics (2 free, then a flat fee thereafter).

Kept dependency-light on purpose: Pillow is used for real image watermarking
when available, but the module imports and the server boots fine without it
(video / external assets fall back to a player-overlay watermark + access
gating, which is the security-critical part).
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Anonymous handle hardening (PRD 2.5)
# ---------------------------------------------------------------------------

# Handle format: 4-20 chars, must start with a letter, lowercase alphanumeric +
# underscore only. (PRD 2.5 validation rules.)
HANDLE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{3,19}$")

# Small, extensible blocklist of offensive / reserved tokens. Substring match,
# case-insensitive. This is intentionally conservative; admin review remains the
# backstop for anything that slips through.
OFFENSIVE_HANDLE_WORDS = {
    "admin", "ugcad", "support", "official", "moderator", "staff", "root",
    "fuck", "shit", "bitch", "cunt", "nigger", "rape", "nazi", "slut", "whore",
    "sex", "porn", "xxx",
}

# Common Indian given/last-name stop-tokens used to catch "real name" handles
# like `priya_sharma`. Not exhaustive — the KYC name match (done at approval)
# is the authoritative check; this is the cheap pre-filter at selection time.
COMMON_NAME_TOKENS = {
    "priya", "sharma", "kumar", "singh", "patel", "gupta", "anjali", "rahul",
    "amit", "neha", "rohan", "raj", "verma", "reddy", "nair", "iyer", "das",
    "khan", "ali", "mehta", "shah", "rao", "joshi", "kapoor", "bose", "ghosh",
}


def normalize_handle(value: Optional[str]) -> str:
    """Lower-case and strip a leading @, returning the bare handle."""
    handle = (value or "").strip().lower()
    if handle.startswith("@"):
        handle = handle[1:]
    return handle


def looks_like_real_name(handle: str) -> bool:
    """Heuristic: a `firstname_lastname` / `firstname.lastname` shape where one
    of the parts is a known name token reads as a real name."""
    parts = [p for p in re.split(r"[_.]", handle) if p]
    if len(parts) < 2:
        return False
    return any(part in COMMON_NAME_TOKENS for part in parts)


def validate_handle(value: Optional[str]) -> Tuple[bool, str, str]:
    """Validate a proposed creator handle.

    Returns (ok, normalized_handle, error_message). error_message is empty when
    ok is True.
    """
    handle = normalize_handle(value)
    if not handle:
        return False, "", "Handle is required."
    if not HANDLE_PATTERN.match(handle):
        return (
            False,
            handle,
            "Handle must be 4-20 characters, start with a letter, and use only "
            "lowercase letters, numbers, or underscores.",
        )
    lowered = handle
    for word in OFFENSIVE_HANDLE_WORDS:
        if word in lowered:
            return False, handle, "This handle contains a blocked or reserved word."
    if looks_like_real_name(handle):
        return False, handle, "Handle looks like a real name. Pick something anonymous to protect your identity."
    return True, handle, ""


def handle_suggestions(base: str, taken: set) -> List[str]:
    """Generate a few available-looking variants when a handle is taken."""
    base = normalize_handle(base) or "creator"
    base = base[:16]
    candidates = [f"{base}1", f"{base}_", f"{base}23", f"the{base}"[:20], f"{base}_official"[:20]]
    return [c for c in candidates if HANDLE_PATTERN.match(c) and c not in taken][:3]


def generate_creator_code() -> str:
    """Permanent, unique-per-creator public code (distinct from the handle).
    Caller is responsible for verifying uniqueness in the DB."""
    return f"CR-{uuid.uuid4().hex[:6].upper()}"


# ---------------------------------------------------------------------------
# Creator levels & price floors (PRD: level-based price floors on offers)
# ---------------------------------------------------------------------------

DEFAULT_CREATOR_LEVEL = "new"

# level -> {label, min price floor (INR) for any offer involving the creator}
CREATOR_LEVELS: Dict[str, Dict[str, Any]] = {
    "new":         {"label": "New",         "rank": 1, "price_floor": 1500},
    "rising":      {"label": "Rising",      "rank": 2, "price_floor": 2500},
    "established": {"label": "Established", "rank": 3, "price_floor": 4000},
    "elite":       {"label": "Elite",       "rank": 4, "price_floor": 7500},
}


def normalize_level(level: Optional[str]) -> str:
    level = (level or "").strip().lower()
    return level if level in CREATOR_LEVELS else DEFAULT_CREATOR_LEVEL


def price_floor_for_level(level: Optional[str]) -> int:
    return CREATOR_LEVELS[normalize_level(level)]["price_floor"]


# ---------------------------------------------------------------------------
# Paid revisions (PRD 2.x / Section 8: 2 free, then a flat fee)
# ---------------------------------------------------------------------------

FREE_REVISION_LIMIT = 2
PAID_REVISION_FEE = 500  # INR, charged to the brand wallet per extra revision


def revision_fee_for(existing_revision_count: int) -> int:
    """Fee owed by the brand for the next revision given how many already used."""
    return 0 if existing_revision_count < FREE_REVISION_LIMIT else PAID_REVISION_FEE


# ---------------------------------------------------------------------------
# Portfolio (PRD 2.7: 3-5 samples, per-item metadata)
# ---------------------------------------------------------------------------

PORTFOLIO_MIN = 3
PORTFOLIO_MAX = 5
PORTFOLIO_ITEM_REQUIRED_FIELDS = ["title"]


def validate_portfolio(items: List[Any]) -> Tuple[bool, str]:
    """Enforce 3-5 items and minimal per-item metadata.

    Accepts legacy list-of-URLs (strings) for backward compatibility, but rich
    dict items must carry a title.
    Returns (ok, error_message).
    """
    if not isinstance(items, list):
        return False, "Portfolio must be a list of samples."
    count = len(items)
    if count < PORTFOLIO_MIN or count > PORTFOLIO_MAX:
        return False, f"Portfolio must contain between {PORTFOLIO_MIN} and {PORTFOLIO_MAX} samples (got {count})."
    for idx, item in enumerate(items, start=1):
        if isinstance(item, dict):
            for field in PORTFOLIO_ITEM_REQUIRED_FIELDS:
                if not str(item.get(field) or "").strip():
                    return False, f"Sample {idx} is missing required field '{field}'."
            title = str(item.get("title") or "")
            if not 3 <= len(title) <= 60:
                return False, f"Sample {idx} title must be 3-60 characters."
        elif not isinstance(item, str) or not item.strip():
            return False, f"Sample {idx} is invalid."
    return True, ""


# ---------------------------------------------------------------------------
# Watermark-protected previews (PRD 2.7 / Section 8)
# ---------------------------------------------------------------------------

WATERMARK_TEXT = "UGCAD.IO — Sample Only"


def _is_local_upload(url: Optional[str]) -> Optional[str]:
    """If the url points at a locally-served upload, return its disk-relative
    path fragment, else None. We only ever burn-in watermarks for assets we
    actually host."""
    if not url:
        return None
    marker = "/uploads/"
    idx = url.find(marker)
    if idx == -1:
        return None
    return url[idx + len(marker):]


def apply_image_watermark(src_path: str, dest_path: str) -> bool:
    """Burn a diagonal sample watermark into a local image. Returns True on
    success. No-op (returns False) when Pillow is unavailable or the source is
    not a readable image — callers fall back to player-overlay watermarking."""
    try:
        from PIL import Image, ImageDraw, ImageFont  # type: ignore
    except Exception:
        return False
    try:
        with Image.open(src_path).convert("RGBA") as base:
            overlay = Image.new("RGBA", base.size, (0, 0, 0, 0))
            draw = ImageDraw.Draw(overlay)
            try:
                font = ImageFont.truetype("arial.ttf", max(18, base.size[0] // 18))
            except Exception:
                font = ImageFont.load_default()
            text = WATERMARK_TEXT
            # Tile the watermark diagonally across the frame.
            step_x = max(base.size[0] // 2, 200)
            step_y = max(base.size[1] // 3, 120)
            for y in range(0, base.size[1] + step_y, step_y):
                for x in range(-step_x, base.size[0] + step_x, step_x):
                    draw.text((x, y), text, fill=(255, 255, 255, 110), font=font)
            watermarked = Image.alpha_composite(base, overlay).convert("RGB")
            watermarked.save(dest_path, quality=82)
        return True
    except Exception:
        return False


def build_watermark_record(asset_url: Optional[str], kind: str = "video", uploads_dir: Optional[str] = None) -> Dict[str, Any]:
    """Produce a watermark descriptor + a brand-safe preview URL for an asset.

    For locally-hosted images we burn the watermark in and point preview_url at
    the watermarked copy. For everything else (video, external/S3 URLs) we mark
    the asset for a runtime player-overlay watermark; the raw original is never
    handed to brands (access gating happens in to_brand_facing_asset).
    """
    record: Dict[str, Any] = {
        "text": WATERMARK_TEXT,
        "applied": False,
        "method": "player_overlay",
        "preview_url": asset_url,
    }
    rel = _is_local_upload(asset_url)
    if rel and kind == "image" and uploads_dir:
        import os
        src = os.path.join(uploads_dir, rel)
        wm_rel = f"watermarked/{uuid.uuid4().hex}.jpg"
        dest = os.path.join(uploads_dir, wm_rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if apply_image_watermark(src, dest):
            preview = asset_url.replace(rel, wm_rel)
            record.update({"applied": True, "method": "burned_in", "preview_url": preview})
    return record


# Keys that must never be exposed to a brand before approval — these reference
# the raw, unwatermarked originals.
_RAW_ASSET_KEYS = ("video_url", "raw_footage_url", "original_url", "work_files")


def to_brand_facing_asset(asset: Dict[str, Any], approved: bool = False) -> Dict[str, Any]:
    """Strip raw originals from a content/asset dict for brand-facing responses.

    Before approval the brand only ever sees the watermarked `preview_url`
    (plus overlay instructions). After approval the watermark is removed: the
    clean original is released and the asset is explicitly flagged so the
    frontend stops overlaying the sample mark.
    """
    if approved:
        released = dict(asset)
        original = released.get("original_url") or released.get("video_url")
        # The clean, watermark-free file the brand now owns.
        released["video_url"] = original
        released["preview_url"] = original
        released["watermark_protected"] = False
        released["watermark"] = {
            "text": WATERMARK_TEXT,
            "method": "none",
            "applied": False,
            "removed": True,
        }
        return released
    safe = dict(asset)
    watermark = safe.get("watermark") or {}
    preview = watermark.get("preview_url")
    for key in _RAW_ASSET_KEYS:
        if key in safe:
            safe.pop(key, None)
    safe["preview_url"] = preview
    safe["watermark"] = {
        "text": watermark.get("text", WATERMARK_TEXT),
        "method": watermark.get("method", "player_overlay"),
        "applied": bool(watermark.get("applied")),
    }
    safe["watermark_protected"] = True
    return safe
