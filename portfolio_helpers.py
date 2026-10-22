"""Read every saved portfolio shape without dropping clips or their metadata."""
import re

def portfolio_url(item):
    if isinstance(item, str):
        return item
    if not isinstance(item, dict):
        return ""
    urls = item.get("urls") or []
    candidates = [item.get("videoUrl"), item.get("video_url"), item.get("original_url"),
                  *urls, item.get("link"), item.get("url")]
    for value in candidates:
        if value and re.search(r"\.(mp4|webm|mov|m4v|avi|mkv)(?:[?#]|$)|/video/", str(value), re.I):
            return value
    return next((value for value in candidates if value), "")


def clip_key(url):
    """The same clip reached through a Cloudinary, bucket or signed link must count once
    (mirrors clipKey in the app's mediaPreview.ts)."""
    url = str(url or "")
    cloud = re.match(r"^https?://res\.cloudinary\.com/[^/]+/video/upload/(?:[^/]*,[^/]*/)?(?:v\d+/)?(.+)$", url, re.I)
    path = cloud.group(1) if cloud else re.sub(r"^https?://[^/]+/", "", url, flags=re.I)
    path = re.sub(r"[?#].*$", "", path.lstrip("/"))
    path = re.sub(r"\.[a-z0-9]{2,4}$", "", path, flags=re.I)
    return re.sub(r"^previews/", "", path, flags=re.I).lower()


def creator_portfolio(user):
    profile = user.get("profile") or {}
    result, seen = [], set()
    for source in (profile.get("portfolio_items"), user.get("portfolio"), profile.get("portfolio")):
        for item in source if isinstance(source, list) else [source]:
            url = portfolio_url(item)
            key = clip_key(url)
            if not url or str(url).startswith("blob:") or key in seen:
                continue
            seen.add(key)
            result.append({**item, "videoUrl": url} if isinstance(item, dict) else item)
    if not result:
        intro = user.get("intro_video") or profile.get("intro_video")
        if intro and not str(intro).startswith("blob:"):
            result.append(intro)
    return result
