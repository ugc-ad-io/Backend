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


def creator_portfolio(user):
    profile = user.get("profile") or {}
    result, seen = [], set()
    for source in (profile.get("portfolio_items"), user.get("portfolio"), profile.get("portfolio")):
        for item in source if isinstance(source, list) else [source]:
            url = portfolio_url(item)
            if not url or str(url).startswith("blob:") or url in seen:
                continue
            seen.add(url)
            result.append({**item, "videoUrl": url} if isinstance(item, dict) else item)
    if not result:
        intro = user.get("intro_video") or profile.get("intro_video")
        if intro and not str(intro).startswith("blob:"):
            result.append(intro)
    return result
